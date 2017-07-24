#!/usr/bin/python3 -tt
# vim: fileencoding=utf8

# Copyright (C) 2016-2017 RedTeam Pentesting GmbH
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA


import argparse
import ctypes
import logging
import os
import shlex
import subprocess
import sys
from ctypes.util import find_library
from functools import lru_cache


from prettytable import PrettyTable


log = logging.getLogger(__name__)


class TpmException(Exception):
    pass


@lru_cache(maxsize=1)
def load_libnvcrypt():
    nvcrypt = find_library("nvcrypt")
    if nvcrypt is None:
        raise TpmException("Could not find libnvcrypt")
    return ctypes.CDLL(nvcrypt)


class Tpm(object):
    def __init__(self):
        self.__nvcrypt = load_libnvcrypt()
        self.__nvcrypt.nv_initialize()

        self.__nv_keyslots_entry = self.__nvcrypt.nv_keyslots_entry
        self.__nv_keyslots_entry.argtypes = [ctypes.c_void_p]
        self.__nv_keyslots_entry.restype = ctypes.c_void_p

        self.__nv_keyslots_next = self.__nvcrypt.nv_keyslots_next
        self.__nv_keyslots_next.argtypes = [ctypes.c_void_p]
        self.__nv_keyslots_next.restype = ctypes.c_void_p

        self.__nv_keyslots_get_all = self.__nvcrypt.nv_keyslots_get_all
        self.__nv_keyslots_get_all.restype = ctypes.c_void_p

        self.__nv_keyslots_free_list = self.__nvcrypt.nv_keyslots_free_list
        self.__nv_keyslots_free_list.argtypes = [ctypes.c_void_p]

    @property
    def keyslots(self):
        head = self.__nv_keyslots_get_all()
        current = head
        keyslots = []
        while current:
            ptr = self.__nv_keyslots_entry(current)
            keyslots.append(TpmKeyslot(ptr))
            current = self.__nv_keyslots_next(current)
        self.__nv_keyslots_free_list(head)
        return keyslots


class TpmKeyslot(object):
    def __init__(self, ptr):
        self.__nvcrypt = load_libnvcrypt()
        self.__ptr = ptr

        self.__get_uuid = self.__nvcrypt.nv_keyslot_get_uuid
        self.__get_uuid.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        self.__get_key = self.__nvcrypt.nv_keyslot_get_key
        self.__get_key.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

        self.__get_index = self.__nvcrypt.nv_keyslot_get_index
        self.__get_index.argtypes = [ctypes.c_void_p]
        self.__get_index.restype = ctypes.c_uint8

        self.__remove = self.__nvcrypt.nv_keyslot_remove
        self.__remove.argtypes = [ctypes.c_void_p]

        self.__free = self.__nvcrypt.nv_keyslot_free
        self.__free.argtypes = [ctypes.c_void_p]

    @property
    def uuid(self):
        uuid = ctypes.create_string_buffer(128)
        self.__get_uuid(self.__ptr, uuid)
        return uuid.value.decode("utf-8")

    @property
    def index(self):
        return self.__get_index(self.__ptr)

    @property
    def key(self):
        key = ctypes.create_string_buffer(128)
        self.__get_key(self.__ptr, key)
        return key.value.decode("utf-8")

    def remove(self):
        self.__remove(self.__ptr)
        self.__free(self.__ptr)
        self.__ptr = None  # mitigate potential use-after-free

    def __del__(self):
        if self.__ptr is not None:
            self.__free(self.__ptr)


class Table(PrettyTable):
    def __init__(self, field_names, **kwargs):
        super().__init__(field_names, **kwargs)
        for field in field_names:
            self.align[field] = "l"


def abort(msg, code=1):
    log.critical(msg)
    sys.exit(code)


def check(cmd):
    cmdrepr = " ".join([shlex.quote(x) for x in cmd])
    log.debug("Running: %s", cmdrepr)
    with open(os.path.devnull, "wb") as devnull:
        retcode = subprocess.call(cmd, stdout=devnull, stderr=devnull)
    if retcode == 0:
        return True
    else:
        return False


def run(cmd, get_output=False, do_abort=True, silent_errors=False):
    cmdrepr = " ".join([shlex.quote(x) for x in cmd])
    log.debug("Running: %s", cmdrepr)

    if silent_errors:
        stderr = open(os.devnull)
    else:
        stderr = None

    try:
        if get_output:
            res = subprocess.check_output(cmd, stderr=stderr).decode("utf-8",
                                                                     "ignore")
        else:
            res = subprocess.check_call(cmd, stderr=stderr)
    except subprocess.CalledProcessError:
        if not do_abort:
            return
        abort("Error running cmd " + cmdrepr)
    return res


def get_vgs():
    vgs = []
    data = run(["vgs", "-o", "vg_name", "--noheadings", "--unbuffered"],
               get_output=True)
    for line in data.splitlines():
        line = line.strip()
        vgs.append(line)
    return vgs


def get_vg(infix="plain"):
    vgs = get_vgs()
    if len(vgs) == 1:
        return vgs[0]
    else:
        vgs = [x for x in vgs if infix in x]
        if len(vgs) == 1:
            return vgs[0]
        else:
            abort("Did not find exactly one vg, vgs found: {}".format(vgs))


def luksuuid(device, do_abort=True, silent_errors=False):
    uuid = run(["cryptsetup", "luksUUID", device], get_output=True,
               do_abort=do_abort, silent_errors=silent_errors)
    if uuid is not None:
        uuid = uuid.strip()
    return uuid


def remove_prefix(string, prefix):
    if string.startswith(prefix):
        string = string[len(prefix):]
    return string


def pluralize(word, n):
    if n == 1:
        return word
    return word + "s"


def prompt(string):
    return input(string + " (y/N): ") == "y"


def tpm_list(args):
    tpm = Tpm()
    fields = ["UUID", "Key Slot"]
    if args.show_keys:
        fields.append("Key")
    table = Table(fields)
    for keyslot in tpm.keyslots:
        uuid = keyslot.uuid
        row = [uuid, keyslot.index]
        if args.show_keys:
            row.append(keyslot.key)
        table.add_row(row)
    print(table)


def is_root():
    return os.geteuid() == 0


def sudo_exec():
    os.execvp("sudo", ["sudo"] + sys.argv)


def tpm_remove(args):
    tpm = Tpm()
    for keyslot in tpm.keyslots:
        if keyslot.uuid == args.uuid:
            if prompt("Remove {}".format(args.uuid)):
                keyslot.remove()
                print("Removed keyslot {}".format(args.uuid))
            break
    else:
        print("Keyslot not found")


def check_cryptsetup():
    if "--use-nvram" not in run(("cryptsetup", "--help"), get_output=True):
        abort("cryptsetup seems to lack TPM support")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers()

    parser.add_argument("--debug", help="Print debug log, default: off",
                        default=False, action="store_true")
    parser_tpm_list = subparsers.add_parser("list")
    parser_tpm_list.add_argument("--show-keys", action="store_true")
    parser_tpm_list.set_defaults(callback=tpm_list)

    parser_tpm_remove = subparsers.add_parser("remove")
    parser_tpm_remove.add_argument("uuid")
    parser_tpm_remove.set_defaults(callback=tpm_remove)

    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(format="%(levelname)s:%(message)s",
                            level=logging.DEBUG)
    else:
        logging.basicConfig(format="%(levelname)s:%(message)s")

    if not is_root():
        sudo_exec()

    if "callback" in args:
        args.callback(args)
    else:
        parser.print_help()
