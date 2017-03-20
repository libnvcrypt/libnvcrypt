## Overview ##

Libnvcrypt is a helper library for cryptsetup to store an extra (random)
password for each LUKS keyslot in the TPM nvram. Whenever cryptsetup creates a
new LUKS container, libnvcrypt will generate a random password, store it in its
TPVM nvram section and add the password to the user-supplied password. This
combination is then used to protect the LUKS container's master key. Whenever
cryptsetup opens a LUKS volume it uses libnvcrypt to get the extra password
from the TPM nvram if available, appends it to the user-supplied password and
opens the volume with the resulting password.

## Build Dependencies ##
On Fedora: trousers-devel is needed, also all packages built with libnvcrypt
need trousers-devel.

## Basic Setup ##

libnvcrypt is written with the assumption that it is the only thing using the
TPM chip. Only the TPM chip on the Lenovo Thinkpad T450s is tested so far.
There it supports up to 15 keyslots, which is currently hardcoded in the
```NV_RAM_SIZE``` definition in ```libnvcrypt.h```.

### Install dependencies and start trousers ###
The following commands need to be run with root privileges.

Debian:

    apt install trousers tpm-tools
    systemctl enable trousers.service
    systemctl start trousers.service


Fedora:

    dnf install trousers tpm-tools
    systemctl enable tcsd
    systemctl start tcsd

### Set TPM password ###
Set owner and SRK password to the same password with

    tpm_takeownership

It should prompt you for the passwords like this:

    Enter owner password:
    Confirm password:
    Enter SRK password:
    Confirm password:

Setup the config file to store the TPM password:

    mkdir /etc/nvcrypt
    chown root:root -R /etc/nvcrypt; chmod og= -R /etc/nvcrypt


Store the password as ASCII in ```/etc/nvcrypt/secret```

### Usage ###

After installing libnvcrypt and patched versions of libcryptsetup cryptsetup
(see contrib directory), you can invoke libnvcrypt with the ```--use-nvram```
command-line parameter. cryptsetup will automatically use libnvcrypt to open
existing volumes if trousers is running and a key is found in the TPM chip.

cryptsetup luksFormat --use-nvram [...]

## License ##
libnvcrypt is licensed under the terms of the GNU Lesser General Public License
v2 or later.
