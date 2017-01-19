/*
 * Copyright (C) 2016-2017  RedTeam Pentesting GmbH
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/random.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include "libnvcrypt.h"
#include "tpm_nvram.h"

struct __attribute__((packed)) nv_keyslot {
    uint8_t uuid[NV_RAW_UUID_SIZE];
    uint8_t index;
    uint8_t key[NV_RAW_KEY_SIZE];
};

struct nv_keyslot_list {
    struct nv_keyslot *keyslot;
    struct nv_keyslot_list *next;
};

static void mem_erase(void *mem, size_t len)
{
    volatile char *ptr = mem;

    while(len--) {
        *ptr++ = 0;
    }
}

static int random_bytes(uint8_t *buf, size_t len)
{
    ssize_t tmp;
    size_t nbytes = 0;

#ifndef SYS_GETRANDOM
    int urandom = open("/dev/urandom", O_RDONLY);
    if(urandom == -1) {
        return -1;
    }
#endif

    while(nbytes != len) {
#ifdef SYS_GETRANDOM
        tmp = getrandom(buf + nbytes, len - nbytes, 0);
#else
        tmp = read(urandom, buf + nbytes, len - nbytes);
#endif
        if(tmp == -1) {
#ifndef SYS_GETRANDOM
            close(urandom);
#endif
            return -1;
        }
        nbytes += tmp;
    }

#ifndef SYS_GETRANDOM
    close(urandom);
#endif

    return 0;
}

static int uuid4_to_bytes(uint8_t *buf, const char *uuid)
{
    if(strlen(uuid) != NV_UUID_SIZE - 1) {
        return -1;
    }

    while(*uuid) {
        if(*uuid == '-') {
            uuid++;
            continue;
        }

        if(!isxdigit(*uuid)) {
            return -1;
        }

        errno = 0;

        *buf = strtoul((char[]){uuid[0], uuid[1], 0}, NULL, 16);

        if(errno) { /* error in strtol() */
            return -1;
        }

        uuid += 2;
        buf++;
    }

    return 0;
}

static int mem_to_hex(char *buf, const uint8_t *mem, size_t len)
{
    for(size_t nbytes = 0; nbytes < len; ++nbytes, buf += 2) {
        if(sprintf(buf, "%02x", *mem++) < 0) {
            return -1;
        }
    }

    return 0;
}

static unsigned char *read_auth_password_from_file(const char *filename, unsigned char *password, size_t len) {
    if (!filename)
        return NULL;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "unable to read TPM NVRAM password from %s: %s\n", filename, strerror(errno));
    }

    ssize_t l = read(fd, password, len-1);
    if (l < 0) {
        fprintf(stderr, "unable to read from file: %s\n", strerror(errno));
        close(fd);
        return NULL;
    }

    password[l] = '\0';
    if (password[l-1] == '\n') {
        password[l-1] = '\0';
        l--;
    }

    close(fd);
    return password;
}

static unsigned char *read_auth_password(unsigned char *password, size_t len) {
    unsigned char *pw = NULL;

    if ((pw = (unsigned char *)getenv("NVRAM_PASSWORD"))) {
        return pw;
    }

    if ((pw = read_auth_password_from_file(getenv("NVRAM_PASSWORD_FILE"), password, len))) {
        return pw;
    }

    if ((pw = read_auth_password_from_file("/etc/nvcrypt/secret", password, len))) {
        return pw;
    }

    return NULL;
}

static tpm_context *ctx;
#define MAX_NVRAM_PASSWORD_SIZE 50

int nv_initialize(void) {
    if (ctx != NULL)
        return 0;

    ctx = malloc(sizeof(tpm_context));
    if (ctx == NULL) {
        fprintf(stderr, "unable to allocate memory\n");
        return -1;
    }
    memset(ctx, 0, sizeof(*ctx));

    unsigned char *secret = malloc(MAX_NVRAM_PASSWORD_SIZE);
    if (secret == NULL) {
        fprintf(stderr, "unable to allocate memory\n");
        return -1;
    }
    memset(secret, 0, sizeof(*secret));

    ctx->secret = read_auth_password(secret, MAX_NVRAM_PASSWORD_SIZE);
    ctx->id = NVRAM_INDEX;

    TSS_RESULT r;
    r = connect_tpm(ctx);
    if (r != TSS_SUCCESS) {
        fprintf(stderr, "unable to connect to TPM: %s\n", Trspi_Error_String(r));
        return -1;
    }

    if (find_section(ctx) > 0)
        return 0;

    r = create_nvram_section(ctx, NVRAM_SIZE);
    if (r != TSS_SUCCESS) {
        fprintf(stderr, "unable to create NVRAM section: %s\n", Trspi_Error_String(r));
        disconnect_tpm(ctx);
        return -1;
    }

    return 0;
}

int nv_mem_read_all(size_t *len, uint8_t **ptr) {
    size_t offset = 0;
    *len = 0;
    TSS_RESULT r = read_section(ctx, offset, ptr, len);
    if (r != TSS_SUCCESS) {
        fprintf(stderr, "unable to read NVRAM section: %s\n", Trspi_Error_String(r));
        return -1;
    }

    return 0;
}

struct nv_keyslot * nv_keyslot_by_uuid(const char *uuid, uint8_t index)
{
    uint8_t *mem;
    size_t len;

    if (nv_mem_read_all(&len, &mem)) {
        return NULL;
    }

    size_t remaining = len;
    uint8_t *ptr = mem;
    uint8_t uuid_bytes[NV_RAW_UUID_SIZE];

    if(uuid4_to_bytes(uuid_bytes, uuid)) {
        return NULL;
    }

    while(remaining >= sizeof(struct nv_keyslot)) {
        struct nv_keyslot *current = (struct nv_keyslot *)ptr;
        if(!memcmp(current->uuid, uuid_bytes, sizeof uuid_bytes) &&
           current->index == index) {
            struct nv_keyslot *keyslot = calloc(1, sizeof *keyslot);
            if(!keyslot) {
                mem_erase(mem, len);
                return NULL;
            }
            memcpy(keyslot, ptr, sizeof *keyslot);
            mem_erase(mem, len);
            return keyslot;
        }

        remaining -= sizeof(struct nv_keyslot);
        ptr += sizeof(struct nv_keyslot);
    }

    mem_erase(mem, len);
    return NULL;
}

int nv_keyslot_save(struct nv_keyslot *keyslot)
{
    uint8_t *mem;
    size_t len;

    if (nv_mem_read_all(&len, &mem)) {
        return -1;
    }

    size_t remaining = len;
    uint8_t *ptr = mem;
    uint8_t zeroes[sizeof *keyslot];
    memset(zeroes, 0xff, sizeof *keyslot);

    while(remaining >= sizeof *keyslot) {
        if(!memcmp(ptr, zeroes, sizeof *keyslot)) {
            mem_erase(mem, len);

            size_t offset = ptr-mem;

            TSS_RESULT r = write_section(ctx, offset, (BYTE *)keyslot, sizeof(*keyslot));
            if (r != TSS_SUCCESS) {
                fprintf(stderr, "unable to write NVRAM section: %s\n", Trspi_Error_String(r));
                return -1;
            }

            return 0;
        }
        remaining -= sizeof *keyslot;
        ptr += sizeof *keyslot;
    }

    mem_erase(mem, len);
    return -1;
}

int nv_keyslot_remove(struct nv_keyslot *keyslot)
{
    uint8_t *mem;
    size_t len;

    if (nv_mem_read_all(&len, &mem)) {
        return -1;
    }

    size_t remaining = len;
    uint8_t *ptr = mem;
    uint8_t zeroes[sizeof *keyslot];
    memset(zeroes, 0xff, sizeof *keyslot);

    while(len >= sizeof *keyslot) {
        struct nv_keyslot *current = (struct nv_keyslot *)ptr;
        if(!memcmp(current->uuid, keyslot->uuid, sizeof keyslot->uuid) &&
           current->index == keyslot->index) {
            mem_erase(mem, len);

            size_t offset = ptr-mem;

            TSS_RESULT r = write_section(ctx, offset, (BYTE *)zeroes, sizeof(*keyslot));
            if (r != TSS_SUCCESS) {
                fprintf(stderr, "unable to write NVRAM section: %s\n", Trspi_Error_String(r));
                return -1;
            }

            return 0;
        }
        remaining -= sizeof *keyslot;
        ptr += sizeof *keyslot;
    }

    mem_erase(mem, len);
    return -1;
}

int nv_keyslot_get_key(struct nv_keyslot *keyslot, char *buf)
{
    return mem_to_hex(buf, keyslot->key, NV_RAW_KEY_SIZE);
}

void nv_keyslot_free(struct nv_keyslot *keyslot)
{
    if(keyslot) {
        mem_erase(keyslot, sizeof *keyslot);
    }
    free(keyslot);
}

int nv_keyslot_get_uuid(struct nv_keyslot *keyslot, char *buf)
{
    if(snprintf(buf, NV_UUID_SIZE,
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                keyslot->uuid[0], keyslot->uuid[1], keyslot->uuid[2], keyslot->uuid[3],
                keyslot->uuid[4], keyslot->uuid[5], keyslot->uuid[6], keyslot->uuid[7],
                keyslot->uuid[8], keyslot->uuid[9], keyslot->uuid[10], keyslot->uuid[11],
                keyslot->uuid[12], keyslot->uuid[13], keyslot->uuid[14], keyslot->uuid[15]) > 0) {

        return 0;
    }

    return -1;
}

uint8_t nv_keyslot_get_index(struct nv_keyslot *keyslot)
{
    return keyslot->index;
}

struct nv_keyslot_list * nv_keyslots_get_all(void)
{
    uint8_t *mem;
    size_t len;

    if (nv_mem_read_all(&len, &mem)) {
        return NULL;
    }

    struct nv_keyslot *keyslot = NULL;
    struct nv_keyslot_list *current = NULL;
    struct nv_keyslot_list *head = NULL;

    uint8_t empty[sizeof *keyslot];
    memset(empty, 0xff, sizeof *keyslot);

    while(len >= sizeof(struct nv_keyslot)) {
        if(memcmp(mem, empty, sizeof empty)) {
            if(!current) { /* allocate first list entry */
                current = calloc(1, sizeof *current);
                if(!current) {
                    return NULL;
                }
                head = current;
            }
            keyslot = calloc(sizeof *keyslot, 1);
            if(!keyslot) {
                break;
            }
            memcpy(keyslot, mem, sizeof *keyslot);
            if(current->keyslot) {
                current->next = calloc(sizeof *current, 1);
                if(!current->next) {
                    break;
                }
                current = current->next;
            }
            current->keyslot = keyslot;
        }

        len -= sizeof(struct nv_keyslot);
        mem += sizeof(struct nv_keyslot);
    }

    return head;
}

struct nv_keyslot * nv_keyslots_entry(struct nv_keyslot_list *list)
{
    if(!list) {
        return NULL;
    }
    return list->keyslot;
}

struct nv_keyslot_list * nv_keyslots_next(struct nv_keyslot_list *list)
{
    if(list) {
        list = list->next;
    }
    return list;
}

void nv_keyslots_free_all(struct nv_keyslot_list *list)
{
    while(list) {
        nv_keyslot_free(list->keyslot);
        struct nv_keyslot_list *next = list->next;
        free(list);
        list = next;
    }
}

void nv_keyslots_free_list(struct nv_keyslot_list *list)
{
    while(list) {
        struct nv_keyslot_list *next = list->next;
        free(list);
        list = next;
    }
}

struct nv_keyslot * nv_keyslot_new(const char *uuid, uint8_t index)
{
    struct nv_keyslot *keyslot = calloc(1, sizeof *keyslot);

    if(keyslot) {
        if(random_bytes(keyslot->key, sizeof keyslot->key) ||
           uuid4_to_bytes(keyslot->uuid, uuid)) {
            nv_keyslot_free(keyslot);
            return NULL;
        }
        keyslot->index = index;
    }

    return keyslot;
}

void nv_keyslot_print(struct nv_keyslot *keyslot)
{
    const char *fmt =
        "nv_keyslot {\n"
        "    uuid: %s\n"
        "    index: %d\n"
        "    key: %s\n"
        "}\n";
    char uuid[NV_UUID_SIZE];
    char key[NV_KEY_SIZE];

    if(nv_keyslot_get_uuid(keyslot, uuid) ||
       nv_keyslot_get_key(keyslot, key)) {
        goto fail;
    }

    uint8_t idx = nv_keyslot_get_index(keyslot);

    printf(fmt, uuid, idx, key);
fail:
    mem_erase(key, sizeof key);
}
