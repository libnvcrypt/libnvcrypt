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

#ifndef NVCRYPT_H
#define NVCRYPT_H

#include <stdint.h>

#define NV_RAW_UUID_SIZE 16
#define NV_UUID_SIZE (NV_RAW_UUID_SIZE * 2 + 4 /* hyphens */ + 1)
#define NV_RAW_KEY_SIZE 16
#define NV_KEY_SIZE (NV_RAW_KEY_SIZE * 2 + 1)
#define NV_RAW_INDEX_SIZE 1

#define NVRAM_INDEX (TSS_NV_USER | 'r' << 8 | 't')
#define NVRAM_SIZE (15*(NV_RAW_UUID_SIZE+NV_RAW_KEY_SIZE+NV_RAW_INDEX_SIZE))

#define PUBLIC __attribute__ ((visibility ("default")))

/* initialize the storage, create nvram section if necessary */
PUBLIC int nv_initialize(void);

/* initialize a new keyslot for a given uuid and index */
PUBLIC struct nv_keyslot * nv_keyslot_new(const char *uuid, uint8_t index);

/* retrieve the keyslot for a given uuid and index */
PUBLIC struct nv_keyslot * nv_keyslot_by_uuid(const char *uuid, uint8_t index);

/* store a keyslot in the nvram */
PUBLIC int nv_keyslot_save(struct nv_keyslot *keyslot);

/* remove a given keyslot from the nvram */
PUBLIC int nv_keyslot_remove(struct nv_keyslot *keyslot);

/* (securely) free a keyslot's memory */
PUBLIC void nv_keyslot_free(struct nv_keyslot *keyslot);

/* retrieve the hex representation of the keyslot's key
 * buf must at least be able to hold NV_KEY_SIZE bytes */
PUBLIC int nv_keyslot_get_key(struct nv_keyslot *keyslot, char *buf);

/* retrieve the keyslot's uuid (hyphenated version 4)
 * buf must at least be able to hold NV_UUID_SIZE bytes */
PUBLIC int nv_keyslot_get_uuid(struct nv_keyslot *keyslot, char *buf);

/* retrieve the keyslot's index */
PUBLIC uint8_t nv_keyslot_get_index(struct nv_keyslot *keyslot);

/* retrieve list of assigned keyslots */
PUBLIC struct nv_keyslot_list * nv_keyslots_get_all(void);

/* get the keyslot of a list entry */
PUBLIC struct nv_keyslot * nv_keyslots_entry(struct nv_keyslot_list *list);

/* get next list entry */
PUBLIC struct nv_keyslot_list * nv_keyslots_next(struct nv_keyslot_list *list);

/* free all list entries, including keyslots */
PUBLIC void nv_keyslots_free_all(struct nv_keyslot_list *list);

/* free all list entries, preserving keyslots */
PUBLIC void nv_keyslots_free_list(struct nv_keyslot_list *list);

/* print a human readable representation */
PUBLIC void nv_keyslot_print(struct nv_keyslot *keyslot);

#endif
