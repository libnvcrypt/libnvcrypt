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

#ifndef __TPM_H
#define __TPM_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <tss/tss_error.h>
#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>

#include <tss/tspi.h>
#include <trousers/trousers.h>

typedef struct {
    TSS_HCONTEXT ctx;
    TSS_HTPM tpm;
    unsigned char *secret;
    uint32_t id;
} tpm_context;

// connect_tpm connects to the TPM device.
TSS_RESULT connect_tpm(tpm_context *ctx);

// disconnect_tpm disconnects from the TPM device and does cleanup.
TSS_RESULT disconnect_tpm(tpm_context *ctx);

// create_nvram_section creates a nvram section with the given ID and size.
TSS_RESULT create_nvram_section(tpm_context *ctx, size_t size);

// destroy_nvram_section removes a nvram section with the given id.
TSS_RESULT destroy_nvram_section(tpm_context *ctx);

// find_section returns 1 if the section with the given ID is present in the
// TPM, 0 when it is not and -1 on error.
int find_section(tpm_context *ctx);

// read_section reads the contents of the section with the given ID to p. If
// *len is set to 0, the complete section is read.
TSS_RESULT read_section(tpm_context *ctx, size_t offset, BYTE **p, size_t *len);

// write_section writes data at p to the given section which is identified by id.
TSS_RESULT write_section(tpm_context *ctx, size_t offset, BYTE *p, size_t len);

// get_nv_info loads the public information about an NVRAM section.
TSS_RESULT get_nv_info(tpm_context *ctx, TPM_NV_DATA_PUBLIC *ptr);

#endif
