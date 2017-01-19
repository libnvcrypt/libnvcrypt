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

#include "tpm_nvram.h"

// connect_tpm connects to the TPM device.
TSS_RESULT connect_tpm(tpm_context *ctx) {
    TSS_RESULT r;
    r = Tspi_Context_Create(&ctx->ctx);
    if (r != TSS_SUCCESS)
        return r;

    // NULL means connect to the system TPM
    r = Tspi_Context_Connect (ctx->ctx, NULL);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_Context_GetTpmObject(ctx->ctx, &ctx->tpm);
    return r;
}

// disconnect_tpm disconnects from the TPM device and does cleanup.
TSS_RESULT disconnect_tpm(tpm_context *ctx) {
    TSS_RESULT r;
    r = Tspi_Context_FreeMemory(ctx->ctx, NULL);
    if (r != TSS_SUCCESS)
        return r;

    return Tspi_Context_Close(ctx->ctx);
}

TSS_RESULT create_policy_auth(tpm_context *ctx, TSS_HPOLICY *pol, unsigned char *secret) {
    // use well-known secret (20 null bytes) when no secret is given
    BYTE wks[TCPA_SHA1_160_HASH_LEN];
    memset(wks, 0, TCPA_SHA1_160_HASH_LEN);

    TSS_RESULT r = Tspi_GetPolicyObject(ctx->tpm, TSS_POLICY_USAGE, pol);
    if (r != TSS_SUCCESS)
        return r;

    if (secret == NULL) {
        return Tspi_Policy_SetSecret(*pol, TSS_SECRET_MODE_SHA1, TCPA_SHA1_160_HASH_LEN, wks);
    }

    return Tspi_Policy_SetSecret(*pol, TSS_SECRET_MODE_PLAIN, strlen((const char *)secret), secret);
}

TSS_RESULT create_object_auth(tpm_context *ctx, TSS_HNVSTORE *obj) {
    TSS_HPOLICY tpmPolicy, objPolicy;
    TSS_RESULT r;

    // create policy to authenticate against the TPM module itself, this policy
    // is not assigned to anything.
    r = create_policy_auth(ctx, &tpmPolicy, ctx->secret);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_Context_CreateObject(ctx->ctx, TSS_OBJECT_TYPE_NV, 0, obj);
    if (r != TSS_SUCCESS)
        return r;

    // create policy to authenticate the newly created object
    r = create_policy_auth(ctx, &objPolicy, ctx->secret);
    if (r != TSS_SUCCESS)
        return r;

    // assign policy to object
    return Tspi_Policy_AssignToObject(objPolicy, *obj);
}

// create_nvram_section creates a nvram section with the given ID and size.
TSS_RESULT create_nvram_section(tpm_context *ctx, size_t size) {
    TSS_RESULT r;
    TSS_HNVSTORE obj;

    r = create_object_auth(ctx, &obj);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_SetAttribUint32(obj, TSS_TSPATTRIB_NV_INDEX, 0, ctx->id);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_SetAttribUint32(obj,TSS_TSPATTRIB_NV_PERMISSIONS, 0,
            TPM_NV_PER_OWNERREAD|TPM_NV_PER_OWNERWRITE);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_SetAttribUint32(obj, TSS_TSPATTRIB_NV_DATASIZE, 0, size);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_NV_DefineSpace(obj,0,0);
    if (r != TSS_SUCCESS)
        return r;

    return Tspi_Context_CloseObject(ctx->ctx, obj);
}

// destroy_nvram_section removes a nvram section with the given id.
TSS_RESULT destroy_nvram_section(tpm_context *ctx) {
    TSS_RESULT r;
    TSS_HNVSTORE obj;

    r = create_object_auth(ctx, &obj);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_SetAttribUint32(obj, TSS_TSPATTRIB_NV_INDEX, 0, ctx->id);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_NV_ReleaseSpace(obj);
    if (r != TSS_SUCCESS)
        return r;

    return Tspi_Context_CloseObject(ctx->ctx, obj);
}

// find_section returns 1 if the section with the given ID is present in the
// TPM, 0 when it is not and -1 on error.
int find_section(tpm_context *ctx) {
    uint32_t len;
    BYTE *p;

    TSS_RESULT r;
    r = Tspi_TPM_GetCapability(ctx->tpm, TSS_TPMCAP_NV_LIST, 0, NULL, &len, &p);
    if (r != TSS_SUCCESS) {
        return -1;
    }

    for (int i = 0; i < len; i += sizeof(uint32_t)) {
        // id is returned as a big endian byte sequence
        uint32_t id = p[i] << 24 | p[i+1] << 16 | p[i+2] << 8 | p[i+3] << 0;
        if (id == ctx->id) {
            return true;
        }
    }

    return false;
}

// read_section reads the contents of the section with the given ID to p.
TSS_RESULT read_section(tpm_context *ctx, size_t offset, BYTE **p, size_t *len) {
    TSS_RESULT r;
    TSS_HNVSTORE obj;

    // load size
    TPM_NV_DATA_PUBLIC nvinfo;
    r = get_nv_info(ctx, &nvinfo);
    if (r != TSS_SUCCESS)
        return r;

    if (*len == 0)
        *len = nvinfo.dataSize;

    if (offset > nvinfo.dataSize)
        return TSS_E_BAD_PARAMETER;

    // cap read to max section size
    if (offset+*len > nvinfo.dataSize)
        *len = nvinfo.dataSize - offset;

    r = create_object_auth(ctx, &obj);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_SetAttribUint32(obj, TSS_TSPATTRIB_NV_INDEX, 0, ctx->id);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_NV_ReadValue(obj, offset, (uint32_t *)len, p);
    if (r != TSS_SUCCESS)
        return r;

    return Tspi_Context_CloseObject(ctx->ctx, obj);
}

// write_section writes data at p to the given section which is identified by id.
TSS_RESULT write_section(tpm_context *ctx, size_t offset, BYTE *p, size_t len) {
    TSS_RESULT r;
    TSS_HNVSTORE obj;

    // load size
    TPM_NV_DATA_PUBLIC nvinfo;
    r = get_nv_info(ctx, &nvinfo);
    if (r != TSS_SUCCESS)
        return r;

    if (offset > nvinfo.dataSize)
        return TSS_E_BAD_PARAMETER;

    // cap write to max section size
    if (offset+len > nvinfo.dataSize)
        len = nvinfo.dataSize - offset;

    r = create_object_auth(ctx, &obj);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_SetAttribUint32(obj, TSS_TSPATTRIB_NV_INDEX, 0, ctx->id);
    if (r != TSS_SUCCESS)
        return r;

    r = Tspi_NV_WriteValue(obj, offset, len, p);
    if (r != TSS_SUCCESS)
        return r;

    return Tspi_Context_CloseObject(ctx->ctx, obj);
}

// get_nv_info loads the public information about an NVRAM section.
TSS_RESULT get_nv_info(tpm_context *ctx, TPM_NV_DATA_PUBLIC *ptr) {
    uint32_t len;
    BYTE *p;
    TSS_RESULT r;

    r = Tspi_TPM_GetCapability(ctx->tpm, TSS_TPMCAP_NV_INDEX, sizeof(uint32_t), (BYTE *)&ctx->id, &len, &p);
    if (r != TSS_SUCCESS)
        return r;

    uint64_t offset = 0;
    return Trspi_UnloadBlob_NV_DATA_PUBLIC(&offset, p, ptr);
}
