/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_hash.h"
#include <mbedtls/md.h>
#include <tee_log.h>
#include "soft_common_api.h"
#include "soft_err.h"

struct digest_config {
    uint32_t algo;
    uint32_t length;
    uint32_t mbedtls_type;
};

static const struct digest_config g_digest_config[] = {
    { CRYPTO_TYPE_DIGEST_MD5,    MD5_LEN,    MBEDTLS_MD_MD5 },
    { CRYPTO_TYPE_DIGEST_SHA1,   SHA1_LEN,   MBEDTLS_MD_SHA1 },
    { CRYPTO_TYPE_DIGEST_SHA224, SHA224_LEN, MBEDTLS_MD_SHA224 },
    { CRYPTO_TYPE_DIGEST_SHA256, SHA256_LEN, MBEDTLS_MD_SHA256 },
    { CRYPTO_TYPE_DIGEST_SHA384, SHA384_LEN, MBEDTLS_MD_SHA384 },
    { CRYPTO_TYPE_DIGEST_SHA512, SHA512_LEN, MBEDTLS_MD_SHA512 },
};

static uint32_t get_hash_size(uint32_t alg_type)
{
    for (size_t i = 0; i < sizeof(g_digest_config) / sizeof(g_digest_config[0]); i++) {
        if (alg_type == g_digest_config[i].algo)
            return g_digest_config[i].length;
    }

    return 0;
}

#define INVALID_MBEDTLS_ALG_TYPE 0xFFFFFFFF
static int32_t get_mbedtls_digest_type(uint32_t alg_type)
{
    for (uint32_t i = 0; i < sizeof(g_digest_config) / sizeof(g_digest_config[0]); i++) {
        if (g_digest_config[i].algo == alg_type)
            return g_digest_config[i].mbedtls_type;
    }
    return INVALID_MBEDTLS_ALG_TYPE;
}

static const uint32_t g_algorithm_digest[] = {
    CRYPTO_TYPE_DIGEST_MD5,
    CRYPTO_TYPE_DIGEST_SHA1,
    CRYPTO_TYPE_DIGEST_SHA224,
    CRYPTO_TYPE_DIGEST_SHA256,
    CRYPTO_TYPE_DIGEST_SHA384,
    CRYPTO_TYPE_DIGEST_SHA512,
};

static bool check_valid_dest_len(uint32_t alg_type, uint32_t size)
{
    uint32_t hash_size = get_hash_size(alg_type);
    if (hash_size == 0)
        return false;

    return size >= hash_size;
}

int32_t soft_crypto_hash_init(struct ctx_handle_t *ctx)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    int32_t rc = check_valid_algorithm(ctx->alg_type, g_algorithm_digest, ARRAY_NUM(g_algorithm_digest));
    if (rc != CRYPTO_SUCCESS) {
        tloge("algorithm 0x%x is incorrect", ctx->alg_type);
        return rc;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(get_mbedtls_digest_type(ctx->alg_type));
    if (md_info == NULL) {
        tloge("hash md info is NULL");
        return CRYPTO_BAD_PARAMETERS;
    }

    mbedtls_md_context_t *hash_ctx = TEE_Malloc(sizeof(mbedtls_md_context_t), 0);
    if (hash_ctx == NULL) {
        tloge("Malloc failed!");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    mbedtls_md_init(hash_ctx);
    rc = mbedtls_md_setup(hash_ctx, md_info, 0);
    if (rc != 0) {
        tloge("hash set up fail, err:0x%d!", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        TEE_Free(hash_ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    rc = mbedtls_md_starts(hash_ctx);
    if (rc != 0) {
        tloge("hash set up fail, err:0x%d!", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        mbedtls_md_free(hash_ctx);
        TEE_Free(hash_ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    ctx->ctx_size = sizeof(mbedtls_md_context_t);
    ctx->ctx_buffer = (uint64_t)(uintptr_t)hash_ctx;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hash_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL || data_in->buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    int32_t rc = mbedtls_md_update((mbedtls_md_context_t *)(uintptr_t)ctx->ctx_buffer, in_buffer, data_in->size);
    if (rc != 0) {
        tloge("hash update failed, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hash_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    int32_t rc;
    if (ctx == NULL || ctx->ctx_buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    mbedtls_md_context_t *md_ctx = (mbedtls_md_context_t *)(uintptr_t)ctx->ctx_buffer;

    if (data_out == NULL || data_out->buffer == 0) {
        rc = CRYPTO_BAD_PARAMETERS;
        goto clean;
    }

    bool check = check_valid_dest_len(ctx->alg_type, data_out->size);
    if (!check) {
        tloge("dest len is not large enough!");
        rc = CRYPTO_SHORT_BUFFER;
        goto clean;
    }

    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    rc = mbedtls_md_finish(md_ctx, out_buffer);
    if (rc != 0) {
        tloge("hash dofinal failed");
        rc = get_soft_crypto_error(CRYPTO_SUCCESS, rc);
        goto clean;
    }

    data_out->size = get_hash_size(ctx->alg_type);
clean:
    mbedtls_md_free(md_ctx);
    TEE_Free((void *)(uintptr_t)ctx->ctx_buffer);
    ctx->ctx_buffer = 0;
    return rc;
}

int32_t soft_crypto_hash(uint32_t alg_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (data_in == NULL || data_out == NULL || data_in->buffer == 0 || data_out->buffer == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    check = check_valid_dest_len(alg_type, data_out->size);
    if (!check) {
        tloge("dest len is not large enough!");
        return CRYPTO_SHORT_BUFFER;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(get_mbedtls_digest_type(alg_type));
    if (md_info == NULL) {
        tloge("hash md info is NULL");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t rc = mbedtls_md(md_info, (uint8_t *)(uintptr_t)data_in->buffer, data_in->size,
        (uint8_t *)(uintptr_t)data_out->buffer);
    if (rc != 0) {
        tloge("hash failed, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    return CRYPTO_SUCCESS;
}
