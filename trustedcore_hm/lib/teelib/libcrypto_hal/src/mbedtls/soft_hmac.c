/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_hmac.h"
#include <mbedtls/md.h>
#include <mbedtls/md_internal.h>
#include <tee_log.h>
#include "soft_common_api.h"
#include "soft_err.h"

static const uint32_t g_algorithm_hmac[] = {
    CRYPTO_TYPE_HMAC_MD5,
    CRYPTO_TYPE_HMAC_SHA1,
    CRYPTO_TYPE_HMAC_SHA224,
    CRYPTO_TYPE_HMAC_SHA256,
    CRYPTO_TYPE_HMAC_SHA384,
    CRYPTO_TYPE_HMAC_SHA512,
};

struct hmac_type {
    uint32_t hmac_type;
    uint32_t mbedtls_alg;
};

struct hmac_type g_hmac_type[] = {
    { CRYPTO_TYPE_HMAC_MD5,    MBEDTLS_MD_MD5 },
    { CRYPTO_TYPE_HMAC_SHA1,   MBEDTLS_MD_SHA1 },
    { CRYPTO_TYPE_HMAC_SHA224, MBEDTLS_MD_SHA224 },
    { CRYPTO_TYPE_HMAC_SHA256, MBEDTLS_MD_SHA256 },
    { CRYPTO_TYPE_HMAC_SHA384, MBEDTLS_MD_SHA384 },
    { CRYPTO_TYPE_HMAC_SHA512, MBEDTLS_MD_SHA512 },
};

#define INVALID_MBEDTLS_ALG_TYPE 0xFFFFFFFF
static uint32_t get_mbedtls_hmac_type(uint32_t alg_type)
{
    for (uint32_t i = 0; i < sizeof(g_hmac_type) / sizeof(g_hmac_type[0]); i++) {
        if (g_hmac_type[i].hmac_type == alg_type)
            return g_hmac_type[i].mbedtls_alg;
    }
    return INVALID_MBEDTLS_ALG_TYPE;
}

int32_t soft_crypto_hmac_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key)
{
    if (ctx == NULL || key == NULL || key->key_buffer == 0 || key->key_size == 0)
        return CRYPTO_BAD_PARAMETERS;

    int32_t rc = check_valid_algorithm(ctx->alg_type, g_algorithm_hmac, ARRAY_NUM(g_algorithm_hmac));
    if (rc != CRYPTO_SUCCESS) {
        tloge("algorithm 0x%x is incorrect", ctx->alg_type);
        return rc;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(get_mbedtls_hmac_type(ctx->alg_type));
    if (md_info == NULL) {
        tloge("hmac md is NULL");
        return CRYPTO_BAD_PARAMETERS;
    }

    mbedtls_md_context_t *hmac_ctx = TEE_Malloc(sizeof(mbedtls_md_context_t), 0);
    if (hmac_ctx == NULL) {
        tloge("Malloc failed!");
        return CRYPTO_BAD_PARAMETERS;
    }
    mbedtls_md_init(hmac_ctx);
    rc = mbedtls_md_setup(hmac_ctx, md_info, 1);
    if (rc != 0) {
        tloge("hmac set up fail, err:0x%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        TEE_Free(hmac_ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;
    ctx->ctx_buffer = (uint64_t)(uintptr_t)hmac_ctx;
    rc = mbedtls_md_hmac_starts(hmac_ctx, key_buffer, key->key_size);
    if (rc != 0) {
        tloge("hmac start fail, err:0x%d!", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        free_hmac_context(&ctx->ctx_buffer);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    ctx->free_context = free_hmac_context;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hmac_update(struct ctx_handle_t *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL || ctx->ctx_buffer == 0 || data_in == NULL || data_in->buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    int32_t rc = mbedtls_md_hmac_update((mbedtls_md_context_t *)(uintptr_t)(ctx->ctx_buffer), in_buffer, data_in->size);
    if (rc != 0) {
        tloge("HMAC Update failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hmac_dofinal(struct ctx_handle_t *ctx, struct memref_t *data_out)
{
    if (ctx == NULL || ctx->ctx_buffer == 0 || data_out == NULL || data_out->buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    mbedtls_md_context_t *hmac_ctx = (mbedtls_md_context_t *)(uintptr_t)(ctx->ctx_buffer);
    int32_t rc = mbedtls_md_hmac_finish(hmac_ctx, out_buffer);
    if (rc != 0) {
        tloge("hmac final failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        free_hmac_context(&(ctx->ctx_buffer));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    data_out->size = hmac_ctx->md_info->size;
    free_hmac_context(&(ctx->ctx_buffer));
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_hmac(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    if (key == NULL || data_in == NULL || data_out == NULL || data_in->buffer == 0 || data_out->buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    int32_t rc = check_valid_algorithm(alg_type, g_algorithm_hmac, ARRAY_NUM(g_algorithm_hmac));
    if (rc != CRYPTO_SUCCESS) {
        tloge("algorithm 0x%x is incorrect", alg_type);
        return rc;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(get_mbedtls_hmac_type(alg_type));
    if (md_info == NULL) {
        tloge("hmac md is NULL");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t out_len = data_out->size;
    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;
    rc = mbedtls_md_hmac(md_info, key_buffer, key->key_size, in_buffer, data_in->size, out_buffer);
    if (rc != 0) {
        tloge("hmac failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }
    data_out->size = out_len;
    return CRYPTO_SUCCESS;
}
