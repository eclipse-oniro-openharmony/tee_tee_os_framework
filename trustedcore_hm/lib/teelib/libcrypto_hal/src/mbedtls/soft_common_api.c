/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_common_api.h"
#include <mbedtls/cipher.h>
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/ccm.h>
#include <mbedtls/gcm.h>
#include <mbedtls/des.h>
#include <securec.h>
#include <tee_log.h>
#include "soft_err.h"

int32_t check_valid_algorithm(uint32_t algorithm, const uint32_t *array, uint32_t array_size)
{
    if (array == NULL)
        return CRYPTO_BAD_PARAMETERS;
    uint32_t index;
    for (index = 0; index < array_size; index++) {
        if (algorithm == array[index])
            return CRYPTO_SUCCESS;
    }
    return CRYPTO_NOT_SUPPORTED;
}

void free_cipher_context(uint64_t *ctx)
{
    if (ctx == NULL || *ctx == 0)
        return;
    mbedtls_cipher_free((void *)(uintptr_t)*ctx);
    TEE_Free((void *)(uintptr_t)*ctx);
    *ctx = 0;
}

void free_hmac_context(uint64_t *ctx)
{
    if (ctx == NULL || *ctx == 0)
        return;

    mbedtls_md_free((void *)(uintptr_t)*ctx);
    TEE_Free((void *)(uintptr_t)*ctx);
    *ctx = 0;
}

struct ciper_ctx_len {
    uint32_t algorithm;
    uint32_t cipher_ctx_size;
};
static struct ciper_ctx_len g_aes_des_ciper_ctx_len[] = {
    { CRYPTO_TYPE_AES_ECB_NOPAD, sizeof(mbedtls_aes_context) },
    { CRYPTO_TYPE_AES_CBC_NOPAD, sizeof(mbedtls_aes_context) },
    { CRYPTO_TYPE_AES_CTR, sizeof(mbedtls_aes_context) },
    { CRYPTO_TYPE_AES_CCM, sizeof(mbedtls_ccm_context) },
    { CRYPTO_TYPE_AES_GCM, sizeof(mbedtls_gcm_context) },
    { CRYPTO_TYPE_AES_XTS, sizeof(mbedtls_aes_xts_context) },
    { CRYPTO_TYPE_AES_ECB_PKCS5, sizeof(mbedtls_aes_context) },
    { CRYPTO_TYPE_AES_CBC_PKCS5, sizeof(mbedtls_aes_context) },
    { CRYPTO_TYPE_DES_ECB_NOPAD, sizeof(mbedtls_des_context) },
    { CRYPTO_TYPE_DES_CBC_NOPAD, sizeof(mbedtls_des_context) },
    { CRYPTO_TYPE_DES3_ECB_NOPAD, sizeof(mbedtls_des3_context) },
    { CRYPTO_TYPE_DES3_CBC_NOPAD, sizeof(mbedtls_des3_context) },
};

static uint32_t get_mbedtls_cipher_ctx_size(uint32_t alg)
{
    uint32_t i;
    uint32_t array_size = sizeof(g_aes_des_ciper_ctx_len) / sizeof(g_aes_des_ciper_ctx_len[0]);
    for (i = 0; i < array_size; i++) {
        if (g_aes_des_ciper_ctx_len[i].algorithm == alg)
            return g_aes_des_ciper_ctx_len[i].cipher_ctx_size;
    }
    return 0;
}

static int32_t ccm_and_gcm_ctx_copy(mbedtls_ccm_context *ccm_dest_ctx, const mbedtls_ccm_context *ccm_src_ctx)
{
    mbedtls_aes_context *aes_ctx = TEE_Malloc(sizeof(mbedtls_aes_context), 0);
    if (aes_ctx == NULL)
        return CRYPTO_ERROR_OUT_OF_MEMORY;

    (void)memcpy_s(aes_ctx, sizeof(mbedtls_aes_context),
        ccm_src_ctx->cipher_ctx.cipher_ctx, sizeof(mbedtls_aes_context));
    aes_ctx->rk = aes_ctx->buf;
    ccm_dest_ctx->cipher_ctx.cipher_ctx = aes_ctx;
    return CRYPTO_SUCCESS;
}

static int32_t mbedtls_cipher_copy(uint32_t alg_type, const mbedtls_cipher_context_t *src_ctx,
    mbedtls_cipher_context_t *dest_ctx)
{
    int32_t rc;

    dest_ctx->key_bitlen = src_ctx->key_bitlen;
    dest_ctx->operation = src_ctx->operation;
    dest_ctx->add_padding = src_ctx->add_padding;
    dest_ctx->get_padding = src_ctx->get_padding;
    dest_ctx->unprocessed_len = src_ctx->unprocessed_len;
    rc = memcpy_s(dest_ctx->unprocessed_data, sizeof(dest_ctx->unprocessed_data),
        src_ctx->unprocessed_data, sizeof(src_ctx->unprocessed_data));
    if (rc != 0) {
        tloge("copy unprocessed failed, rc:%d\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    dest_ctx->iv_size = src_ctx->iv_size;
    rc = memcpy_s(dest_ctx->iv, sizeof(dest_ctx->iv), src_ctx->iv, sizeof(src_ctx->iv));
    if (rc != 0) {
        tloge("copy iv failed, rc:%d\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    uint32_t cipher_ctx_size = get_mbedtls_cipher_ctx_size(alg_type);
    if (cipher_ctx_size != 0) {
        rc = memcpy_s(dest_ctx->cipher_ctx, cipher_ctx_size, src_ctx->cipher_ctx, cipher_ctx_size);
        if (rc != 0) {
            tloge("copy cipher_ctx failed,rc:%d\n", rc);
            return CRYPTO_ERROR_SECURITY;
        }
    }

    bool alg_type_aes = (alg_type == CRYPTO_TYPE_AES_CBC_NOPAD) ||
        (alg_type == CRYPTO_TYPE_AES_ECB_NOPAD) || (alg_type == CRYPTO_TYPE_AES_CBC_PKCS5)
        || (alg_type == CRYPTO_TYPE_AES_ECB_PKCS5) || (alg_type == CRYPTO_TYPE_AES_CTR);
    if (alg_type == CRYPTO_TYPE_AES_CCM || alg_type == CRYPTO_TYPE_AES_GCM) {
        rc = ccm_and_gcm_ctx_copy(dest_ctx->cipher_ctx, src_ctx->cipher_ctx);
        if (rc != 0) {
            tloge("cipher_ctx copy failed,rc:%d\n", rc);
            return rc;
        }
    } else if (alg_type_aes) {
        mbedtls_aes_context *aes_ctx = dest_ctx->cipher_ctx;
        aes_ctx->rk = aes_ctx->buf;
    } else if (alg_type == CRYPTO_TYPE_AES_XTS) {
        mbedtls_aes_xts_context *aes_xts_ctx = dest_ctx->cipher_ctx;
        aes_xts_ctx->crypt.rk = aes_xts_ctx->crypt.buf;
        aes_xts_ctx->tweak.rk = aes_xts_ctx->tweak.buf;
    }

    return CRYPTO_SUCCESS;
}

static int32_t soft_copy_aes_des_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    if (dest->ctx_buffer != 0) {
        free_cipher_context(&dest->ctx_buffer);
        dest->ctx_buffer = 0;
    }

    if (dest->aad_cache != 0) {
        TEE_Free((void *)(uintptr_t)dest->aad_cache);
        dest->aad_cache = 0;
    }

    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    if (src->alg_type == CRYPTO_TYPE_AES_CCM || src->alg_type == CRYPTO_TYPE_AES_GCM) {
        dest->aad_cache = src->aad_cache;
        dest->aad_size = src->aad_size;
    }

    mbedtls_cipher_context_t *dest_ctx = TEE_Malloc(sizeof(*dest_ctx), 0);
    if (dest_ctx == NULL) {
        tloge("New aes ctx failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    mbedtls_cipher_init(dest_ctx);
    dest->ctx_buffer = (uint64_t)(uintptr_t)dest_ctx;
    const mbedtls_cipher_context_t *src_ctx = (mbedtls_cipher_context_t *)(uintptr_t)src->ctx_buffer;

    int32_t rc = mbedtls_cipher_setup(dest_ctx, src_ctx->cipher_info);
    if (rc != 0) {
        tloge("aes cipher setup failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        free_cipher_context(&dest->ctx_buffer);
        dest->ctx_buffer = 0;
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    rc = mbedtls_cipher_copy(src->alg_type, src_ctx, dest_ctx);
    if (rc != 0) {
        tloge("aes cipher copy failed,err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        free_cipher_context(&dest->ctx_buffer);
        dest->ctx_buffer = 0;
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    dest->ctx_size = src->ctx_size;
    return CRYPTO_SUCCESS;
}

static int32_t soft_copy_cmac_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    (void)dest;
    (void)src;
    return CRYPTO_NOT_SUPPORTED;
}

static int32_t soft_copy_digest_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    if (dest->ctx_buffer != 0) {
        mbedtls_cipher_free((void *)(uintptr_t)dest->ctx_buffer);
        TEE_Free((void *)(uintptr_t)(dest->ctx_buffer));
        dest->ctx_buffer = 0;
    }

    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    mbedtls_md_context_t *dest_ctx = TEE_Malloc(sizeof(mbedtls_md_context_t), 0);
    if (dest_ctx == NULL) {
        tloge("hash new ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    mbedtls_md_context_t *src_ctx = (mbedtls_md_context_t *)(uintptr_t)src->ctx_buffer;
    int32_t rc = mbedtls_md_setup(dest_ctx, src_ctx->md_info, 0);
    if (rc != 0) {
        tloge("setup failed, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        TEE_Free(dest_ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    rc = mbedtls_md_clone(dest_ctx, src_ctx);
    if (rc != 0) {
        tloge("Copy digest ctx failed, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        TEE_Free(dest_ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }
    dest->ctx_buffer = (uintptr_t)dest_ctx;
    dest->ctx_size = src->ctx_size;

    return CRYPTO_SUCCESS;
}

static int32_t soft_copy_hmac_info(struct ctx_handle_t *dest, const struct ctx_handle_t *src)
{
    free_hmac_context(&(dest->ctx_buffer));

    if (src->ctx_buffer == 0)
        return CRYPTO_SUCCESS;

    mbedtls_md_context_t *dest_ctx = TEE_Malloc(sizeof(mbedtls_md_context_t), 0);
    if (dest_ctx == NULL) {
        tloge("hash new ctx failed");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    mbedtls_md_context_t *src_ctx = (mbedtls_md_context_t *)(uintptr_t)src->ctx_buffer;
    int32_t rc = mbedtls_md_setup(dest_ctx, src_ctx->md_info, 1);
    if (rc != 0) {
        tloge("setup failed, err %x", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        TEE_Free(dest_ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }

    rc = mbedtls_md_clone(dest_ctx, src_ctx);
    if (rc != 0) {
        tloge("Copy hmac ctx failed,err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        TEE_Free(dest_ctx);
        return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
    }
    dest->ctx_buffer = (uintptr_t)dest_ctx;
    dest->ctx_size = src->ctx_size;
    return CRYPTO_SUCCESS;
}

typedef int32_t (*copy_ctx_func)(struct ctx_handle_t *dest, const struct ctx_handle_t *src);
struct soft_ctx_copy {
    uint32_t algorithm;
    copy_ctx_func copy_call_back;
};

static struct soft_ctx_copy g_soft_copy_ctx[] = {
    { CRYPTO_TYPE_DIGEST, soft_copy_digest_info },
    { CRYPTO_TYPE_HMAC, soft_copy_hmac_info },
    { CRYPTO_TYPE_CIPHER, soft_copy_aes_des_info },
    { CRYPTO_TYPE_AES_MAC, soft_copy_cmac_info },
    { CRYPTO_TYPE_AES, soft_copy_aes_des_info },
};

int32_t soft_crypto_ctx_copy(const struct ctx_handle_t *src_ctx, struct ctx_handle_t *dest_ctx)
{
    if (src_ctx == NULL || dest_ctx == NULL) {
        tloge("The src ctx or dest ctx is null\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t i = 0;
    for (; i < ARRAY_NUM(g_soft_copy_ctx); i++) {
        if ((src_ctx->alg_type & g_soft_copy_ctx[i].algorithm) == g_soft_copy_ctx[i].algorithm)
            return g_soft_copy_ctx[i].copy_call_back(dest_ctx, src_ctx);
    }

    return CRYPTO_SUCCESS;
}
