/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_ae.h"
#include <mbedtls/cipher.h>
#include <securec.h>
#include <tee_log.h>
#include "soft_common_api.h"
#include "ae_common.h"
#include "soft_err.h"

static bool check_param_is_invalid(uint32_t alg_type, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param)
{
    bool check = (key == NULL || key->key_buffer == 0 || key->key_size == 0 ||
        (ae_init_param == NULL) || (ae_init_param->nonce == 0));
    if (check) {
        tloge("The input has null point");
        return true;
    }

    check = ((alg_type != CRYPTO_TYPE_AES_CCM) && (alg_type != CRYPTO_TYPE_AES_GCM));
    if (check) {
        tloge("Invalid AE algorithm, algorithm=0x%x", alg_type);
        return true;
    }

    return false;
}

static int32_t ae_final_chek_param(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag, const struct memref_t *data_out)
{
    bool check = (ctx == NULL || ctx->ctx_buffer == 0);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    check = (data_in == NULL || data_out == NULL || tag == NULL || tag->buffer == 0);
    if (check) {
        free_cipher_context(&(ctx->ctx_buffer));
        TEE_Free((void *)(uintptr_t)(ctx->aad_cache));
        ctx->aad_cache = 0;
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_ae_dec_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    const struct memref_t *tag_in, struct memref_t *data_out)
{
    if (ae_final_chek_param(ctx, data_in, tag_in, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;

    mbedtls_cipher_context_t *ae_ctx = (mbedtls_cipher_context_t *)(uintptr_t)ctx->ctx_buffer;
    size_t olen = data_out->size;
    int32_t rc = mbedtls_cipher_auth_decrypt(ae_ctx, ae_ctx->iv, ae_ctx->iv_size,
        (uint8_t *)(uintptr_t)ctx->aad_cache, ctx->aad_size,
        (uint8_t *)(uintptr_t)data_in->buffer, data_in->size,
        (uint8_t *)(uintptr_t)data_out->buffer, &olen,
        (uint8_t *)(uintptr_t)tag_in->buffer, tag_in->size);
    free_cipher_context(&(ctx->ctx_buffer));
    TEE_Free((void *)(uintptr_t)(ctx->aad_cache));
    ctx->aad_cache = 0;
    if (rc != 0)
        tloge("mbedtls_cipher_auth_decrypt fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
    data_out->size = olen;
    return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
}

int32_t soft_crypto_ae_enc_final(struct ctx_handle_t *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    if (ae_final_chek_param(ctx, data_in, tag_out, data_out) != CRYPTO_SUCCESS)
        return CRYPTO_BAD_PARAMETERS;

    uint32_t actual_tag_len = ctx->tag_len;
    if (tag_out->size < actual_tag_len) {
        tloge("The input tag buffer length is too small\n");
        free_cipher_context(&(ctx->ctx_buffer));
        TEE_Free((void *)(uintptr_t)(ctx->aad_cache));
        ctx->aad_cache = 0;
        return CRYPTO_BAD_PARAMETERS;
    }

    mbedtls_cipher_context_t *ae_ctx = (mbedtls_cipher_context_t *)(uintptr_t)ctx->ctx_buffer;
    size_t olen = data_out->size;
    int32_t rc = mbedtls_cipher_auth_encrypt(ae_ctx, ae_ctx->iv, ae_ctx->iv_size,
        (uint8_t *)(uintptr_t)ctx->aad_cache, ctx->aad_size,
        (uint8_t *)(uintptr_t)data_in->buffer, data_in->size,
        (uint8_t *)(uintptr_t)data_out->buffer, &olen,
        (uint8_t *)(uintptr_t)tag_out->buffer, actual_tag_len);
    free_cipher_context(&(ctx->ctx_buffer));
    TEE_Free((void *)(uintptr_t)(ctx->aad_cache));
    ctx->aad_cache = 0;
    if (rc != 0)
        tloge("mbedtls_cipher_auth_encrypt fail, err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
    data_out->size = olen;
    tag_out->size = actual_tag_len;
    return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
}

static mbedtls_cipher_context_t *do_ae_init(const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param, uint32_t mbedtls_alg, uint32_t direction)
{
    int32_t rc;
    mbedtls_cipher_context_t *ae_ctx = TEE_Malloc(sizeof(*ae_ctx), 0);
    if (ae_ctx == NULL) {
        tloge("alloc aes ctx fail!\n");
        return NULL;
    }
    mbedtls_cipher_init(ae_ctx);

    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(mbedtls_alg);
    if (cipher_info == NULL) {
        tloge("get cipher_info fail\n");
        goto clean;
    }

    rc = mbedtls_cipher_setup(ae_ctx, cipher_info);
    if (rc != 0) {
        tloge("aes cipher setkey failed,err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        goto clean;
    }

    ae_ctx->operation = (direction == DEC_MODE) ? MBEDTLS_DECRYPT : MBEDTLS_ENCRYPT;
    rc = mbedtls_cipher_setkey(ae_ctx, (uint8_t *)(uintptr_t)key->key_buffer, key->key_size * BYTE2BIT,
        ae_ctx->operation);
    if (rc != 0) {
        tloge("aes cipher setkey failed,err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        goto clean;
    }

    /* set nonce */
    rc = mbedtls_cipher_set_iv(ae_ctx, (uint8_t *)(uintptr_t)ae_init_param->nonce, ae_init_param->nonce_len);
    if (rc != 0) {
        tloge("aes cipher setiv failed,err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        goto clean;
    }

    return ae_ctx;
clean:
    mbedtls_cipher_free(ae_ctx);
    TEE_Free(ae_ctx);
    return NULL;
}

int32_t soft_crypto_ae_init(struct ctx_handle_t *ctx, const struct symmerit_key_t *key,
    const struct ae_init_data *ae_init_param)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (check_param_is_invalid(ctx->alg_type, key, ae_init_param))
        return CRYPTO_BAD_PARAMETERS;

    uint32_t mbedtls_alg = get_mbedtls_ae_alg(ctx->alg_type, key->key_size);
    if (mbedtls_alg == 0) {
        tloge("alg type is not invalid!");
        return CRYPTO_BAD_PARAMETERS;
    }

    mbedtls_cipher_context_t *ae_ctx = do_ae_init(key, ae_init_param, mbedtls_alg, ctx->direction);
    if (ae_ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    ctx->ctx_buffer = (uint64_t)(uintptr_t)ae_ctx;
    ctx->tag_len = ae_init_param->tag_len;
    ctx->free_context = free_cipher_context;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_ae_update_aad(struct ctx_handle_t *ctx, const struct memref_t *aad_data)
{
    bool check = (ctx == NULL || aad_data == NULL || ctx->ctx_buffer == 0 ||
        aad_data == NULL || aad_data->size > INT32_MAX);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    uint8_t *aad_buff = TEE_Malloc(aad_data->size, 0);
    if (aad_buff == NULL) {
        tloge("malloc fail!");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }

    (void)memcpy_s(aad_buff, aad_data->size, (uint8_t *)(uintptr_t)aad_data->buffer, aad_data->size);
    ctx->aad_cache = (uint64_t)(uintptr_t)aad_buff;
    ctx->aad_size = aad_data->size;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_ae_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)data_in;
    (void)data_out;
    (void)ctx;

    return CRYPTO_NOT_SUPPORTED;
}
