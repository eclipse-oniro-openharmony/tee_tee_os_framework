/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: implement GP API using mbedtls
 * Create: 2020-11-27
 */
#include "soft_cipher.h"
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/aes.h>
#include <securec.h>
#include <tee_log.h>
#include "soft_common_api.h"
#include "ae_common.h"
#include "soft_err.h"

#define AES_NO_PADDING   0

static const uint32_t g_algorithm_cipher[] = {
    CRYPTO_TYPE_AES_CBC_PKCS5,
    CRYPTO_TYPE_AES_CBC_NOPAD,
    CRYPTO_TYPE_AES_XTS,
    CRYPTO_TYPE_AES_CTR,
    CRYPTO_TYPE_DES_CBC_NOPAD,
    CRYPTO_TYPE_DES3_CBC_NOPAD,
};

static bool check_is_aes_algorithm(uint32_t alg)
{
    bool is_aes_alg = (alg == CRYPTO_TYPE_AES_ECB_NOPAD || alg == CRYPTO_TYPE_AES_CBC_NOPAD ||
        alg == CRYPTO_TYPE_AES_CTR || alg == CRYPTO_TYPE_AES_CTS || alg == CRYPTO_TYPE_AES_XTS ||
        alg == CRYPTO_TYPE_AES_CBC_MAC_NOPAD || alg == CRYPTO_TYPE_AES_CBC_MAC_PKCS5 ||
        alg == CRYPTO_TYPE_AES_CMAC || alg == CRYPTO_TYPE_AES_CCM || alg == CRYPTO_TYPE_AES_GCM ||
        alg == CRYPTO_TYPE_AES_ECB_PKCS5 || alg == CRYPTO_TYPE_AES_CBC_PKCS5);
    return is_aes_alg;
}

static bool check_is_des_algorithm(uint32_t alg)
{
    bool is_des_alg = (alg == CRYPTO_TYPE_DES_ECB_NOPAD || alg == CRYPTO_TYPE_DES_CBC_NOPAD ||
        alg == CRYPTO_TYPE_DES_CBC_MAC_NOPAD);

    return is_des_alg;
}

static bool check_is_des3_algorithm(uint32_t alg)
{
    bool is_des3_alg = (alg == CRYPTO_TYPE_DES3_ECB_NOPAD || alg == CRYPTO_TYPE_DES3_CBC_NOPAD ||
        alg == CRYPTO_TYPE_DES3_CBC_MAC_NOPAD);

    return is_des3_alg;
}

static bool check_cipher_key_des_size_valid(uint32_t alg, uint32_t key_size)
{
    if (check_is_des_algorithm(alg)) {
        if (key_size == DES_KEY_SIZE)
            return true;
    } else if (check_is_des3_algorithm(alg)) {
        if (key_size == DES3_KEY_SIZE)
            return true;
    }
    return false;
}

static bool check_cipher_aes_key_size_valid(uint32_t alg, uint32_t key_size)
{
    uint32_t i = 0;
    if (check_is_aes_algorithm(alg)) {
        uint32_t key_size_set[] = { AES_TEN_ROUNDS_KEY_SIZE, AES_TWELVE_ROUNDS_KEY_SIZE, AES_FOURTEEN_ROUNDS_KEY_SIZE,
            AES_MAX_KEY_SIZE };
        for (; i < ARRAY_NUM(key_size_set); i++) {
            if (key_size_set[i] == key_size)
                return true;
        }
    }
    return false;
}

static int32_t get_aes_des_cipher_key(uint32_t alg_type, uint8_t *key_buff, uint32_t key_size,
    const struct symmerit_key_t *key)
{
    bool is_abnormal = ((key->key_size > key_size) ||
        (alg_type == CRYPTO_TYPE_AES_XTS && key->key_size != AES_MAX_KEY_SIZE));
    if (is_abnormal) {
        tloge("Invalid aes key size, key_size=0x%x\n", key->key_size);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *key_buffer = (uint8_t *)(uintptr_t)key->key_buffer;
    errno_t rc = memcpy_s(key_buff, key_size, key_buffer, key->key_size);
    if (rc != EOK) {
        tloge("Copy aes key failed");
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

static int32_t get_and_check_cipher_key(uint32_t alg_type, uint8_t *key_buff, uint32_t key_size,
    const struct symmerit_key_t *key)
{
    int32_t ret = get_aes_des_cipher_key(alg_type, key_buff, key_size, key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Get aes key failed");
        return ret;
    }
    if (!check_cipher_aes_key_size_valid(alg_type, key->key_size) &&
        !check_cipher_key_des_size_valid(alg_type, key->key_size)) {
        tloge("The key size is not support, alog=0x%x size = 0x%x", alg_type, key->key_size);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t get_cipher_iv(uint8_t *iv_buff, uint32_t iv_size, const struct memref_t *iv)
{
    if (iv == NULL) {
        tlogd("No iv info");
        return CRYPTO_SUCCESS;
    }
    if (iv->size > iv_size) {
        tloge("Invaild iv len, len=0x%x\n", iv->size);
        return CRYPTO_BAD_PARAMETERS;
    }
    errno_t rc = memcpy_s(iv_buff, iv_size, (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
    if (rc != EOK) {
        tloge("Copy iv info failed, rc %x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    return CRYPTO_SUCCESS;
}

static void *proc_aes_des_cipher_init(uint32_t alg_type, uint32_t direction, uint8_t *aes_key,
    uint32_t key_size, uint8_t *iv)
{
    uint32_t mbedtls_alg = get_mbedtls_ae_alg(alg_type, key_size);
    if (mbedtls_alg == 0) {
        tloge("alg type is not invalid!");
        return NULL;
    }

    mbedtls_cipher_context_t *cipher_ctx = TEE_Malloc(sizeof(*cipher_ctx), 0);
    if (cipher_ctx == NULL) {
        tloge("New aes ctx failed");
        return NULL;
    }

    mbedtls_cipher_init(cipher_ctx);
    const mbedtls_cipher_info_t *cipher_info = NULL;
    cipher_info = mbedtls_cipher_info_from_type(mbedtls_alg);
    if (cipher_info == NULL) {
        tloge("cipher_info is invalid");
        goto clean;
    }

    int32_t rc = mbedtls_cipher_setup(cipher_ctx, cipher_info);
    if (rc != 0) {
        tloge("aes cipher setup failed\n,err:%d", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        goto clean;
    }

    uint32_t enc_mode = (direction == DEC_MODE) ? MBEDTLS_DECRYPT : MBEDTLS_ENCRYPT;
    rc = mbedtls_cipher_setkey(cipher_ctx, aes_key, key_size * BYTE2BIT, enc_mode);
    if (rc != 0) {
        tloge("aes cipher setkey failed,err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        goto clean;
    }

    rc = mbedtls_cipher_set_iv(cipher_ctx, iv, AES_MAX_IV_SIZE);
    if (rc != 0) {
        tloge("aes cipher set iv failed,err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
        goto clean;
    }

    if (cipher_info->mode == MBEDTLS_MODE_CBC) {
        if (alg_type != CRYPTO_TYPE_AES_ECB_PKCS5 && alg_type != CRYPTO_TYPE_AES_CBC_PKCS5)
            rc = mbedtls_cipher_set_padding_mode(cipher_ctx, MBEDTLS_PADDING_NONE);
        if (rc != 0) {
            tloge("aes cipher padding mode failed,err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
            goto clean;
        }
    }

    return cipher_ctx;
clean:
    mbedtls_cipher_free(cipher_ctx);
    TEE_Free(cipher_ctx);
    return NULL;
}

static int32_t soft_des_src_len_check(uint32_t alg, uint32_t src_len)
{
    if (check_is_des_algorithm(alg) || check_is_des3_algorithm(alg)) {
        if (src_len % DES_BLOCK_SIZE != 0) {
            tloge("des src len error:0x%x", src_len);
            return CRYPTO_BAD_PARAMETERS;
        }
    }
    return CRYPTO_SUCCESS;
}

static void *soft_aes_cipher_init(uint32_t alg_type, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    uint8_t aes_key[AES_MAX_KEY_SIZE] = { 0 };
    uint8_t aes_iv[AES_MAX_IV_SIZE] = { 0 };

    int32_t rc = get_and_check_cipher_key(alg_type, aes_key, sizeof(aes_key), key);
    if (rc != CRYPTO_SUCCESS) {
        tloge("Get aes key failed, ret=%d", rc);
        (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
        return NULL;
    }

    rc = get_cipher_iv(aes_iv, sizeof(aes_iv), iv);
    if (rc != CRYPTO_SUCCESS) {
        tloge("Get aes iv failed, ret=%d", rc);
        (void)memset_s(aes_key, AES_MAX_KEY_SIZE, 0x0, AES_MAX_KEY_SIZE);
        return NULL;
    }

    void *cipher_ctx = proc_aes_des_cipher_init(alg_type, direction, aes_key, key->key_size, aes_iv);
    (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    return cipher_ctx;
}

int32_t soft_crypto_cipher_init(struct ctx_handle_t *ctx,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    if (ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    int32_t rc = check_valid_algorithm(ctx->alg_type, g_algorithm_cipher, ARRAY_NUM(g_algorithm_cipher));
    if (rc != CRYPTO_SUCCESS) {
        tloge("algorithm 0x%x is not support\n", ctx->alg_type);
        return rc;
    }

    if (key == NULL || key->key_buffer == 0) {
        tloge("param is Invalid");
        return CRYPTO_BAD_PARAMETERS;
    }

    void *cipher_ctx = soft_aes_cipher_init(ctx->alg_type, ctx->direction, key, iv);
    if (cipher_ctx == NULL) {
        tloge("cipher init failed");
        return CRYPTO_BAD_PARAMETERS;
    }

    ctx->ctx_buffer = (uint64_t)(uintptr_t)cipher_ctx;
    ctx->free_context = free_cipher_context;

    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_cipher_update(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (ctx == NULL || data_in == NULL || data_in->buffer == 0)
        return CRYPTO_BAD_PARAMETERS;

    mbedtls_cipher_context_t *cipher_ctx = (mbedtls_cipher_context_t *)(uintptr_t)(ctx->ctx_buffer);
    if (cipher_ctx == NULL) {
        tloge("The cipher ctx is null");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (data_out == NULL || data_out->size > INT32_MAX) {
        tloge("data out is invalid\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;

    int32_t rc = soft_des_src_len_check(ctx->alg_type, data_in->size);
    if (rc != CRYPTO_SUCCESS)
        return rc;

    size_t dest_len_temp = data_out->size;
    rc = mbedtls_cipher_update(cipher_ctx, in_buffer, data_in->size, out_buffer, &dest_len_temp);
    if (rc != 0 || dest_len_temp < 0) {
        tloge("aes cipher update failed\n");
        return get_soft_crypto_error(CRYPTO_BAD_PARAMETERS, rc);
    }
    data_out->size = (uint32_t)dest_len_temp;
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_cipher_dofinal(struct ctx_handle_t *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (ctx == NULL || data_out == NULL)
        return CRYPTO_BAD_PARAMETERS;

    mbedtls_cipher_context_t *cipher_ctx = (mbedtls_cipher_context_t *)(uintptr_t)(ctx->ctx_buffer);
    if (cipher_ctx == NULL || data_out->size > INT32_MAX) {
        tloge("ctx is null or data out size is too long\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t rc;
    size_t update_len = 0;
    uint8_t *out_buffer = (uint8_t *)(uintptr_t)data_out->buffer;
    if (data_in != NULL && data_in->buffer != 0) {
        uint8_t *in_buffer = (uint8_t *)(uintptr_t)data_in->buffer;
        update_len = data_out->size;
        rc = mbedtls_cipher_update(cipher_ctx, in_buffer, data_in->size, out_buffer, &update_len);
        if (rc != 0) {
            tloge("aes cipher update failed, err:%d\n", get_soft_crypto_error(CRYPTO_SUCCESS, rc));
            free_cipher_context(&(ctx->ctx_buffer));
            return get_soft_crypto_error(CRYPTO_SUCCESS, rc);
        }
    }

    size_t final_len = data_out->size - update_len;
    rc = mbedtls_cipher_finish(cipher_ctx, out_buffer + update_len, &final_len);
    free_cipher_context(&(ctx->ctx_buffer));
    if (rc != 0 || update_len + (uint32_t)final_len < 0) {
        tloge("aes cipher final failed\n");
        return get_soft_crypto_error(TEE_ERROR_GENERIC, rc);
    }
    data_out->size = (uint32_t)(update_len + final_len);
    return CRYPTO_SUCCESS;
}

int32_t soft_crypto_cipher(uint32_t alg_type, uint32_t direction, const struct symmerit_key_t *key,
    const struct memref_t *iv, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)alg_type;
    (void)direction;
    (void)key;
    (void)iv;
    (void)data_in;
    (void)data_out;
    return CRYPTO_NOT_SUPPORTED;
}
