/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc hal implementation
 * Create: 2020-06-18
 */
#include "cc_driver_adapt.h"
#include <securec.h>
#include <sre_log.h>
#if (TRUSTEDCORE_PLATFORM_CHOOSE != WITH_BALONG_PLATFORM)
int32_t dxcc_power_on(void)
{
    return secs_power_on();
}

int32_t dxcc_power_off(void)
{
    return secs_power_down();
}
#else
int32_t dxcc_power_on(void)
{
    return CRYPTO_SUCCESS;
}

int32_t dxcc_power_off(void)
{
    return CRYPTO_SUCCESS;
}
#endif
static int32_t aes_set_iv(CCAesUserContext_t *aes_ctx, const struct memref_t *iv)
{
    CCAesIv_t drv_iv = {0};

    if ((iv == NULL) || (iv->buffer == 0))
        return CRYPTO_SUCCESS;

    errno_t rc = memcpy_s(drv_iv, sizeof(drv_iv), (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    CCError_t cc_ret = CC_AesSetIv(aes_ctx, drv_iv);
    if (cc_ret != CC_OK) {
        tloge("Cipher aes set iv failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

int32_t dxcc_aes_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    struct cipher_ctx_t *cipher_ctx = ctx;
    CCAesUserKeyData_t key_data = {0};

    if (key == NULL || cipher_ctx == NULL) {
        tloge("Cipher aes init failed, params check failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    key_data.pKey = (uint8_t *)(uintptr_t)(key->key_buffer);
    key_data.keySize = key->key_size;
    cipher_ctx->alg_type = alg_type;

    int32_t operation_mode = get_cipher_drv_mode(alg_type);
    if (operation_mode == INVALID_DRV_MODE) {
        tloge("Algorithm is not supported, algorithm=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }

    CCError_t cc_ret = CC_AesInit(&(cipher_ctx->ctx.aes), direction, operation_mode, CC_AES_PADDING_NONE);
    if (cc_ret != CC_OK) {
        tloge("Cipher aes init failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    cc_ret = CC_AesSetKey(&(cipher_ctx->ctx.aes), CC_AES_USER_KEY, &key_data, sizeof(key_data));
    if (cc_ret != CC_OK) {
        tloge("Cipher aes set key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return aes_set_iv(&(cipher_ctx->ctx.aes), iv);
}

int32_t dxcc_aes_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    size_t out_size;
    struct cipher_ctx_t *cipher_ctx = ctx;

    if (ctx == NULL || data_in == NULL || data_out == NULL) {
        tloge("Cipher aes dofinal failed, params check failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    out_size = data_out->size;
    CCError_t cc_ret = CC_AesFinish(&(cipher_ctx->ctx.aes), data_in->size,
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size, (uint8_t *)(uintptr_t)(data_out->buffer), &out_size);
    if (cc_ret != CC_OK) {
        tloge("Cipher aes dofinal failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    data_out->size = out_size;

    return CRYPTO_SUCCESS;
}
uint32_t dxcc_dh_get_secret_key_adaptr(uint8_t *client_prvkey_ptr, size_t clientprv_keysize,
    uint8_t *server_pubkey_ptr, size_t serverpub_keysize, uint8_t *prime_ptr, size_t primesize,
    dx_dh_user_pub_key_t *tmp_pubkey_ptr, dx_dh_prime_data_t *tmpprime_data_ptr,
    uint8_t *secret_key_ptr, uint16_t *secret_keysize_ptr)
{
    if (secret_keysize_ptr == NULL)
        return CRYPTO_BAD_PARAMETERS;

    size_t secret_key_size = *secret_keysize_ptr;
    uint32_t ret = CC_DhGetSecretKey(client_prvkey_ptr, clientprv_keysize, server_pubkey_ptr, serverpub_keysize,
        prime_ptr, primesize, tmp_pubkey_ptr, tmpprime_data_ptr, secret_key_ptr, &secret_key_size);
    *secret_keysize_ptr = (uint16_t)secret_key_size;
    return ret;
}
