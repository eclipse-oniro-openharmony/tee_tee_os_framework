/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc hal implementation
 * Create: 2020-06-18
 */
#include "cc_driver_adapt.h"
#include <securec.h>
#include <sre_log.h>

/* These two global variables only for current keymaster */
uint32_t g_rnd_context_ptr[CRYS_DES_KEY_SIZE_IN_BYTES] = {0};
uint32_t g_rnd_workbuff_ptr[CRYS_DES_KEY_SIZE_IN_BYTES] = {0};

dx_rand_ctx_t *get_rnd_context_ptr(void)
{
    return &g_rnd_context_ptr;
}

dx_rand_work_buf_t *get_rnd_workbuff_ptr(void)
{
    return &g_rnd_workbuff_ptr;
}

int32_t dxcc_power_on(void)
{
    return CRYPTO_SUCCESS;
}

int32_t dxcc_power_off(void)
{
    return CRYPTO_SUCCESS;
}

int32_t dxcc_aes_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    struct cipher_ctx_t *cipher_ctx = ctx;
    CRYS_AES_Key_t aes_key = {0};
    CRYS_AES_IvCounter_t aes_iv = {0};

    if (key == NULL || cipher_ctx == NULL) {
        tloge("Cipher aes init failed, params check failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    cipher_ctx->alg_type = alg_type;
    errno_t rc = memcpy_s(aes_key, sizeof(aes_key), (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    int32_t key_size_id = get_cc_sym_key_size_id(key);
    if (key_size_id == INVALID_KEY_SIZE_ID) {
        tloge("Key size is invalid, type = %u\n", alg_type);
        (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t operation_mode = get_cipher_drv_mode(alg_type);
    if (operation_mode == INVALID_DRV_MODE) {
        tloge("Algorithm is not supported, algorithm=0x%x\n", alg_type);
        (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
        return CRYPTO_NOT_SUPPORTED;
    }

    if ((iv != NULL) && (iv->buffer != 0)) {
        rc = memcpy_s(aes_iv, sizeof(aes_iv), (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
        if (rc != EOK) {
            tloge("memory copy failed, rc=0x%x\n", rc);
            (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
            return CRYPTO_ERROR_SECURITY;
        }
    }

    uint32_t cc_ret = CRYS_AES_Init(&(cipher_ctx->ctx.aes), aes_iv,
        aes_key, key_size_id, direction, operation_mode);
    (void)memset_s(aes_key, sizeof(aes_key), 0, sizeof(aes_key));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cipher aes init failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

int32_t dxcc_aes_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct cipher_ctx_t *cipher_ctx = ctx;

    if (ctx == NULL || data_in == NULL || data_out == NULL) {
        tloge("Cipher aes dofinal failed, params check failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t cc_ret = CRYS_AES_Finish(&(cipher_ctx->ctx.aes),
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size, (uint8_t *)(uintptr_t)(data_out->buffer));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cipher aes dofinal failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    bool is_mac_alg = false;
    if (cipher_ctx->alg_type == CRYPTO_TYPE_AES_CBC_MAC_NOPAD || cipher_ctx->alg_type == CRYPTO_TYPE_AES_CMAC)
        is_mac_alg = true;

    data_out->size = is_mac_alg ? AES_BLOCK_SIZE : data_in->size;

    return CRYPTO_SUCCESS;
}

int32_t read_entropy_data(void *buffer, size_t size)
{
    if (buffer == NULL || size == 0)
        return CRYPTO_BAD_PARAMETERS;

    CRYS_RND_WorkBuff_t workBuff_ptr;
    (void)memset_s(&workBuff_ptr, sizeof(workBuff_ptr), 0x0, sizeof(workBuff_ptr));
    CRYSError_t error = CRYS_RND_GetEntropy(buffer, size, &workBuff_ptr);
    return error;
}
