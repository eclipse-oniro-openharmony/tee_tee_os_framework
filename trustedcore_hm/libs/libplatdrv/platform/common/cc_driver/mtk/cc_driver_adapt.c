/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc hal implementation
 * Author: gaobo gaobo794@huawei.com
 * Create: 2020-06-18
 */
#include "cc_driver_adapt.h"
#include <securec.h>
#include <sre_log.h>

void set_secs_suspend_flag(void)
{
    return;
}

int32_t dxcc_power_on(void)
{
    DX_Clock_Init();
    return CRYPTO_SUCCESS;
}

int32_t dxcc_power_off(void)
{
    DX_Clock_Uninit();
    return CRYPTO_SUCCESS;
}

static int32_t aes_set_iv(SaSiAesUserContext_t *aes_ctx, const struct memref_t *iv)
{
    SaSiAesIv_t drv_iv = {0};

    if ((iv == NULL) || (iv->buffer == 0))
        return CRYPTO_SUCCESS;

    errno_t rc = memcpy_s(drv_iv, sizeof(drv_iv), (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    SaSiError_t cc_ret = SaSi_AesSetIv(aes_ctx, drv_iv);
    if (cc_ret != SaSi_OK) {
        tloge("Cipher aes set iv failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

int32_t dxcc_aes_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    struct cipher_ctx_t *cipher_ctx = ctx;
    SaSiAesUserKeyData_t key_data = {0};

    if (key == NULL || cipher_ctx == NULL) {
        tloge("dxcc aes init failed, params check failed\n");
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

    SaSiError_t cc_ret = SaSi_AesInit(&(cipher_ctx->ctx.aes), direction, operation_mode, SASI_AES_PADDING_NONE);
    if (cc_ret != SaSi_OK) {
        tloge("Cipher aes init failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    cc_ret = SaSi_AesSetKey(&(cipher_ctx->ctx.aes), SASI_AES_USER_KEY, &key_data, sizeof(key_data));
    if (cc_ret != SaSi_OK) {
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
        tloge("dxcc aes dofinal failed, params check failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    out_size = data_out->size;
    SaSiError_t cc_ret = SaSi_AesFinish(&(cipher_ctx->ctx.aes), data_in->size,
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size, (uint8_t *)(uintptr_t)(data_out->buffer), &out_size);
    if (cc_ret != SaSi_OK) {
        tloge("Cipher aes dofinal failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    data_out->size = out_size;

    return CRYPTO_SUCCESS;
}

int32_t read_entropy_data(void *buffer, size_t size)
{
    if (buffer == NULL || size == 0)
        return CRYPTO_BAD_PARAMETERS;

    SaSi_RND_Context_t rndContext_ptr;
    SaSi_RND_WorkBuff_t workBuff_ptr;
    (void)memset_s(&rndContext_ptr, sizeof(rndContext_ptr), 0x0, sizeof(rndContext_ptr));
    (void)memset_s(&workBuff_ptr, sizeof(workBuff_ptr), 0x0, sizeof(workBuff_ptr));
    SaSiError_t error = SaSi_GetEntropy(&rndContext_ptr, buffer, size, &workBuff_ptr);
    return error;
}
