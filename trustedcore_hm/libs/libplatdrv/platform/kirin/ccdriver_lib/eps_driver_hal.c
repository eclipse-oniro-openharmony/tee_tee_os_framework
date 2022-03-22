/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: for adapt eps hal
 * Create: 2020-06-26
 */
#include <securec.h>
#include <tee_log.h>
#include <cdrmr_hash.h>
#include <cdrmr_hmac.h>
#include <api_cipher.h>
#include <api_sm2.h>
#include <drv_module.h>
#include "crypto_driver_adaptor.h"

#define SM4_KEY_SIZE      16
#define BITS_LEN_ONE_BYTE 8

struct eps_alg_to_ctx_size_t {
    uint32_t alg_type;
    uint32_t ctx_size;
};

static const struct eps_alg_to_ctx_size_t g_alg_to_ctx_size[] = {
    { CRYPTO_TYPE_DIGEST_SM3,         sizeof(struct cdrmr_hash_user_ctx) },
    { CRYPTO_TYPE_HMAC_SM3,           sizeof(struct cdrmr_hmac_user_ctx) },
    { CRYPTO_TYPE_SM4_ECB,            sizeof(api_cipher_ctx_s) },
    { CRYPTO_TYPE_SM4_CBC,            sizeof(api_cipher_ctx_s) },
    { CRYPTO_TYPE_SM4_CTR,            sizeof(api_cipher_ctx_s) },
};

int32_t get_ctx_size(uint32_t alg_type)
{
    for (uint32_t i = 0; i < (sizeof(g_alg_to_ctx_size) / sizeof(g_alg_to_ctx_size[0])); i++) {
        if (g_alg_to_ctx_size[i].alg_type == alg_type)
            return g_alg_to_ctx_size[i].ctx_size;
    }

    return CRYPTO_BAD_PARAMETERS;
}

int32_t ctx_copy(uint32_t alg_type, const void *src_ctx, uint32_t src_size, void *dest_ctx, uint32_t dest_size)
{
    errno_t rc;

    if (src_ctx == NULL || dest_ctx == NULL)
        return CRYPTO_BAD_PARAMETERS;

    switch (alg_type) {
    case CRYPTO_TYPE_DIGEST_SM3:
        if (src_size < sizeof(struct cdrmr_hash_user_ctx) || dest_size < sizeof(struct cdrmr_hash_user_ctx))
            return CRYPTO_BAD_PARAMETERS;
        rc = memcpy_s(dest_ctx, dest_size, src_ctx, sizeof(struct cdrmr_hash_user_ctx));
        break;
    case CRYPTO_TYPE_HMAC_SM3:
        if (src_size < sizeof(struct cdrmr_hmac_user_ctx) || dest_size < sizeof(struct cdrmr_hmac_user_ctx))
            return CRYPTO_BAD_PARAMETERS;
        rc = memcpy_s(dest_ctx, dest_size, src_ctx, sizeof(struct cdrmr_hmac_user_ctx));
        break;
    case CRYPTO_TYPE_SM4_ECB:
    case CRYPTO_TYPE_SM4_CBC:
    case CRYPTO_TYPE_SM4_CTR:
        if (src_size < sizeof(api_cipher_ctx_s) || dest_size < sizeof(api_cipher_ctx_s))
            return CRYPTO_BAD_PARAMETERS;
        rc = memcpy_s(dest_ctx, dest_size, src_ctx, sizeof(api_cipher_ctx_s));
        break;
    default:
        return CRYPTO_BAD_PARAMETERS;
    }

    if (rc != EOK) {
        tloge("memcpy failed\n");
        return CRYPTO_ERROR_SECURITY;
    }

    return CRYPTO_SUCCESS;
}

int32_t hash_init(void *ctx, uint32_t alg_type)
{
    if (ctx == NULL || alg_type != CRYPTO_TYPE_DIGEST_SM3)
        return CRYPTO_BAD_PARAMETERS;

    return cdrmr_crypto_hash_init(CDRMR_ALG_SM3, ctx);
}

int32_t hash_update(void *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL || data_in == NULL)
        return CRYPTO_BAD_PARAMETERS;

    return cdrmr_crypto_hash_update(ctx,
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
}

int32_t hash_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)data_in;
    if (ctx == NULL || data_out == NULL)
        return CRYPTO_BAD_PARAMETERS;

    return cdrmr_crypto_hash_dofinal(ctx,
        (uint8_t *)(uintptr_t)(data_out->buffer), &(data_out->size));
}

int32_t hmac_init(uint32_t alg_type, void *ctx, const struct symmerit_key_t *key)
{
    if (ctx == NULL || key == NULL || alg_type != CRYPTO_TYPE_HMAC_SM3)
        return CRYPTO_BAD_PARAMETERS;

    return cdrmr_crypto_hmac_init(CDRMR_ALG_HMAC_SM3,
        (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size, ctx);
}

int32_t hmac_update(void *ctx, const struct memref_t *data_in)
{
    if (ctx == NULL || data_in == NULL)
        return CRYPTO_BAD_PARAMETERS;

    return cdrmr_crypto_hmac_update(ctx,
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
}

int32_t hmac_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)data_in;
    if (ctx == NULL || data_out == NULL)
        return CRYPTO_BAD_PARAMETERS;

    return cdrmr_crypto_hmac_dofinal(ctx,
        (uint8_t *)(uintptr_t)(data_out->buffer), &(data_out->size));
}

static int32_t change_alg_to_eps(uint32_t alg_type, uint32_t *eps_alg, uint32_t *mode)
{
    switch (alg_type) {
    case CRYPTO_TYPE_SM4_ECB:
        *eps_alg = SYMM_ALGORITHM_SM4;
        *mode = SYMM_MODE_ECB;
        return CRYPTO_SUCCESS;
    case CRYPTO_TYPE_SM4_CBC:
        *eps_alg = SYMM_ALGORITHM_SM4;
        *mode = SYMM_MODE_CBC;
        return CRYPTO_SUCCESS;
    case CRYPTO_TYPE_SM4_CTR:
        *eps_alg = SYMM_ALGORITHM_SM4;
        *mode = SYMM_MODE_CTR;
        return CRYPTO_SUCCESS;
    default:
        return CRYPTO_BAD_PARAMETERS;
    };
}

int32_t cipher_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    bool check = (ctx == NULL || key == NULL || (direction != ENC_MODE && direction != DEC_MODE) ||
        key->key_size < SM4_KEY_SIZE);
    if (check)
        return CRYPTO_BAD_PARAMETERS;
    uint32_t eps_alg;
    uint32_t mode;
    int32_t rc = change_alg_to_eps(alg_type, &eps_alg, &mode);
    if (rc != CRYPTO_SUCCESS) {
        tloge("alg is Invalid");
        return rc;
    }
    api_cipher_init_s pcipher_s = { 0 };
    pcipher_s.algorithm = eps_alg;
    pcipher_s.direction = (direction == ENC_MODE) ? SYMM_DIRECTION_ENCRYPT : SYMM_DIRECTION_DECRYPT;
    pcipher_s.keytype = API_CIPHER_KEYTYPE_USER_KEY;
    pcipher_s.mode = mode;
    pcipher_s.pkey = (uint8_t *)(uintptr_t)(key->key_buffer);
    pcipher_s.width = SM4_KEY_SIZE * BITS_LEN_ONE_BYTE;
    if (alg_type != CRYPTO_TYPE_SM4_ECB) {
        if (iv == NULL)
            return CRYPTO_BAD_PARAMETERS;
        pcipher_s.piv = (uint8_t *)(uintptr_t)(iv->buffer);
        pcipher_s.ivlen = iv->size;
    }
    err_bsp_t ret = api_cipher_init(ctx, &pcipher_s);
    if (ret != BSP_RET_OK) {
        tloge("cipher init fail, result = 0x%x", ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t cipher_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    err_bsp_t rc = api_cipher_update(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer), &(data_out->size));
    if (rc != BSP_RET_OK) {
        tloge("cipher update fail, result = 0x%x", rc);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t cipher_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    bool check = (ctx == NULL || data_in == NULL || data_out == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    if (data_in->buffer == 0 || data_in->size == 0) {
        data_out->size = 0;
        return CRYPTO_SUCCESS;
    }
    err_bsp_t rc = api_cipher_dofinal(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer), &(data_out->size));
    if (rc != BSP_RET_OK) {
        tloge("cipher dofinal fail, result = 0x%x", rc);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t ecc_generate_keypair(uint32_t keysize, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    (void)curve;
    if (public_key == NULL || private_key == NULL)
        return CRYPTO_BAD_PARAMETERS;
    struct hal_ecc_key_s sm2_key = { 0 };
    sm2_key.width = keysize * BITS_LEN_ONE_BYTE;
    sm2_key.ppubx = (uint8_t *)(public_key->x);
    sm2_key.ppuby = (uint8_t *)(public_key->y);
    sm2_key.ppriv = (uint8_t *)(private_key->r);

    err_bsp_t rc = api_sm2_gen_keypair(&sm2_key);
    if (rc != BSP_RET_OK) {
        tloge("sm2 generate key failed, rc = 0x%x\n", rc);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t ecc_encrypt(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)ec_params;
    if (alg_type != CRYPTO_TYPE_SM2_PKE || public_key == NULL || data_in == NULL || data_out == NULL)
        return CRYPTO_BAD_PARAMETERS;
    struct hal_ecc_key_s sm2_key = { 0 };
    sm2_key.width = public_key->x_len * BITS_LEN_ONE_BYTE;
    sm2_key.ppubx = (uint8_t *)(public_key->x);
    sm2_key.ppuby = (uint8_t *)(public_key->y);

    err_bsp_t rc = api_sm2_encrypt(&sm2_key, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer), &(data_out->size));
    if (rc != BSP_RET_OK) {
        tloge("sm2 encrypt failed, rc = 0x%x\n", rc);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t ecc_decrypt(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)ec_params;
    if (alg_type != CRYPTO_TYPE_SM2_PKE || private_key == NULL || data_in == NULL || data_out == NULL)
        return CRYPTO_BAD_PARAMETERS;
    struct hal_ecc_key_s sm2_key = { 0 };
    sm2_key.width = private_key->r_len * BITS_LEN_ONE_BYTE;
    sm2_key.ppriv = (uint8_t *)(private_key->r);

    err_bsp_t rc = api_sm2_decrypt(&sm2_key, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer), &(data_out->size));
    if (rc != BSP_RET_OK) {
        tloge("sm2 decrypt failed, rc = 0x%x\n", rc);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, struct memref_t *signature)
{
    (void)ec_params;
    if (alg_type != CRYPTO_TYPE_SM2_DSA_SM3 || private_key == NULL || digest == NULL || signature == NULL)
        return CRYPTO_BAD_PARAMETERS;
    struct hal_ecc_key_s sm2_key = { 0 };
    sm2_key.width = private_key->r_len * BITS_LEN_ONE_BYTE;
    sm2_key.ppriv = (uint8_t *)(private_key->r);

    err_bsp_t rc = api_sm2_digest_sign(&sm2_key, (uint8_t *)(uintptr_t)(digest->buffer), digest->size,
        (uint8_t *)(uintptr_t)(signature->buffer), &(signature->size));
    if (rc != BSP_RET_OK) {
        tloge("sm2 sign failed, rc = 0x%x\n", rc);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

int32_t ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params,
    const struct memref_t *digest, const struct memref_t *signature)
{
    (void)ec_params;
    if (alg_type != CRYPTO_TYPE_SM2_DSA_SM3 || public_key == NULL || digest == NULL || signature == NULL)
        return CRYPTO_BAD_PARAMETERS;
    struct hal_ecc_key_s sm2_key = { 0 };
    sm2_key.width = public_key->x_len * BITS_LEN_ONE_BYTE;
    sm2_key.ppubx = (uint8_t *)(public_key->x);
    sm2_key.ppuby = (uint8_t *)(public_key->y);

    err_bsp_t rc = api_sm2_digest_verify(&sm2_key, (uint8_t *)(uintptr_t)(digest->buffer), digest->size,
        (uint8_t *)(uintptr_t)(signature->buffer), signature->size);
    if (rc != BSP_RET_OK) {
        tloge("sm2 verify failed, rc = 0x%x\n", rc);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

const static struct crypto_ops_t g_ops_list = {
    NULL,
    NULL,
    get_ctx_size,
    ctx_copy,
    NULL,
    hash_init,
    hash_update,
    hash_dofinal,
    NULL,
    hmac_init,
    hmac_update,
    hmac_dofinal,
    NULL,
    cipher_init,
    cipher_update,
    cipher_dofinal,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    ecc_generate_keypair,
    ecc_encrypt,
    ecc_decrypt,
    ecc_sign_digest,
    ecc_verify_digest,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
};

static int32_t eps_adapt_init(void)
{
    return register_crypto_ops(EPS_CRYPTO_FLAG, &g_ops_list);
}

DECLARE_TC_DRV(
    crypto_eps_adapt,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    eps_adapt_init,
    NULL,
    NULL,
    NULL,
    NULL
);
