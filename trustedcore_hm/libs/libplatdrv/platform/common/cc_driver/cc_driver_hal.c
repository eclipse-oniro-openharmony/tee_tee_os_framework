/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cc hal implementation
 * Create: 2020-06-18
 */
#include <drv_module.h>
#include <securec.h>
#include <sre_log.h>
#include "cc_driver_adapt.h"

/* These two global variables only for current keymaster */
dx_rand_ctx_t *g_tmp_rnd_context_ptr = NULL;
dx_rand_work_buf_t *g_tmp_rnd_workbuff_ptr = NULL;
static int32_t check_g_rnd_ptr(void)
{
    g_tmp_rnd_context_ptr = get_rnd_context_ptr();
    g_tmp_rnd_workbuff_ptr = get_rnd_workbuff_ptr();
    if (g_tmp_rnd_workbuff_ptr == NULL || g_tmp_rnd_context_ptr == NULL) {
        tloge("get rnd ptr failed\n");
        return CRYPTO_BAD_STATE;
    }
    return CRYPTO_SUCCESS;
}

static int32_t get_entropy(void *buffer, size_t size)
{
    return read_entropy_data(buffer, size);
}

static int32_t generate_random(void *buffer, size_t size)
{
    if ((buffer == NULL) || (size == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (check_g_rnd_ptr() != CC_DRIVER_OK)
        return CRYPTO_BAD_PARAMETERS;

    uint32_t cc_ret = cc_rand_generate_vector(&g_tmp_rnd_context_ptr->rndState, size, buffer);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("generate random failed ret = 0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    return CRYPTO_SUCCESS;
}

static const struct alg_to_ctx_size_t g_alg_to_ctx_size[] = {
    { CRYPTO_TYPE_DIGEST_MD5,         sizeof(struct hash_ctx_t) },
    { CRYPTO_TYPE_DIGEST_SHA1,        sizeof(struct hash_ctx_t) },
    { CRYPTO_TYPE_DIGEST_SHA224,      sizeof(struct hash_ctx_t) },
    { CRYPTO_TYPE_DIGEST_SHA256,      sizeof(struct hash_ctx_t) },
    { CRYPTO_TYPE_DIGEST_SHA384,      sizeof(struct hash_ctx_t) },
    { CRYPTO_TYPE_DIGEST_SHA512,      sizeof(struct hash_ctx_t) },
    { CRYPTO_TYPE_HMAC_MD5,           sizeof(struct hmac_ctx_t) },
    { CRYPTO_TYPE_HMAC_SHA1,          sizeof(struct hmac_ctx_t) },
    { CRYPTO_TYPE_HMAC_SHA224,        sizeof(struct hmac_ctx_t) },
    { CRYPTO_TYPE_HMAC_SHA256,        sizeof(struct hmac_ctx_t) },
    { CRYPTO_TYPE_HMAC_SHA384,        sizeof(struct hmac_ctx_t) },
    { CRYPTO_TYPE_HMAC_SHA512,        sizeof(struct hmac_ctx_t) },
    { CRYPTO_TYPE_AES_ECB_NOPAD,      sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_CBC_NOPAD,      sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_ECB_PKCS5,      sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_CBC_PKCS5,      sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_CBC_MAC_NOPAD,  sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_CMAC,           sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_CTS,            sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_CTR,            sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_XTS,            sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_DES_ECB_NOPAD,      sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_DES_CBC_NOPAD,      sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_DES3_ECB_NOPAD,     sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_DES3_CBC_NOPAD,     sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_DES_CBC_MAC_NOPAD,  sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_DES3_CBC_MAC_NOPAD, sizeof(struct cipher_ctx_t) },
    { CRYPTO_TYPE_AES_CCM,            sizeof(aes_ccm_ctx_t) },
};
static int32_t get_ctx_size(uint32_t alg_type)
{
    for (uint32_t i = 0; i < (sizeof(g_alg_to_ctx_size) / sizeof(g_alg_to_ctx_size[0])); i++) {
        if (g_alg_to_ctx_size[i].alg_type == alg_type)
            return g_alg_to_ctx_size[i].ctx_size;
    }
    return INVALID_CTX_SIZE;
}

static int32_t ctx_copy(uint32_t alg_type, const void *src_ctx, uint32_t src_size, void *dest_ctx, uint32_t dest_size)
{
    if ((src_ctx == NULL) || (dest_ctx == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    for (uint32_t i = 0; i < (sizeof(g_alg_to_ctx_size) / sizeof(g_alg_to_ctx_size[0])); i++) {
        if (g_alg_to_ctx_size[i].alg_type == alg_type) {
            if (src_size < g_alg_to_ctx_size[i].ctx_size || dest_size < g_alg_to_ctx_size[i].ctx_size) {
                tloge("src size = %u, dest size = %u, ctx size = %u",
                    src_size, dest_size, g_alg_to_ctx_size[i].ctx_size);
                return CRYPTO_SHORT_BUFFER;
            }
            errno_t rc = memcpy_s(dest_ctx, g_alg_to_ctx_size[i].ctx_size, src_ctx, g_alg_to_ctx_size[i].ctx_size);
            if (rc != EOK) {
                tloge("memory copy failed, rc=0x%x\n", rc);
                return CRYPTO_ERROR_SECURITY;
            }
            return CRYPTO_SUCCESS;
        }
    }
    return CRYPTO_NOT_SUPPORTED;
}

static int32_t get_hash_mode(uint32_t alg_type)
{
    for (uint32_t i = 0; i < (sizeof(g_hash_mode_len) / sizeof(g_hash_mode_len[0])); i++) {
        if (g_hash_mode_len[i].alg_type == alg_type)
            return g_hash_mode_len[i].hash_mode;
    }

    return INVALID_HASH_MODE;
}

static size_t get_hash_len(int32_t hash_mode)
{
    for (uint32_t i = 0; i < (sizeof(g_hash_mode_len) / sizeof(g_hash_mode_len[0])); i++) {
        if (g_hash_mode_len[i].hash_mode == hash_mode)
            return g_hash_mode_len[i].hash_len;
    }

    return INVALID_HASH_LEN;
}

static int32_t hash_init(void *ctx, uint32_t alg_type)
{
    if (ctx == NULL) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct hash_ctx_t *hash_ctx = ctx;
    int32_t hash_mode = get_hash_mode(alg_type);
    if (hash_mode == INVALID_HASH_MODE) {
        tloge("Algorithm not supported, alg_type=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }
    hash_ctx->hash_mode = hash_mode;
    uint32_t cc_ret = cc_hash_init(&(hash_ctx->ctx), hash_mode);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Digest init failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t hash_update(void *ctx, const struct memref_t *data_in)
{
    if ((ctx == NULL) || (data_in == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    struct hash_ctx_t *hash_ctx = ctx;

    uint32_t cc_ret = cc_hash_update(&(hash_ctx->ctx),
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cc hash update failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t hash_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)data_in;
    if ((ctx == NULL) || (data_out == NULL) || (data_out->buffer == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    hash_result_buf_t hash_result_buf = {0};
    struct hash_ctx_t *hash_ctx = ctx;

    size_t out_len = get_hash_len(hash_ctx->hash_mode);
    if (data_out->size < out_len) {
        tloge("The out len is too small\n");
        return CRYPTO_SHORT_BUFFER;
    }

    uint32_t cc_ret = cc_hash_finish(&(hash_ctx->ctx), hash_result_buf);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Digest finish failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s((uint8_t *)(uintptr_t)(data_out->buffer), data_out->size, hash_result_buf, out_len);
    (void)memset_s(hash_result_buf, sizeof(hash_result_buf), 0, sizeof(hash_result_buf));
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    data_out->size = out_len;

    return CRYPTO_SUCCESS;
}


static int32_t hmac_init(uint32_t alg_type, void *ctx, const struct symmerit_key_t *key)
{
    if ((ctx == NULL) || (key == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct hmac_ctx_t *hmac_ctx = ctx;
    int32_t hash_mode = get_hash_mode(alg_type);
    if (hash_mode == INVALID_HASH_MODE) {
        tloge("Algorithm not supported, alg_type=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }
    hmac_ctx->hash_mode = hash_mode;

    uint32_t cc_ret = cc_hmac_init(&(hmac_ctx->ctx), hash_mode,
        (uint8_t *)(uintptr_t)(key->key_buffer), (uint16_t)(key->key_size));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Hmac init failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t hmac_update(void *ctx, const struct memref_t *data_in)
{
    if ((ctx == NULL) || (data_in == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct hmac_ctx_t *hmac_ctx = ctx;
    uint32_t cc_ret = cc_hmac_update(&(hmac_ctx->ctx),
        (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Hmac update failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t hmac_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)data_in;
    if ((ctx == NULL) || (data_out == NULL) || (data_out->buffer == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    hash_result_buf_t hash_result_buf = {0};
    struct hmac_ctx_t *hmac_ctx = ctx;

    size_t out_len = get_hash_len(hmac_ctx->hash_mode);
    if (data_out->size < out_len) {
        tloge("The out len is too small\n");
        return CRYPTO_SHORT_BUFFER;
    }

    uint32_t cc_ret = cc_hmac_finish(&(hmac_ctx->ctx), hash_result_buf);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Digest finish failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s((uint8_t *)(uintptr_t)(data_out->buffer), data_out->size, hash_result_buf, out_len);
    (void)memset_s(hash_result_buf, sizeof(hash_result_buf), 0, sizeof(hash_result_buf));
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    data_out->size = out_len;

    return CRYPTO_SUCCESS;
}

static int32_t cipher_des_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    des_iv_t des_iv = {0};
    des_key_t key_data = { { 0 }, { 0 }, { 0 } };
    struct cipher_ctx_t *cipher_ctx = ctx;

    cipher_ctx->alg_type = alg_type;
    errno_t rc = memcpy_s(&key_data, sizeof(key_data), (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    if ((iv != NULL) && ((iv->buffer != 0))) {
        rc = memcpy_s(des_iv, sizeof(des_iv), (uint8_t *)(uintptr_t)(iv->buffer), iv->size);
        if (rc != EOK) {
            tloge("memory copy failed, rc=0x%x\n", rc);
            (void)memset_s(&key_data, sizeof(key_data), 0, sizeof(key_data));
            return CRYPTO_ERROR_SECURITY;
        }
    }

    int32_t operation_mode = get_cipher_drv_mode(alg_type);
    if (operation_mode == INVALID_DRV_MODE) {
        tloge("Algorithm is not supported, algorithm=0x%x\n", alg_type);
        (void)memset_s(&key_data, sizeof(key_data), 0, sizeof(key_data));
        return CRYPTO_NOT_SUPPORTED;
    }

    uint32_t cc_ret = cc_des_init(&(cipher_ctx->ctx.des), des_iv, &key_data,
        key->key_size / DX_DES_KEY_SIZE_IN_BYTES, direction, operation_mode);
    (void)memset_s(&key_data, sizeof(key_data), 0, sizeof(key_data));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cipher des init failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

typedef int32_t (*cipher_init_func)(uint32_t, void *, uint32_t, const struct symmerit_key_t *, const struct memref_t *);
struct cipher_init_operation_t {
    uint32_t alg_type;
    cipher_init_func cipher_init;
};
static const struct cipher_init_operation_t g_cipher_init_oeration_func[] = {
    { CRYPTO_TYPE_AES_ECB_NOPAD,         dxcc_aes_init },
    { CRYPTO_TYPE_AES_CBC_NOPAD,         dxcc_aes_init },
    { CRYPTO_TYPE_AES_CTR,               dxcc_aes_init },
    { CRYPTO_TYPE_AES_CTS,               dxcc_aes_init },
    { CRYPTO_TYPE_AES_XTS,               dxcc_aes_init },
    { CRYPTO_TYPE_AES_CMAC,              dxcc_aes_init },
    { CRYPTO_TYPE_AES_CBC_MAC_NOPAD,     dxcc_aes_init },
    { CRYPTO_TYPE_DES_ECB_NOPAD,         cipher_des_init },
    { CRYPTO_TYPE_DES_CBC_NOPAD,         cipher_des_init },
    { CRYPTO_TYPE_DES3_ECB_NOPAD,        cipher_des_init },
    { CRYPTO_TYPE_DES3_CBC_NOPAD,        cipher_des_init },
    { CRYPTO_TYPE_DES_CBC_MAC_NOPAD,     cipher_des_init },
    { CRYPTO_TYPE_DES3_CBC_MAC_NOPAD,    cipher_des_init },
};

static int32_t cipher_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct memref_t *iv)
{
    if ((ctx == NULL) || (key == NULL) || (key->key_buffer == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    for (uint32_t i = 0; i < (sizeof(g_cipher_init_oeration_func) / sizeof(g_cipher_init_oeration_func[0])); i++) {
        if (g_cipher_init_oeration_func[i].alg_type == alg_type)
            return g_cipher_init_oeration_func[i].cipher_init(alg_type, ctx, direction, key, iv);
    }

    tloge("Algorithm is not supported, algorithm=0x%x\n", alg_type);
    return CRYPTO_NOT_SUPPORTED;
}

static int32_t cipher_aes_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct cipher_ctx_t *cipher_ctx = ctx;

    uint32_t cc_ret = cc_aes_block(&(cipher_ctx->ctx.aes), (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cipher aes update failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = data_in->size;

    return CRYPTO_SUCCESS;
}

static int32_t cipher_des_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct cipher_ctx_t *cipher_ctx = ctx;

    uint32_t cc_ret = cc_des_block(&(cipher_ctx->ctx.des), (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cipher des update failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = data_in->size;

    return CRYPTO_SUCCESS;
}

static int32_t do_des_mac(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct cipher_ctx_t *cipher_ctx = ctx;

    if (data_out->size < DES_MAC_LEN) {
        tloge("Dest len is too short\n");
        return CRYPTO_SHORT_BUFFER;
    }

    uint32_t mac_data_len = (data_in->size > DES_MAC_LEN) ? data_in->size : DES_MAC_LEN;

    if (mac_data_len == 0)
        return CRYPTO_BAD_PARAMETERS;

    uint8_t *mac_data_out = malloc(mac_data_len);
    if (mac_data_out == NULL) {
        tloge("Malloc memory failed\n");
        return CRYPTO_ERROR_OUT_OF_MEMORY;
    }
    (void)memset_s(mac_data_out, mac_data_len, 0, mac_data_len);

    uint32_t cc_ret = cc_des_block(&(cipher_ctx->ctx.des), (uint8_t *)(uintptr_t)(data_in->buffer),
        data_in->size, mac_data_out);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Do des mac failed, cc_ret=0x%x\n", cc_ret);
        free(mac_data_out);
        return CRYPTO_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s((uint8_t *)(uintptr_t)(data_out->buffer), data_out->size,
        mac_data_out + (mac_data_len - DES_MAC_LEN), DES_MAC_LEN);
    (void)memset_s(mac_data_out, mac_data_len, 0, mac_data_len);
    free(mac_data_out);
    mac_data_out = NULL;
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    data_out->size = DES_MAC_LEN;

    return CRYPTO_SUCCESS;
}

static int32_t cipher_des_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    struct cipher_ctx_t *cipher_ctx = ctx;

    if (cipher_ctx->alg_type == CRYPTO_TYPE_DES_CBC_MAC_NOPAD ||
        cipher_ctx->alg_type == CRYPTO_TYPE_DES3_CBC_MAC_NOPAD)
        return do_des_mac(ctx, data_in, data_out);

    uint32_t cc_ret = cc_des_block(&(cipher_ctx->ctx.des), (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cipher des dofinal failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = data_in->size;

    return CRYPTO_SUCCESS;
}

typedef int32_t (*cipher_proc_func)(void *, const struct memref_t *, struct memref_t *);
struct cipher_data_operation_t {
    uint32_t alg_type;
    cipher_proc_func cipher_update;
    cipher_proc_func cipher_final;
};
static const struct cipher_data_operation_t g_cipher_data_oeration_func[] = {
    { CRYPTO_TYPE_AES_ECB_NOPAD,      cipher_aes_update, dxcc_aes_dofinal },
    { CRYPTO_TYPE_AES_CBC_NOPAD,      cipher_aes_update, dxcc_aes_dofinal },
    { CRYPTO_TYPE_AES_CTR,            cipher_aes_update, dxcc_aes_dofinal },
    { CRYPTO_TYPE_AES_CTS,            cipher_aes_update, dxcc_aes_dofinal },
    { CRYPTO_TYPE_AES_XTS,            cipher_aes_update, dxcc_aes_dofinal },
    { CRYPTO_TYPE_AES_CMAC,           cipher_aes_update, dxcc_aes_dofinal },
    { CRYPTO_TYPE_AES_CBC_MAC_NOPAD,  cipher_aes_update, dxcc_aes_dofinal },
    { CRYPTO_TYPE_DES_ECB_NOPAD,      cipher_des_update, cipher_des_dofinal },
    { CRYPTO_TYPE_DES_CBC_NOPAD,      cipher_des_update, cipher_des_dofinal },
    { CRYPTO_TYPE_DES3_ECB_NOPAD,     cipher_des_update, cipher_des_dofinal },
    { CRYPTO_TYPE_DES3_CBC_NOPAD,     cipher_des_update, cipher_des_dofinal },
    { CRYPTO_TYPE_DES_CBC_MAC_NOPAD,  cipher_des_update, cipher_des_dofinal },
    { CRYPTO_TYPE_DES3_CBC_MAC_NOPAD, cipher_des_update, cipher_des_dofinal },
};

static int32_t cipher_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if ((ctx == NULL) || (data_in == NULL) || (data_in->buffer == 0) ||
        (data_out == NULL) || (data_out->buffer == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct cipher_ctx_t *cipher_ctx = ctx;

    for (uint32_t i = 0; i < (sizeof(g_cipher_data_oeration_func) / sizeof(g_cipher_data_oeration_func[0])); i++) {
        if (g_cipher_data_oeration_func[i].alg_type == cipher_ctx->alg_type)
            return g_cipher_data_oeration_func[i].cipher_update(ctx, data_in, data_out);
    }

    tloge("Algorithm is not supported, algorithm=0x%x\n", cipher_ctx->alg_type);
    return CRYPTO_NOT_SUPPORTED;
}

static int32_t cipher_dofinal(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if ((ctx == NULL) || (data_in == NULL) || (data_out == NULL) || (data_out->buffer == 0)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    struct cipher_ctx_t *cipher_ctx = ctx;

    for (uint32_t i = 0; i < (sizeof(g_cipher_data_oeration_func) / sizeof(g_cipher_data_oeration_func[0])); i++) {
        if (g_cipher_data_oeration_func[i].alg_type == cipher_ctx->alg_type)
            return g_cipher_data_oeration_func[i].cipher_final(ctx, data_in, data_out);
    }

    tloge("Algorithm is not supported, algorithm=0x%x\n", cipher_ctx->alg_type);
    return CRYPTO_NOT_SUPPORTED;
}

static int32_t ae_init(uint32_t alg_type, void *ctx, uint32_t direction,
    const struct symmerit_key_t *key, const struct ae_init_data *ae_init_param)
{
    aes_ccm_key_t ccm_key = {0};

    if ((ctx == NULL) || (key == NULL) || (key->key_buffer == 0) ||
        (ae_init_param == NULL) || (ae_init_param->nonce_len > ONE_BYTE_MAX_VALUE) ||
        (ae_init_param->tag_len > ONE_BYTE_MAX_VALUE)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (alg_type != CRYPTO_TYPE_AES_CCM) {
        tloge("Invalid algorith, algorithm=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t key_size_id = get_cc_sym_key_size_id(key);
    if (key_size_id == INVALID_KEY_SIZE_ID) {
        tloge("Invalid key size\n");
        return CRYPTO_NOT_SUPPORTED;
    }

    errno_t rc = memcpy_s(ccm_key, sizeof(ccm_key), (uint8_t *)(uintptr_t)(key->key_buffer), key->key_size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    uint32_t cc_ret = cc_aes_ccm_init(ctx, direction, ccm_key, key_size_id,
        ae_init_param->aad_len, ae_init_param->payload_len,
        (uint8_t *)(uintptr_t)(ae_init_param->nonce), ae_init_param->nonce_len, ae_init_param->tag_len);
    (void)memset_s(ccm_key, sizeof(ccm_key), 0, sizeof(ccm_key));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ae init failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t ae_update_aad(void *ctx, const struct memref_t *aad_data)
{
    if ((ctx == NULL) || (aad_data == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t cc_ret = cc_aes_ccm_update_aad(ctx, (uint8_t *)(uintptr_t)(aad_data->buffer), aad_data->size);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Cc ae update aad failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t ae_update(void *ctx, const struct memref_t *data_in, struct memref_t *data_out)
{
    if ((ctx == NULL) || (data_in == NULL) || (data_out == NULL) || (data_out->size < data_in->size)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (data_in->size == INVALID_DATA_SIZE)
        return CRYPTO_SUCCESS;

    uint32_t cc_ret = cc_aes_ccm_update_data(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ae update failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    data_out->size = data_in->size;

    return CRYPTO_SUCCESS;
}

static int32_t ae_enc_final(void *ctx, const struct memref_t *data_in,
    struct memref_t *data_out, struct memref_t *tag_out)
{
    if ((ctx == NULL) || (data_in == NULL) || (data_out == NULL) ||
        (tag_out == NULL) || (tag_out->buffer == 0) || (data_out->size < data_in->size)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint8_t tag_size = 0;
    aes_ccm_mac_res_t mac_res = {0};

    uint32_t cc_ret = cc_aes_ccm_finish(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer), mac_res, &tag_size);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ae enc final failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    if (tag_out->size < tag_size) {
        tloge("The tag out len is too small\n");
        (void)memset_s(mac_res, sizeof(mac_res), 0, sizeof(mac_res));
        return CRYPTO_SHORT_BUFFER;
    }
    errno_t rc = memcpy_s((void *)(uintptr_t)tag_out->buffer, tag_out->size, mac_res, tag_size);
    (void)memset_s(mac_res, sizeof(mac_res), 0, sizeof(mac_res));
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    tag_out->size = tag_size;
    data_out->size = data_in->size;

    return CRYPTO_SUCCESS;
}

static int32_t ae_dec_final(void *ctx, const struct memref_t *data_in, const struct memref_t *tag_in,
    struct memref_t *data_out)
{
    uint8_t tag_size = 0;
    aes_ccm_mac_res_t mac_res = {0};

    if ((ctx == NULL) || (data_in == NULL) ||
        (tag_in == NULL) || (data_out == NULL) ||
        (tag_in->buffer == 0) || (tag_in->size == INVALID_DATA_SIZE) || (data_out->size < data_in->size)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s(mac_res, sizeof(mac_res), (uint8_t *)(uintptr_t)(tag_in->buffer), tag_in->size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    uint32_t cc_ret = cc_aes_ccm_finish(ctx, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer), mac_res, &tag_size);
    (void)memset_s(mac_res, sizeof(mac_res), 0, sizeof(mac_res));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ae dec final failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_MAC_INVALID;
    }
    data_out->size = data_in->size;

    return CRYPTO_SUCCESS;
}

static struct cc_rsa_info_t *get_sign_info(uint32_t alg_type)
{
    for (uint32_t i = 0; i < (sizeof(g_rsa_alg_to_sign_info) / sizeof(g_rsa_alg_to_sign_info[0])); i++) {
        if (g_rsa_alg_to_sign_info[i].alg_type == alg_type)
            return (struct cc_rsa_info_t *)&(g_rsa_alg_to_sign_info[i].sign_info);
    }
    return NULL;
}

static uint32_t get_default_pss_salt_len(uint32_t alg_type)
{
    struct alg_to_salt_len_t salt_len_array[] = {
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_MD5,    MD5_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA1,   SHA1_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA224, SHA224_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA256, SHA256_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA384, SHA384_LEN },
        { CRYPTO_TYPE_RSASSA_PKCS1_PSS_MGF1_SHA512, SHA512_LEN },
    };
    for (uint32_t i = 0; i < (sizeof(salt_len_array) / sizeof(salt_len_array[0])); i++) {
        if (salt_len_array[i].alg_type == alg_type)
            return salt_len_array[i].salt_len;
    }

    return INVALID_SALT_LEN;
}

static uint32_t get_pss_salt_len(uint32_t alg_type, const struct asymmetric_params_t *rsa_params)
{
    if (rsa_params == NULL)
        return get_default_pss_salt_len(alg_type);
    struct crypto_attribute_t *crypto_attr = (struct crypto_attribute_t *)(uintptr_t)(rsa_params->attribute);
    if ((crypto_attr != NULL) && (crypto_attr[0].attribute_id == (uint32_t)CRYPTO_ATTR_RSA_PSS_SALT_LENGTH))
        return crypto_attr[0].content.value.a;
    else
        return get_default_pss_salt_len(alg_type);
}

static int32_t rsa_build_cc_private_key(const struct rsa_priv_key_t *hal_key, dx_rsa_user_priv_key_t *cc_key)
{
    uint32_t cc_ret;
    dx_rsa_priv_key_t *cc_private_key = (dx_rsa_priv_key_t *)(cc_key->PrivateKeyDbBuff);

    if (!(hal_key->crt_mode))
        cc_ret = cc_rsa_build_priv_key(cc_key, (uint8_t *)hal_key->d, (uint16_t)hal_key->d_len,
            (uint8_t *)hal_key->e, (uint16_t)hal_key->e_len, (uint8_t *)hal_key->n, (uint16_t)hal_key->n_len);
    else
        cc_ret = cc_rsa_build_priv_key_crt(cc_key, (uint8_t *)hal_key->p, (uint16_t)hal_key->p_len,
            (uint8_t *)hal_key->q, (uint16_t)hal_key->q_len, (uint8_t *)hal_key->dp, (uint16_t)hal_key->dp_len,
            (uint8_t *)hal_key->dq, (uint16_t)hal_key->dq_len, (uint8_t *)hal_key->qinv, (uint16_t)hal_key->qinv_len);

    if (cc_ret != CC_DRIVER_OK) {
        tloge("Build rsa cc privaate key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    cc_private_key->OperationMode = (hal_key->crt_mode) ? DX_RSA_CRT : DX_RSA_NO_CRT;

    return CRYPTO_SUCCESS;
}

static int32_t rsa_sign_digest(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest, struct memref_t *signature)
{
    if ((private_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint16_t signature_size = (uint16_t)signature->size;
    dx_rsa_user_priv_key_t cc_private_key = {0};
    dx_rsa_priv_user_ctx_t cc_ctx_ptr = {0};

    struct cc_rsa_info_t *sign_info = get_sign_info(alg_type);
    if (sign_info == NULL) {
        tloge("Algorithm not supported, alg_type=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }
    uint32_t salt_len = (sign_info->pkcs1_version == DX_PKCS1_VER15) ? 0 : get_pss_salt_len(alg_type, rsa_params);

    int32_t ret = rsa_build_cc_private_key(private_key, &cc_private_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Rsa build cc priv key failed\n");
        return ret;
    }
    if (check_g_rnd_ptr() != CC_DRIVER_OK)
        return CRYPTO_BAD_STATE;
    uint32_t cc_ret = cc_rsa_sign(g_tmp_rnd_context_ptr, &cc_ctx_ptr, &cc_private_key,
        sign_info->hash_mode, sign_info->pkcs1_mgf, (uint16_t)salt_len,
        (uint8_t *)(uintptr_t)(digest->buffer), (uint32_t)digest->size,
        (uint8_t *)(uintptr_t)(signature->buffer), &signature_size, sign_info->pkcs1_version);
    (void)memset_s(&cc_private_key, sizeof(cc_private_key), 0, sizeof(cc_private_key));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Rsa sign failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    signature->size = (size_t)signature_size;

    return CRYPTO_SUCCESS;
}

static int32_t rsa_verify_digest(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *digest, const struct memref_t *signature)
{
    if ((public_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    dx_rsa_user_pub_key_t cc_public_key = {0};
    dx_rsa_pub_user_ctx_t cc_ctx_ptr = {0};
    struct cc_rsa_info_t *sign_info = get_sign_info(alg_type);
    if (sign_info == NULL) {
        tloge("Invalid sign info\n");
        return CRYPTO_NOT_SUPPORTED;
    }
    uint32_t salt_len = (sign_info->pkcs1_version == DX_PKCS1_VER15) ? 0 : get_pss_salt_len(alg_type, rsa_params);

    uint32_t cc_ret = cc_rsa_build_pub_key(&cc_public_key,
        (uint8_t *)public_key->e, (uint16_t)public_key->e_len,
        (uint8_t *)public_key->n, (uint16_t)public_key->n_len);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Rsa build cc public key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    cc_ret = cc_rsa_verify(&cc_ctx_ptr, &cc_public_key, sign_info->hash_mode,
        sign_info->pkcs1_mgf, (uint16_t)salt_len,
        (uint8_t *)(uintptr_t)(digest->buffer), (uint32_t)digest->size,
        (uint8_t *)(uintptr_t)(signature->buffer), sign_info->pkcs1_version);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Rsa sign failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_SIGNATURE_INVALID;
    }

    return CRYPTO_SUCCESS;
}

static int32_t rsa_build_hal_pub_key(dx_rsa_user_pub_key_t *cc_key, struct rsa_priv_key_t *hal_key)
{
    uint16_t n_len = RSA_MAX_KEY_SIZE;
    uint16_t e_len = RSA_EXPONENT_LEN;

    uint32_t cc_ret = cc_rsa_get_pub_key(cc_key, hal_key->e, &e_len, hal_key->n, &n_len);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Build rsa hal normal key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    hal_key->e_len = e_len;
    hal_key->n_len = n_len;

    return CRYPTO_SUCCESS;
}

static void init_rsa_hal_key_len(struct rsa_priv_key_t *hal_key)
{
    hal_key->n_len = RSA_MAX_KEY_SIZE;
    hal_key->d_len = RSA_MAX_KEY_SIZE;
    hal_key->e_len = RSA_EXPONENT_LEN;
    hal_key->p_len = RSA_MAX_KEY_SIZE_CRT;
    hal_key->q_len = RSA_MAX_KEY_SIZE_CRT;
    hal_key->dp_len = RSA_MAX_KEY_SIZE_CRT;
    hal_key->dq_len = RSA_MAX_KEY_SIZE_CRT;
    hal_key->qinv_len = RSA_MAX_KEY_SIZE_CRT;
}

static int32_t rsa_build_hal_pri_key(dx_rsa_user_priv_key_t *cc_key, bool crt_mode, struct rsa_priv_key_t *hal_key)
{
    uint32_t cc_ret;

    if (!crt_mode)
        cc_ret = cc_rsa_get_priv_key(cc_key, hal_key->d, (uint16_t *)&(hal_key->d_len),
            hal_key->e, (uint16_t *)&hal_key->e_len, hal_key->n, (uint16_t *)&(hal_key->n_len));
    else
        cc_ret = cc_rsa_get_priv_key_crt(cc_key, hal_key->p, (uint16_t *)&(hal_key->p_len),
            hal_key->q, (uint16_t *)&(hal_key->q_len),
            hal_key->dp, (uint16_t *)&(hal_key->dp_len),
            hal_key->dq, (uint16_t *)&(hal_key->dq_len),
            hal_key->qinv, (uint16_t *)&(hal_key->qinv_len));

    if (cc_ret != CC_DRIVER_OK) {
        tloge("Build rsa hal crt key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t rsa_build_hal_key_pair(dx_rsa_user_priv_key_t *cc_pri_key, dx_rsa_user_pub_key_t *cc_pub_key,
    bool crt_mode, struct rsa_priv_key_t *hal_key)
{
    init_rsa_hal_key_len(hal_key);

    int32_t ret = rsa_build_hal_pri_key(cc_pri_key, crt_mode, hal_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Build rsa hal pri key failed\n");
        return ret;
    }

    ret = rsa_build_hal_pub_key(cc_pub_key, hal_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Build rsa hal pub key failed\n");
        return ret;
    }
    hal_key->crt_mode = crt_mode;
    return CRYPTO_SUCCESS;
}

static int32_t rsa_generate_keypair(uint32_t key_size, const struct memref_t *e_value,
    bool crt_mode, struct rsa_priv_key_t *key_pair)
{
    if ((e_value == NULL) || (key_pair == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t cc_ret;
    dx_rsa_kg_data_t key_gen_data;
    dx_rsa_user_priv_key_t cc_private_key = {0};
    dx_rsa_user_pub_key_t cc_public_key = {0};

    (void)memset_s(&key_gen_data, sizeof(key_gen_data), 0, sizeof(key_gen_data));
    if (check_g_rnd_ptr() != CC_DRIVER_OK)
        return CRYPTO_BAD_STATE;
    if (crt_mode)
        cc_ret = cc_rsa_generate_key_pair_crt(g_tmp_rnd_context_ptr,
            (uint8_t *)(uintptr_t)(e_value->buffer), (size_t)e_value->size,
            key_size, &cc_private_key, &cc_public_key, &key_gen_data, NULL);
    else
        cc_ret = cc_rsa_generate_key_pair(g_tmp_rnd_context_ptr,
            (uint8_t *)(uintptr_t)(e_value->buffer), (size_t)e_value->size,
            key_size, &cc_private_key, &cc_public_key, &key_gen_data, NULL);

    if (cc_ret != CC_DRIVER_OK) {
        tloge("DX generate rsa key failed, key_size=0x%x, cc_ret=0x%x\n", key_size, cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = rsa_build_hal_key_pair(&cc_private_key, &cc_public_key, crt_mode, key_pair);
    (void)memset_s(&cc_private_key, sizeof(cc_private_key), 0, sizeof(cc_private_key));
    return ret;
}

static struct cc_rsa_info_t *get_rsa_ency_info(uint32_t alg_type)
{
    for (uint32_t i = 0; i < (sizeof(g_rsa_alg_to_ency_info) / sizeof(g_rsa_alg_to_ency_info[0])); i++) {
        if (g_rsa_alg_to_ency_info[i].alg_type == alg_type)
            return (struct cc_rsa_info_t *)&(g_rsa_alg_to_ency_info[i].ency_info);
    }
    return NULL;
}

static int32_t rsa_encrypt(uint32_t alg_type, const struct rsa_pub_key_t *public_key,
    const struct asymmetric_params_t *rsa_params, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)rsa_params;
    if ((public_key == NULL) || (data_in == NULL) || (data_out == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    dx_rsa_user_pub_key_t cc_public_key = {0};
    dx_rsa_prime_data_t cc_prime_data;
    (void)memset_s(&cc_prime_data, sizeof(cc_prime_data), 0x0, sizeof(cc_prime_data));

    struct cc_rsa_info_t *ency_info = get_rsa_ency_info(alg_type);
    if (ency_info == NULL) {
        tloge("Algorithm not supported, algorithm=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }

    uint32_t cc_ret = cc_rsa_build_pub_key(&cc_public_key,
        (uint8_t *)public_key->e, (uint16_t)public_key->e_len,
        (uint8_t *)public_key->n, (uint16_t)public_key->n_len);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Rsa build cc priv key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    if (alg_type == CRYPTO_TYPE_RSA_NO_PAD) {
        cc_ret = cc_rsa_prim_encrypt(&cc_public_key, &cc_prime_data,
            (uint8_t *)(uintptr_t)(data_in->buffer), (uint16_t)data_in->size,
            (uint8_t *)(uintptr_t)(data_out->buffer));
    } else {
        if (check_g_rnd_ptr() != CC_DRIVER_OK)
            return CRYPTO_BAD_STATE;
        cc_ret =  cc_rsa_schemes_encrypt(g_tmp_rnd_context_ptr, &cc_public_key, &cc_prime_data,
            ency_info->hash_mode, NULL, 0, ency_info->pkcs1_mgf,
            (uint8_t *)(uintptr_t)(data_in->buffer), (uint16_t)data_in->size,
            (uint8_t *)(uintptr_t)(data_out->buffer), ency_info->pkcs1_version);
    }
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Rsa encrypt failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = (size_t)public_key->n_len;

    return CRYPTO_SUCCESS;
}

static int32_t rsa_decrypt(uint32_t alg_type, const struct rsa_priv_key_t *private_key,
    const struct asymmetric_params_t *rsa_params,
    const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)rsa_params;
    if ((private_key == NULL) || (data_in == NULL) || (data_out == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t cc_ret;
    uint16_t out_len = (uint16_t)data_out->size;
    dx_rsa_user_priv_key_t cc_private_key = {0};
    dx_rsa_prime_data_t cc_prime_data;
    (void)memset_s(&cc_prime_data, sizeof(cc_prime_data), 0x0, sizeof(cc_prime_data));

    struct cc_rsa_info_t *ency_info = get_rsa_ency_info(alg_type);
    if (ency_info == NULL) {
        tloge("Algorithm not supported, algorithm=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = rsa_build_cc_private_key(private_key, &cc_private_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Rsa build cc priv key failed\n");
        return ret;
    }

    if (alg_type == CRYPTO_TYPE_RSA_NO_PAD)
        cc_ret = cc_rsa_prim_decrypt(&cc_private_key, &cc_prime_data,
            (uint8_t *)(uintptr_t)(data_in->buffer), (uint16_t)data_in->size,
            (uint8_t *)(uintptr_t)(data_out->buffer));
    else
        cc_ret = cc_rsa_schemes_decrypt(&cc_private_key, &cc_prime_data,
            ency_info->hash_mode, NULL, 0, ency_info->pkcs1_mgf,
            (uint8_t *)(uintptr_t)(data_in->buffer), (uint16_t)data_in->size,
            (uint8_t *)(uintptr_t)(data_out->buffer), &out_len, ency_info->pkcs1_version);

    (void)memset_s(&cc_private_key, sizeof(cc_private_key), 0, sizeof(cc_private_key));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Rsa decrypt failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    data_out->size = (alg_type == CRYPTO_TYPE_RSA_NO_PAD) ? ((size_t)private_key->n_len) : ((size_t)out_len);

    return CRYPTO_SUCCESS;
}


static int32_t get_ecc_domain_from_curve_id(uint32_t curve_id)
{
    for (uint32_t i = 0; i < (sizeof(g_ecc_curve_domain) / sizeof(g_ecc_curve_domain[0])); i++) {
        if (g_ecc_curve_domain[i].curve_id == curve_id)
            return g_ecc_curve_domain[i].domain_id;
    }
    return INVALID_DOMAIN_ID;
}

static uint32_t get_ecc_curve_id_from_domain(int32_t domain_id)
{
    for (uint32_t i = 0; i < (sizeof(g_ecc_curve_domain) / sizeof(g_ecc_curve_domain[0])); i++) {
        if (g_ecc_curve_domain[i].domain_id == domain_id)
            return g_ecc_curve_domain[i].curve_id;
    }
    return INVALID_CURVE_ID;
}

static uint32_t get_ecc_key_size_from_domain(int32_t domain_id)
{
    for (uint32_t i = 0; i < (sizeof(g_ecc_curve_domain) / sizeof(g_ecc_curve_domain[0])); i++) {
        if (g_ecc_curve_domain[i].domain_id == domain_id)
            return g_ecc_curve_domain[i].key_size;
    }
    return ECC_INVALID_KEY_SIZE;
}

static int32_t ecc_build_hal_public_key(dx_ecc_user_pub_key_t *cc_public_key, struct ecc_pub_key_t *hal_public_key)
{
    uint8_t public_key[DX_EC_MAX_PUBLIC_KEY_LEN] = {0};
    uint32_t public_key_len = DX_EC_MAX_PUBLIC_KEY_LEN;
    dx_ecc_pub_key_t *cc_key = (dx_ecc_pub_key_t *)cc_public_key->PublKeyDbBuff;

    uint32_t cc_ret = cc_ecc_export_pub_key(cc_public_key, DX_EC_POINT_UNCOMPRESSED,
        public_key, &public_key_len);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc export public key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t mod_size = (public_key_len - 1) >> 1;
    errno_t rc = memcpy_s(hal_public_key->x, sizeof(hal_public_key->x),
        public_key + 1, mod_size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    hal_public_key->x_len = mod_size;
    rc = memcpy_s(hal_public_key->y, sizeof(hal_public_key->y),
        public_key + 1 + mod_size, mod_size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    hal_public_key->y_len = mod_size;
    hal_public_key->domain_id = get_ecc_curve_id_from_domain(GET_DX_EC_KEY_DOMAINID(cc_key));

    return CRYPTO_SUCCESS;
}

static void inplace_convert_bytes_word_endianness(uint32_t *buf_ptr, uint32_t size_words)
{
    if (buf_ptr == NULL)
        return;

    uint32_t mid = size_words / HALF_SIZE_BASE;
    /* Reverse words order and bytes in each word */
    for (uint32_t i = 0; i < mid; i++) {
        uint32_t tmp = REVERSE_ONE_WORD(buf_ptr[i]);
        buf_ptr[i] = REVERSE_ONE_WORD(buf_ptr[size_words - i - 1]);
        buf_ptr[size_words - i - 1] = tmp;
    }
    if ((size_words & ODD_NUM_MASK) != 0)
        buf_ptr[mid] = REVERSE_ONE_WORD(buf_ptr[mid]);
}

static int32_t  convert_lsw_msw_words_to_msb_lsb_bytes(
    uint8_t *out8_ptr, uint32_t size_out_bytes,
    uint32_t *in32_ptr, uint32_t size_in_bytes)
{
    if ((out8_ptr == NULL) || (in32_ptr == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if ((size_in_bytes == 0) || (size_out_bytes < size_in_bytes)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (((uintptr_t)out8_ptr > (uintptr_t)in32_ptr && (uintptr_t)out8_ptr < ((uintptr_t)in32_ptr + size_in_bytes)) ||
        ((uintptr_t)out8_ptr < (uintptr_t)in32_ptr && ((uintptr_t)out8_ptr + size_in_bytes) >= (uintptr_t)in32_ptr)) {
        tloge("The input and output addr is overlapped\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t size_in_words = BYTES_TO_WORD(size_in_bytes);

    inplace_convert_bytes_word_endianness(in32_ptr, size_in_words);

    if ((uintptr_t)out8_ptr != (uintptr_t)in32_ptr) {
        if (memcpy_s(out8_ptr, size_out_bytes,
            (uint8_t *)in32_ptr + ADDR_OFFSET_ALIGNED(size_in_bytes), size_in_bytes) != EOK)
            return CRYPTO_ERROR_SECURITY;
        /* Revert the input buffer to previous state */
        inplace_convert_bytes_word_endianness(in32_ptr, size_in_words);
    }

    return CRYPTO_SUCCESS;
}

static int32_t ecc_build_hal_private_key(dx_ecc_user_priv_key_t *cc_private_key,
    struct ecc_priv_key_t *hal_private_key)
{
    dx_ecc_priv_key_t *cc_key = (dx_ecc_priv_key_t *)cc_private_key->PrivKeyDbBuff;

    uint32_t key_size = get_ecc_key_size_from_domain(GET_DX_EC_KEY_DOMAINID(cc_key));
    if (key_size == ECC_INVALID_KEY_SIZE) {
        tloge("Invalid key size, key_size=0x%x\n", key_size);
        return CRYPTO_BAD_PARAMETERS;
    }
    uint32_t key_size_in_bytes = BITS_TO_BYTE(key_size);
    if (key_size_in_bytes > ECC_KEY_LEN) {
        tloge("Invalid key size, key_size_in_bytes=0x%x\n", key_size_in_bytes);
        return CRYPTO_BAD_PARAMETERS;
    }
    int32_t cc_ret = convert_lsw_msw_words_to_msb_lsb_bytes(hal_private_key->r,
        ALIGNED_TO_WORD(key_size_in_bytes), cc_key->PrivKey, key_size_in_bytes);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc build private key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    hal_private_key->domain_id = get_ecc_curve_id_from_domain(GET_DX_EC_KEY_DOMAINID(cc_key));
    hal_private_key->r_len = key_size_in_bytes;

    return CRYPTO_SUCCESS;
}

static int32_t ecc_build_hal_key(dx_ecc_user_pub_key_t *cc_public_key, dx_ecc_user_priv_key_t *cc_private_key,
    struct ecc_pub_key_t *hal_public_key, struct ecc_priv_key_t *hal_private_key)
{
    int32_t ret = ecc_build_hal_public_key(cc_public_key, hal_public_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Ecc build hal public key failed\n");
        return ret;
    }

    ret = ecc_build_hal_private_key(cc_private_key, hal_private_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Ecc build hal private key failed\n");
        return ret;
    }

    return CRYPTO_SUCCESS;
}

static int32_t ecc_generate_keypair(uint32_t key_size, uint32_t curve,
    struct ecc_pub_key_t *public_key, struct ecc_priv_key_t *private_key)
{
    (void)key_size;
    if ((public_key == NULL) || (private_key == NULL) || (curve == INVALID_CURVE_ID)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    dx_ecc_user_priv_key_t cc_private_key = {0};
    dx_ecc_user_pub_key_t cc_public_key = { 0, { 0 } };
    dx_ecc_kg_temp_data_t cc_tmp_data = {0};

    int32_t domain_id = get_ecc_domain_from_curve_id(curve);
    if (domain_id == INVALID_DOMAIN_ID) {
        tloge("Invalid ecc curve, curve=0x%x\n", curve);
        return CRYPTO_BAD_PARAMETERS;
    }
    if (check_g_rnd_ptr() != CC_DRIVER_OK)
        return CRYPTO_BAD_STATE;
    uint32_t cc_ret = cc_ecc_generate_key_pair(g_tmp_rnd_context_ptr, domain_id,
                                               &cc_private_key, &cc_public_key, &cc_tmp_data, NULL);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc generate key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = ecc_build_hal_key(&cc_public_key, &cc_private_key, public_key, private_key);
    (void)memset_s(&cc_private_key, sizeof(cc_private_key), 0, sizeof(cc_private_key));
    return ret;
}

static int32_t ecc_sign_digest(uint32_t alg_type, const struct ecc_priv_key_t *private_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest, struct memref_t *signature)
{
    (void)ec_params;
    if ((private_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    size_t signature_size = signature->size;
    dx_ecc_sign_user_ctx_t user_ctx;
    dx_ecc_user_priv_key_t cc_private_key = {0};

    (void)memset_s(&user_ctx, sizeof(user_ctx), 0, sizeof(user_ctx));
    int32_t domain_id = get_ecc_domain_from_curve_id(private_key->domain_id);
    if (domain_id == INVALID_DOMAIN_ID) {
        tloge("Invalid ecc domain id, domain_id=0x%x\n", domain_id);
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t hash_mode = get_hash_mode(alg_type);
    if (hash_mode == INVALID_HASH_MODE) {
        tloge("Algorithm not supported, alg_type=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }

    uint32_t cc_ret = cc_ecc_build_priv_key(domain_id,
        (uint8_t *)private_key->r, private_key->r_len, &cc_private_key);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc build private key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    if (check_g_rnd_ptr() != CC_DRIVER_OK)
        return CRYPTO_BAD_STATE;
    cc_ret = cc_ecc_sign(g_tmp_rnd_context_ptr, &user_ctx, &cc_private_key, (uint32_t)hash_mode,
        (uint8_t *)(uintptr_t)(digest->buffer), digest->size,
        (uint8_t *)(uintptr_t)(signature->buffer), &signature_size);
    (void)memset_s(&user_ctx, sizeof(user_ctx), 0, sizeof(user_ctx));
    (void)memset_s(&cc_private_key, sizeof(cc_private_key), 0, sizeof(cc_private_key));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc sign failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    signature->size = signature_size;

    return CRYPTO_SUCCESS;
}

static int32_t ecc_check_public_key_size(const struct ecc_pub_key_t *hal_key)
{
    if ((hal_key->x_len > (DX_EC_MAX_PUBLIC_KEY_LEN - ECC_POINT_LENGTH)) ||
        (hal_key->y_len > (DX_EC_MAX_PUBLIC_KEY_LEN - ECC_POINT_LENGTH)) ||
        (hal_key->y_len > (DX_EC_MAX_PUBLIC_KEY_LEN - ECC_POINT_LENGTH - hal_key->x_len)))
        return CRYPTO_BAD_PARAMETERS;

    return CRYPTO_SUCCESS;
}

static int32_t ecc_build_cc_public_key(const struct ecc_pub_key_t *hal_key, dx_ecc_user_pub_key_t *cc_key)
{
    uint8_t public_key[DX_EC_MAX_PUBLIC_KEY_LEN] = {0};
    size_t public_key_len = 0;
    dx_ecc_build_temp_data_t tmp_buf = {0};

    if (ecc_check_public_key_size(hal_key) != CRYPTO_SUCCESS) {
        tloge("Invalid ecc public key, x_len=0x%x, y_len=0x%x\n", hal_key->x_len, hal_key->y_len);
        return CRYPTO_BAD_PARAMETERS;
    }

    public_key[0] = ECC_POINT_TYPE;
    public_key_len++;

    errno_t rc = memcpy_s(public_key + 1, DX_EC_MAX_PUBLIC_KEY_LEN - 1, hal_key->x, hal_key->x_len);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    public_key_len += hal_key->x_len;
    rc = memcpy_s(public_key + 1 + hal_key->x_len, DX_EC_MAX_PUBLIC_KEY_LEN - 1 - hal_key->x_len,
        hal_key->y, hal_key->y_len);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }
    public_key_len += hal_key->y_len;

    int32_t domain_id = get_ecc_domain_from_curve_id(hal_key->domain_id);
    if (domain_id == INVALID_DOMAIN_ID) {
        tloge("Invalid ecc domain id, domain_id=0x%x\n", domain_id);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t cc_ret = cc_ecc_build_pub_key(domain_id,
        public_key, public_key_len, DX_CHECK_POINTERS_SIZES_ONLY, cc_key, &tmp_buf);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc build public key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t ecc_verify_digest(uint32_t alg_type, const struct ecc_pub_key_t *public_key,
    const struct asymmetric_params_t *ec_params, const struct memref_t *digest, const struct memref_t *signature)
{
    (void)ec_params;
    if ((public_key == NULL) || (digest == NULL) || (signature == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    dx_ecc_user_pub_key_t cc_public_key = { 0, { 0 } };
    dx_ecc_verify_user_ctx_t user_ctx;

    (void)memset_s(&user_ctx, sizeof(user_ctx), 0, sizeof(user_ctx));
    int32_t hash_mode = get_hash_mode(alg_type);
    if (hash_mode == INVALID_HASH_MODE) {
        tloge("Algorithm not supported, alg_type=0x%x\n", alg_type);
        return CRYPTO_NOT_SUPPORTED;
    }

    int32_t ret = ecc_build_cc_public_key(public_key, &cc_public_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Ecc build public key failed\n");
        return ret;
    }

    uint32_t cc_ret = cc_ecc_verify(&user_ctx, &cc_public_key, hash_mode,
        (uint8_t *)(uintptr_t)(signature->buffer), signature->size,
        (uint8_t *)(uintptr_t)(digest->buffer), digest->size);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc verify failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    return CRYPTO_SUCCESS;
}

static int32_t ecdh_derive_key(uint32_t alg_type,
    const struct ecc_pub_key_t *client_key, const struct ecc_priv_key_t *server_key,
    const struct asymmetric_params_t *ec_params, struct memref_t *secret)
{
    (void)ec_params;
    if ((client_key == NULL) || (server_key == NULL) || (secret == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    size_t derive_key_len = secret->size;
    dx_ecdh_temp_data_t tmp_data = {0};
    dx_ecc_user_pub_key_t cc_public_key = { 0, { 0 } };
    dx_ecc_user_priv_key_t cc_private_key = {0};

    if (alg_type != CRYPTO_TYPE_ECDH_DERIVE_SECRET) {
        tloge("Invalid algorithm\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    int32_t ret = ecc_build_cc_public_key(client_key, &cc_public_key);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Ecc build public key failed\n");
        return ret;
    }

    int32_t domain_id = get_ecc_domain_from_curve_id(server_key->domain_id);
    if (domain_id == INVALID_DOMAIN_ID) {
        tloge("Invalid ecc domain id, domain_id=0x%x\n", domain_id);
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t cc_ret = cc_ecc_build_priv_key(domain_id,
        (uint8_t *)server_key->r, server_key->r_len, &cc_private_key);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecc build private key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }

    cc_ret = cc_ecdh_svdp_dh(&cc_public_key, &cc_private_key,
        (uint8_t *)(uintptr_t)(secret->buffer), &derive_key_len, &tmp_data);
    (void)memset_s(&cc_private_key, sizeof(cc_private_key), 0, sizeof(cc_private_key));
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Ecdh derive key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    secret->size = derive_key_len;

    return CRYPTO_SUCCESS;
}

static int32_t dh_derive_key(const struct dh_key_t *derive_key_data, struct memref_t *secret)
{
    if ((derive_key_data == NULL) || (secret == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint16_t secret_len = (uint16_t)(secret->size);
    dx_dh_user_pub_key_t tmp_key = {0};
    dx_dh_prime_data_t tmp_data;
    (void)memset_s(&tmp_data, sizeof(tmp_data), 0, sizeof(tmp_data));

    uint32_t cc_ret = cc_dh_get_secret_key(
        (uint8_t *)(uintptr_t)(derive_key_data->dh_param.derive_key_t.priv_key),
        derive_key_data->dh_param.derive_key_t.priv_key_size,
        (uint8_t *)(uintptr_t)(derive_key_data->dh_param.derive_key_t.pub_key),
        derive_key_data->dh_param.derive_key_t.pub_key_size,
        (uint8_t *)(uintptr_t)(derive_key_data->prime), derive_key_data->prime_size,
        &tmp_key, &tmp_data, (uint8_t *)(uintptr_t)(secret->buffer), &secret_len);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Dh derive key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    secret->size = secret_len;

    return CRYPTO_SUCCESS;
}

static int32_t dh_generate_key(const struct dh_key_t *generate_key_data,
    struct memref_t *pub_key, struct memref_t *priv_key)
{
    if ((generate_key_data == NULL) || (pub_key == NULL) || (priv_key == NULL)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    size_t priv_key_len = priv_key->size;
    size_t pub_key_len = pub_key->size;
    dx_dh_user_pub_key_t user_key = {0};
    dx_dh_prime_data_t tmp_data;
    (void)memset_s(&tmp_data, sizeof(tmp_data), 0, sizeof(tmp_data));
    if (check_g_rnd_ptr() != CC_DRIVER_OK)
        return CRYPTO_BAD_STATE;
    uint32_t cc_ret = cc_dh_generate_pub_priv(g_tmp_rnd_context_ptr,
        (uint8_t *)(uintptr_t)generate_key_data->generator, generate_key_data->generator_size,
        (uint8_t *)(uintptr_t)generate_key_data->prime, generate_key_data->prime_size,
        (uint16_t)generate_key_data->dh_param.generate_key_t.l,
        (uint8_t *)(uintptr_t)generate_key_data->dh_param.generate_key_t.q,
        generate_key_data->dh_param.generate_key_t.q_size,
        DX_DH_PKCS3_MODE, &user_key, &tmp_data,
        (uint8_t *)(uintptr_t)(priv_key->buffer), &priv_key_len,
        (uint8_t *)(uintptr_t)(pub_key->buffer), &pub_key_len);
    if (cc_ret != CC_DRIVER_OK) {
        tloge("Dh generate key failed, cc_ret=0x%x\n", cc_ret);
        return CRYPTO_BAD_PARAMETERS;
    }
    priv_key->size = priv_key_len;
    pub_key->size = pub_key_len;

    return CRYPTO_SUCCESS;
}

static int32_t derive_root_key(uint32_t derive_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    (void)derive_type;
    if ((data_in == NULL) || (data_out == NULL) ||
        (data_out->size < AES_CMAC_LEN)) {
        tloge("Invalid params\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    uint32_t ret = cc_cmac_derive_key(NULL, (uint8_t *)(uintptr_t)(data_in->buffer), data_in->size,
        (uint8_t *)(uintptr_t)(data_out->buffer));
    if (ret != CC_DRIVER_OK) {
        tloge("Derive root key failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    data_out->size = AES_CMAC_LEN;

    return CRYPTO_SUCCESS;
}

const static struct crypto_ops_t g_crypto_ops = {
    dxcc_power_on,
    dxcc_power_off,
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
    ae_init,
    ae_update_aad,
    ae_update,
    ae_enc_final,
    ae_dec_final,
    rsa_generate_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign_digest,
    rsa_verify_digest,
    ecc_generate_keypair,
    NULL,
    NULL,
    ecc_sign_digest,
    ecc_verify_digest,
    ecdh_derive_key,
    dh_generate_key,
    dh_derive_key,
    generate_random,
    get_entropy,
    derive_root_key,
    NULL
};

static int32_t cc_crypto_init(void)
{
    if (check_g_rnd_ptr() != CC_DRIVER_OK)
        return CRYPTO_BAD_STATE;
    uint32_t ret = cc_lib_init(g_tmp_rnd_context_ptr, g_tmp_rnd_workbuff_ptr, false, NULL);
    if (ret != CC_DRIVER_OK) {
        tloge("CC lib init failed\n");
        return CRYPTO_BAD_PARAMETERS;
    }
    return register_crypto_ops(DX_CRYPTO_FLAG, &g_crypto_ops);
}

static int32_t cc_suspend_proc(void)
{
#if (TRUSTEDCORE_PLATFORM_CHOOSE != WITH_BALONG_PLATFORM)
    set_secs_suspend_flag();
#endif
    return CRYPTO_SUCCESS;
}

DECLARE_TC_DRV(
    ccdriver_init,
    0,
    0,
    0,
    TC_DRV_EARLY_INIT,
    cc_crypto_init,
    NULL,
    NULL,
    cc_suspend_proc,
    NULL
);
