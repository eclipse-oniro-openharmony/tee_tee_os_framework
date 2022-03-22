/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster keyblob process
 * Create: 2020-11-09
 */

#include "keymaster_defs.h"
#include "securec.h"
#include "tee_crypto_api.h"
#include "km_common.h"
#include "km_types.h"
#include "km_tag_operation.h"
#include "km_env.h"
#include "keyblob.h"
#include "km_3des_weak_keys.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "km_key_enhanced.h"
#endif

static TEE_Result generate_keymaterial_get_key(TEE_ObjectHandle object_handle, keymaster_blob_t *key)
{
    if (key == NULL)
        return TEE_ERROR_GENERIC;
    key->data_addr = TEE_Malloc(KEY_BLOB_MAX_SIZE, TEE_MALLOC_FILL_ZERO); /* should be freed in this function */
    if (key->data_addr == NULL) {
        tloge("alloc key buffer failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    uint32_t length = key->data_length;
    TEE_Result ret = key_object_to_buffer(object_handle, key->data_addr, &length);
    if (ret != TEE_SUCCESS) {
        tloge("convert key object to buffer faild\n");
        return ret;
    }
    key->data_length = length;
    return ret;
}

TEE_Result generate_ec_keymaterial(TEE_ObjectHandle object_handle, uint32_t gp_ec_curve, uint32_t version,
    const struct kb_crypto_factors *factors, keymaster_blob_t *keymaterial)
{
    if ((keymaterial == NULL || factors == NULL || keymaterial->data_addr != NULL)) {
        tloge("input ec parameters invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_blob_t key = { NULL, KEY_BLOB_MAX_SIZE };
    TEE_Result ret = generate_keymaterial_get_key(object_handle, &key);
    if (ret != TEE_SUCCESS) {
        tloge("alloc temp key failed\n");
        goto error;
    }
    /* alloc  keymaterial */
    keymaterial->data_length = four_bytes_align_up(sizeof(struct keymaterial_ecdsa_header) + key.data_length);
    keymaterial->data_addr = (uint8_t *)TEE_Malloc(keymaterial->data_length, TEE_MALLOC_FILL_ZERO);
    if (keymaterial->data_addr == NULL) {
        tloge("keymaterial malloc failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    struct keymaterial_ecdsa_header *buff = (struct keymaterial_ecdsa_header *)keymaterial->data_addr;
    buff->magic = KM_MAGIC_NUM; /* set magic */
    TEE_GenerateRandom(buff->iv, IV_LEN);  /* generate iv */
    if (is_buff_zero(buff->iv, IV_LEN)) {
        tloge("iv random failed\n");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    buff->key_buff_len = key.data_length;
    buff->ecc_curv = gp_ec_curve;
    keymaster_blob_t in = { key.data_addr, key.data_length };
    keymaster_blob_t out = { (uint8_t *)(buff->key), key.data_length };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_ENCRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { buff->iv, IV_LEN },
        *factors
    };
    ret = keyblob_crypto(&in, &out, &ctx);
    if (ret != TEE_SUCCESS)
        tloge("encrypt ec key failed, ret = 0x%x\n", ret);
error:
    erase_free_blob(&key);
    return ret;
}

TEE_Result generate_symmetric_keymaterial(TEE_ObjectHandle object_handle, const struct kb_crypto_factors *factors,
                                          uint32_t version, keymaster_blob_t *keymaterial)
{
    if ((keymaterial == NULL || factors == NULL || keymaterial->data_addr != NULL)) {
        tloge("generate symmetric keymaterial input params invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_blob_t key = { NULL, KEY_BLOB_MAX_SIZE };
    TEE_Result ret = generate_keymaterial_get_key(object_handle, &key);
    if (ret != TEE_SUCCESS) {
        tloge("alloc temp key failed\n");
        goto error;
    }
    /* make keymaterial buffer align 4 bytes */
    keymaterial->data_length = four_bytes_align_up(sizeof(struct keymaterial_symmetric_header)
        + key.data_length);
    keymaterial->data_addr = TEE_Malloc(keymaterial->data_length, TEE_MALLOC_FILL_ZERO);
    if (keymaterial->data_addr == NULL) {
        tloge("keymaterial malloc failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    tlogd("keymaterial_size = %u\n", keymaterial->data_length);
    struct keymaterial_symmetric_header *buff = (struct keymaterial_symmetric_header *)keymaterial->data_addr;
    buff->magic = KM_MAGIC_NUM;
    TEE_GenerateRandom(buff->iv, IV_LEN);
    if (is_buff_zero(buff->iv, IV_LEN)) {
        tloge("iv random failed\n");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    buff->key_buff_len = key.data_length;
    keymaster_blob_t data_in = { key.data_addr, key.data_length };
    keymaster_blob_t data_out = { buff->key, key.data_length };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_ENCRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { buff->iv, IV_LEN },
        *factors
    };
    ret = keyblob_crypto(&data_in, &data_out, &ctx);
    if (ret != TEE_SUCCESS)
        tloge("encrypt symmetric keys failed, ret = 0x%x\n", ret);
error:
    erase_free_blob(&key);
    return ret;
}
TEE_Result parser_symmetric_keymaterial(uint8_t *input, uint8_t *output, uint32_t key_size, uint32_t version,
    const struct kb_crypto_factors *factors)
{
    if (input == NULL || output == NULL) {
        tloge("null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct keymaterial_symmetric_header *keymaterial = (struct keymaterial_symmetric_header *)input;
    /* check magic */
    if (keymaterial->magic != KM_MAGIC_NUM) {
        tloge("magic is invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (eight_align_up(key_size) / BITS_ONE_BYTE > keymaterial->key_buff_len) {
        tloge("key_size %u larger than gp buffer %u\n", key_size, keymaterial->key_buff_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* decrypt keymaterial */
    keymaster_blob_t data_in = { keymaterial->key, keymaterial->key_buff_len };
    keymaster_blob_t data_out = { output, keymaterial->key_buff_len };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { keymaterial->iv, IV_LEN },
        *factors
    };
    TEE_Result ret = keyblob_crypto(&data_in, &data_out, &ctx);
    if (ret != TEE_SUCCESS)
        tloge("decrypt symmetric keymaterial failed, ret = 0x%x\n", ret);
    return ret;
}

TEE_Result generate_rsa_keymaterial(TEE_ObjectHandle object_handle, uint32_t version,
    const struct kb_crypto_factors *factors, keymaster_blob_t *keymaterial)
{
    if ((keymaterial == NULL || factors == NULL || keymaterial->data_addr != NULL)) {
        tloge("input rsa parameters invalid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_blob_t key = { NULL, KEY_BLOB_MAX_SIZE };
    TEE_Result ret = generate_keymaterial_get_key(object_handle, &key);
    if (ret != TEE_SUCCESS) {
        tloge("alloc temp key failed\n");
        goto error;
    }
    keymaterial->data_length = four_bytes_align_up(sizeof(struct keymaterial_rsa_header) + key.data_length);
    keymaterial->data_addr = (uint8_t *)TEE_Malloc(keymaterial->data_length, TEE_MALLOC_FILL_ZERO);
    if (keymaterial->data_addr == NULL) {
        tloge("keymaterial malloc failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto error;
    }
    struct keymaterial_rsa_header *buff = (struct keymaterial_rsa_header *)keymaterial->data_addr;
    /* set magic */
    buff->magic = KM_MAGIC_NUM;
    buff->key_buff_len = key.data_length;
    buff->crt_mode = object_handle->CRTMode;
    /* generate iv */
    TEE_GenerateRandom(buff->iv, IV_LEN);
    if (is_buff_zero(buff->iv, IV_LEN)) {
        tloge("iv random failed\n");
        ret = TEE_ERROR_GENERIC;
        goto error;
    }
    keymaster_blob_t in = { key.data_addr, key.data_length };
    keymaster_blob_t out = { buff->key, key.data_length };
    struct keyblob_crypto_ctx ctx = {
        version, (uint32_t)TEE_MODE_ENCRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { buff->iv, IV_LEN },
        *factors
    };
    ret = keyblob_crypto(&in, &out, &ctx);
    if (ret != TEE_SUCCESS)
        tloge("encrypt rsa key failed, ret = 0x%x\n", ret);
error:
    erase_free_blob(&key);
    return ret;
}

int32_t generate_3des_key(uint8_t *key, uint32_t key_size_in_bytes)
{
    int32_t ret          = 1;
    int max_try_time = MAX_TRY_GENERATE_KEY_TIME;
    while (ret == 1 && max_try_time != 0) {
        TEE_GenerateRandom(key, key_size_in_bytes);
        ret = check_des_weak_keys(key, key_size_in_bytes);
        max_try_time--;
    }
    return ret;
}
int32_t check_symmetric_key_random(uint32_t key_size_in_bytes, const uint8_t *key)
{
    uint32_t i;
    uint32_t j = 0;
    for (i = 0; i < key_size_in_bytes; i++)
        if (key[i] == 0)
            j++;

    if (j == key_size_in_bytes) {
        tloge("key random failed\n");
        return -1;
    }

    return 0;
}

TEE_Result km_copy_keyblob(keyblob_head *keyblob_in, uint32_t keyblob_in_size, const struct kb_crypto_factors *factors,
    keyblob_head *keyblob_out, uint32_t keyblob_out_size)
{
    if (keyblob_in == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (memcpy_s(keyblob_out, keyblob_out_size, keyblob_in, keyblob_in_size) != EOK) {
        tloge("memcpy keyblob failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* decrypt hidden param to verify APPLICATION_ID and APPLICATION_DATA */
    return decrypt_keyblob_hidden(keyblob_in, factors);
}

TEE_Result get_cur_version(const keymaster_key_param_set_t *param, keymaster_algorithm_t alg, uint32_t *version)
{
    if (version == NULL) {
        tloge("null pointer");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *version = VERSION_530;
    if (param == NULL)
        return TEE_SUCCESS;

    keymaster_blob_t application_id;
    uint32_t *passwd_flag = get_passwd_flag();

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    bool is_enhanced_key = false;
    if (get_key_param(KM_TAG_HW_ENHANCED_KEY, &is_enhanced_key, param) != 0)
        is_enhanced_key = false;

    bool has_enhanced_appid = (get_key_param(KM_TAG_HW_ENHANCED_KEY_APPID, &application_id, param) == 0);
    if (alg == KM_ALGORITHM_AES && is_enhanced_key && has_enhanced_appid) {
        tlogd("get_key_param of enhanced APPLICATION TAG success");
        uint8_t temp[MAX_INSE_FACTOR_LEN] = { 0 };
        keymaster_blob_t inse_factor = { temp, sizeof(temp) };
        if (get_inse_factor(param, &inse_factor) != TEE_SUCCESS) {
            tlogd("not find inse factor");
            *version = VERSION_540;
            (void)memset_s(temp, sizeof(temp), 0x0, sizeof(temp));
            return TEE_SUCCESS;
        }
        tlogd("find inse factor");
        *version = VERSION_541;
        (void)memset_s(temp, sizeof(temp), 0x0, sizeof(temp));
        return TEE_SUCCESS;
    }
    if ((is_enhanced_key != has_enhanced_appid) || (has_enhanced_appid && alg != KM_ALGORITHM_AES)) {
        tloge("bad parameters, enhance key type %u, enhance appid type %u, alg %u",
            is_enhanced_key, has_enhanced_appid, alg);
        return TEE_ERROR_BAD_PARAMETERS;
    }
#endif
    (void)alg;
    if ((get_key_param(KM_TAG_APPLICATION_ID, &application_id, param) == 0) && ((*passwd_flag) != 0)) {
        tlogd("get_key_param of APPLICATION TAG success");
        *version = VERSION_510;
    }
    tlogd("version %u", *version);
    return TEE_SUCCESS;
}
