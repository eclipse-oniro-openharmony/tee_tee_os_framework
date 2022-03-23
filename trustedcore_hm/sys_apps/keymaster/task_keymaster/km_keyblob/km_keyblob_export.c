/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster export key process
 * Create: 2020-11-09
 */
#include "securec.h"
#include "keyblob.h"
#include "km_common.h"
#include "km_tag_operation.h"
#include "km_key_check.h"
#include "km_crypto_adaptor.h"
static TEE_Result extract_ec_pub_key_out(TEE_ObjectHandle key_obj, TEE_Param *params, uint32_t key_size)
{
    if (key_obj == TEE_HANDLE_NULL || params == NULL) {
        tloge("invalid parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t x[ECC_PUB_LEN] = { 0 };
    uint8_t y[ECC_PUB_LEN] = { 0 };
    size_t x_len = ECC_PUB_LEN;
    size_t y_len = ECC_PUB_LEN;
    TEE_Result ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_X, x, &x_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub key modulus failed\n");
        return TEE_ERROR_GENERIC;
    }
    ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_ECC_PUBLIC_VALUE_Y, y, &y_len);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub exponent failed\n");
        return TEE_ERROR_GENERIC;
    }
    struct pub_key_header *pub_key_out = (struct pub_key_header *)params[PARAM_TWO].memref.buffer;
    if (params[PARAM_TWO].memref.size < sizeof(*pub_key_out)) {
        tloge("invalid pub key out params size:%zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    errno_t rc = memcpy_s((uint8_t *)pub_key_out + sizeof(*pub_key_out), params[PARAM_TWO].memref.size -
        sizeof(*pub_key_out), x, x_len);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }
    rc = memcpy_s((uint8_t *)pub_key_out + sizeof(*pub_key_out) + x_len, params[PARAM_TWO].memref.size -
     sizeof(*pub_key_out) - x_len, y, y_len);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }

    pub_key_out->key_size = key_size;
    if (pub_key_out->key_size == 0)
        return TEE_ERROR_GENERIC;
    tlogd("pub_key_out->key_size=%u\n", pub_key_out->key_size);

    /* set header */
    pub_key_out->alg = KM_ALGORITHM_EC;
    pub_key_out->n_or_x_len = (uint32_t)x_len;
    pub_key_out->e_or_y_len = (uint32_t)y_len;
    params[PARAM_TWO].memref.size = sizeof(*pub_key_out) + x_len + y_len;
    return TEE_SUCCESS;
}

static TEE_Result populate_ec_keyobj(struct keymaterial_ecdsa_header *keymaterial, TEE_ObjectHandle *key_obj,
    const keymaster_key_param_set_t *hw_enforced, uint8_t *temp_buf, uint32_t *key_size)
{
    TEE_Result ret;
    bool check_fail = (keymaterial == NULL || key_obj == NULL || hw_enforced == NULL ||
        temp_buf == NULL || key_size == NULL);
    if (check_fail) {
        tloge("invalid parameters\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ec_nist_curve2key_size(keymaterial->ecc_curv, key_size) != 0) {
        tloge("get key size failed\n");
        return TEE_ERROR_GENERIC;
    }

    ret = get_key_object(KM_ALGORITHM_EC, *key_size, hw_enforced, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }
    ret = gp_buffer_to_key_obj(temp_buf, keymaterial->key_buff_len, *key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }

    (*key_obj)->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    ret = TEE_RestrictObjectUsage1(*key_obj, (*key_obj)->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        return ret;
    }
    return TEE_SUCCESS;
}

static TEE_Result ec_keymaterial_internal_check(const uint8_t *keymaterial, uint32_t len)
{
    if (keymaterial == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (len < sizeof(struct keymaterial_ecdsa_header)) {
        tloge("invalid keymaterial size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct keymaterial_ecdsa_header *p = (struct keymaterial_ecdsa_header *)keymaterial;
    if (p->magic != KM_MAGIC_NUM) {
        tloge("magic is 0x%x, keymaterial is invalid\n", p->magic);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((len - sizeof(struct keymaterial_ecdsa_header)) < p->key_buff_len) {
        tloge("keymaterial size is %u, key buff len is %u, keymaterial is invalid\n", len,
            p->key_buff_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
static TEE_Result process_ec_export_key(const keymaster_key_param_set_t *hw_enforced, TEE_Param *params,
    keymaster_blob_t *input_keyblob, const struct kb_crypto_factors *factors)
{
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    if ((input_keyblob->data_addr + ((keyblob_head *)input_keyblob->data_addr)->keymaterial_offset) == NULL) {
        tloge("keymaterial is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct keymaterial_ecdsa_header *keymaterial = (struct keymaterial_ecdsa_header *)(input_keyblob->data_addr +
        ((keyblob_head *)input_keyblob->data_addr)->keymaterial_offset);
    if (ec_keymaterial_internal_check((uint8_t *)keymaterial,
        ((keyblob_head *)input_keyblob->data_addr)->keymaterial_size) != TEE_SUCCESS) {
        tloge("ec keymaterial check failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* decrypt keymaterial */
    keymaster_blob_t in = { keymaterial->key, keymaterial->key_buff_len };
    keymaster_blob_t out = { NULL, keymaterial->key_buff_len };
    out.data_addr = (uint8_t *)TEE_Malloc(keymaterial->key_buff_len, TEE_MALLOC_FILL_ZERO);
    if (out.data_addr == NULL) {
        tloge("temp buf malloc failed, size %u\n", keymaterial->key_buff_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    struct keyblob_crypto_ctx ctx = {
        ((keyblob_head *)input_keyblob->data_addr)->version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { keymaterial->iv, IV_LEN },
        *factors
    };
    TEE_Result ret = keyblob_crypto(&in, &out, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("decrypt keymaterial failed, ret = 0x%x\n", ret);
        goto release;
    }
    uint32_t key_size = 0;
    ret = populate_ec_keyobj(keymaterial, &key_obj, hw_enforced, out.data_addr, &key_size);
    if (ret != TEE_SUCCESS) {
        tloge("populate ec key object handle failed\n");
        goto release;
    }
    ret = extract_ec_pub_key_out(key_obj, params, key_size);
    if (ret != TEE_SUCCESS)
        tloge("extract ec pub key out failed\n");
release:
    erase_free_blob(&out);
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    return ret;
}

static TEE_Result populate_rsa_keyobj(uint32_t key_size, const keymaster_key_param_set_t *hw_enforced,
    TEE_ObjectHandle *key_obj, struct keymaterial_rsa_header *keymaterial, uint8_t *temp_buf)
{
    TEE_Result ret = get_key_object(KM_ALGORITHM_RSA, key_size, hw_enforced, key_obj);
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }
    if (keymaterial->crt_mode == GP_NOCRT_MODE || keymaterial->crt_mode == GP_CRT_MODE) {
        (*key_obj)->CRTMode = keymaterial->crt_mode;
    } else {
        tloge("wrong rsa key_type\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    (*key_obj)->ObjectInfo->objectUsage |= TEE_USAGE_EXTRACTABLE;
    ret = TEE_RestrictObjectUsage1((*key_obj), (*key_obj)->ObjectInfo->objectUsage);
    if (ret != TEE_SUCCESS) {
        tloge("set object handle extractable usage failed\n");
        return ret;
    }

    ret = gp_buffer_to_key_obj(temp_buf, keymaterial->key_buff_len, (*key_obj));
    if (ret != TEE_SUCCESS) {
        tloge("get key object failed\n");
        return ret;
    }
    return TEE_SUCCESS;
}
static TEE_Result extract_rsa_pub_key_out(TEE_Param *params, TEE_ObjectHandle key_obj)
{
    if (key_obj == TEE_HANDLE_NULL || params == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t n[KM_KEY_SIZE_4096 / KM_BYTE_SIZE_8] = { 0 };
    size_t n_size = KM_KEY_SIZE_4096 / KM_BYTE_SIZE_8;
    uint8_t e[KM_KEY_SIZE_4096 / KM_BYTE_SIZE_8] = { 0 };
    size_t e_size = KM_KEY_SIZE_4096 / KM_BYTE_SIZE_8;
    TEE_Result ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_RSA_MODULUS, n, &n_size);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub key modulus failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = TEE_GetObjectBufferAttribute(key_obj, TEE_ATTR_RSA_PUBLIC_EXPONENT, e, &e_size);
    if (ret != TEE_SUCCESS) {
        tloge("get rsa pub exponent failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    struct pub_key_header *pub_key_out = (struct pub_key_header *)params[PARAM_TWO].memref.buffer;
    if (params[PARAM_TWO].memref.size < sizeof(*pub_key_out)) {
        tloge("invalid pub key out params size:%zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    errno_t rc = memcpy_s((uint8_t *)pub_key_out + sizeof(*pub_key_out),
        params[PARAM_TWO].memref.size - sizeof(*pub_key_out), n, n_size);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }

    rc = memcpy_s((uint8_t *)pub_key_out + sizeof(*pub_key_out) + n_size, params[PARAM_TWO].memref.size -
        sizeof(*pub_key_out) - n_size, e, e_size);
    if (rc != EOK) {
        tloge("memcpy_s failed, rc 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }
    /* set header */
    pub_key_out->alg = KM_ALGORITHM_RSA;
    pub_key_out->key_size = n_size << KM_FACTOR_3;
    pub_key_out->n_or_x_len = (uint32_t)n_size;
    pub_key_out->e_or_y_len = (uint32_t)e_size;
    params[PARAM_TWO].memref.size = sizeof(*pub_key_out) + n_size + e_size;
    return TEE_SUCCESS;
}

static TEE_Result process_rsa_export_key(uint32_t key_size, const keymaster_key_param_set_t *hw_enforced,
    TEE_Param *params, keymaster_blob_t *input_keyblob, const struct kb_crypto_factors *factors)
{
    TEE_Result ret;
    TEE_ObjectHandle key_obj = TEE_HANDLE_NULL;
    struct keymaterial_rsa_header *keymaterial = (struct keymaterial_rsa_header *)(input_keyblob->data_addr +
        ((keyblob_head *)input_keyblob->data_addr)->keymaterial_offset);
    if (rsa_keymaterial_internal_check((uint8_t *)keymaterial,
        ((keyblob_head *)input_keyblob->data_addr)->keymaterial_size) != TEE_SUCCESS) {
        tloge("check rsa keymaterial failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* decrypt keymaterial */
    keymaster_blob_t in = { keymaterial->key, keymaterial->key_buff_len };
    keymaster_blob_t out = { NULL, keymaterial->key_buff_len };
    out.data_addr = (uint8_t *)TEE_Malloc(keymaterial->key_buff_len, TEE_MALLOC_FILL_ZERO);
    if (out.data_addr == NULL) {
        tloge("buf malloc failed, size %u\n", keymaterial->key_buff_len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    struct keyblob_crypto_ctx ctx = {
        ((keyblob_head *)input_keyblob->data_addr)->version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { keymaterial->iv, IV_LEN },
        *factors
    };
    ret = keyblob_crypto(&in, &out, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("decrypt keymaterial failed, ret = 0x%x\n", ret);
        goto release;
    }

    ret = populate_rsa_keyobj(key_size, hw_enforced, &key_obj, keymaterial, out.data_addr);
    if (ret != TEE_SUCCESS) {
        tloge("populate rsa keyobj failed\n");
        goto release;
    }

    ret = extract_rsa_pub_key_out(params, key_obj);
    if (ret != TEE_SUCCESS)
        tloge("export rsa pub key out failed\n");
release:
    TEE_FreeTransientObject(key_obj);
    key_obj = TEE_HANDLE_NULL;
    erase_free_blob(&out);
    return ret;
}
TEE_Result process_public_key_out(keymaster_algorithm_t algorithm, TEE_Param *params,
    const keymaster_key_param_set_t *hw_enforced, const struct kb_crypto_factors *factors)
{
    /* format pub key out */
    keymaster_blob_t input_keyblob = { (uint8_t *)params[PARAM_ZERO].memref.buffer,
        (uint32_t)params[ZERO].memref.size };
    TEE_Result tee_ret;
    if (params[PARAM_TWO].memref.size < sizeof(struct pub_key_header)) {
        tloge("invalid pub key out params size:%zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (algorithm == KM_ALGORITHM_RSA) {
        /* get keysize */
        uint32_t key_size = 0;
        if (get_key_param(KM_TAG_KEY_SIZE, &key_size, hw_enforced) != 0) {
            tloge("get_key_param of key_size failed\n");
            return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_SIZE;
        }

        tee_ret = process_rsa_export_key(key_size, hw_enforced, params, &input_keyblob, factors);
        if (tee_ret != TEE_SUCCESS) {
            tloge("process rsa export_key is failed\n");
            return tee_ret;
        }
        tlogd("export RSA key success, pub_key_out_len=%zu\n", params[PARAM_TWO].memref.size);
    } else if (algorithm == KM_ALGORITHM_EC) {
        tee_ret = process_ec_export_key(hw_enforced, params, &input_keyblob, factors);
        if (tee_ret != TEE_SUCCESS) {
            tloge("process ec export_key is failed\n");
            return tee_ret;
        }
        tlogd("export EC key success, pub_key_out_len=%zu\n", params[PARAM_TWO].memref.size);
    } else {
        tloge("not support algorithm:%d for export key\n", algorithm);
        return (TEE_Result)KM_ERROR_UNSUPPORTED_KEY_FORMAT;
    }

    return TEE_SUCCESS;
}
