/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: operate enhanced key params functions
 * Create: 2021-01-09
 */

#include "km_key_enhanced.h"
#include "securec.h"
#include "km_tag_operation.h"
#include "km_env.h"
#include "km_common.h"
#include "keyblob.h"
#include "gatekeeper_drv_call.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY

TEE_Result unsupport_enhanced_key(const keymaster_key_param_set_t *param)
{
    /*
     * NOTICE: Interfaces contain input keyblob parameters, without enhanced app id data should NOT support the special
     * TAGS KM_TAG_HW_ENHANCED_KEY, KM_TAG_HW_ENHANCED_KEY_APPID.
     * The TAG may be detected in keyblob or input paramset of the BELOW interfaces:
     * [km_generate_key, km_get_key_characteristics, km_export_key, km_attest_key, km_verify_attestationids_with_param,
     * km_key_policy_set], The interfaces [km_import_key, km_begin, km_upgrade] using NON-AES algorithms [RSA, EC, HMAC]
     * should NOT support TAGS KM_TAG_HW_ENHANCED_KEY, KM_TAG_HW_ENHANCED_KEY_APPID ALSO.
     */
    bool is_enhanced_key = false;
    keymaster_blob_t application_id = { NULL, 0 };
    if (param == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((get_key_param(KM_TAG_HW_ENHANCED_KEY, &is_enhanced_key, param) == 0)) {
        if (is_enhanced_key) {
            tloge("params contained unsupported tags here %x", KM_TAG_HW_ENHANCED_KEY);
            return TEE_ERROR_NOT_SUPPORTED;
        }
    }

    if (get_key_param(KM_TAG_HW_ENHANCED_KEY_APPID, &application_id, param) == 0) {
        tloge("params contained unsupported tags here %x", KM_TAG_HW_ENHANCED_KEY_APPID);
        return TEE_ERROR_NOT_SUPPORTED;
    }

    tlogd("check unsupported tag pass");
    return TEE_SUCCESS;
}

static TEE_Result get_inse_factor_by_sid(uint64_t secure_id, keymaster_blob_t *inse_factor)
{
    bool found = __get_key_factor(secure_id, inse_factor->data_addr, &(inse_factor->data_length));
    if (found) {
        tlogd("get key factor success: %u", inse_factor->data_length);
        return TEE_SUCCESS;
    } else {
        tlogd("get key factor failed: %u", inse_factor->data_length);
        inse_factor->data_addr = NULL;
        inse_factor->data_length = 0;
        return TEE_ERROR_NOT_SUPPORTED;
    }
}

TEE_Result get_inse_factor(const keymaster_key_param_set_t *params, keymaster_blob_t *inse_factor)
{
    if (params == NULL || inse_factor == NULL || inse_factor->data_addr == NULL || inse_factor->data_length == 0) {
        tloge("get factor: bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret;
    uint64_t secure_id;
    bool found = false;
    keymaster_key_param_t *params_hw = (keymaster_key_param_t *)((uint8_t *)params + sizeof(uint32_t));
    if (params_hw == NULL) {
        tloge("params_hw is null");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    uint32_t hw_enforced_len = *(uint32_t *)params;
    keymaster_key_param_t *params_sw = (keymaster_key_param_t *)((uint8_t *)params_hw +
        (hw_enforced_len * sizeof(keymaster_key_param_t)) + sizeof(uint32_t));
    if (params_sw == NULL) {
        tloge("params_sw is null");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    uint32_t sw_enforced_len = *(uint32_t *)((uint8_t *)params_hw + (hw_enforced_len * sizeof(keymaster_key_param_t)));
    for (uint32_t i = 0; i < hw_enforced_len + sw_enforced_len; i++) {
        if (i < hw_enforced_len) {
            if (params_hw[i].tag != KM_TAG_USER_SECURE_ID)
                continue;

            secure_id = params_hw[i].long_integer;
        } else {
            if (params_sw[i - hw_enforced_len].tag != KM_TAG_USER_SECURE_ID)
                continue;

            secure_id = params_sw[i - hw_enforced_len].long_integer;
        }

        tlogd("find secure id: %u", i);
        ret = get_inse_factor_by_sid(secure_id, inse_factor);
        if (ret == TEE_SUCCESS) {
            found = true;
            break;
        }
    }

    if (!found) {
        tlogd("not find inse factor ");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    tlogd("find inse factor: %u", inse_factor->data_length);
    return TEE_SUCCESS;
}

static TEE_Result re_encrypt_hidden(const struct kb_crypto_factors *factors, const keyblob_head *keyblob_old,
    keyblob_head *keyblob_new)
{
    TEE_Result ret;
    uint32_t hidden_size = keyblob_old->extend2_buf_offset - keyblob_old->hidden_offset + keyblob_old->extend2_size;
    /* get decrypted hidden data from old keyblob */
    if (memcpy_s((uint8_t *)keyblob_new + keyblob_new->hidden_offset, hidden_size,
        (uint8_t *)keyblob_old + keyblob_old->hidden_offset, hidden_size) != EOK) {
        tloge("memcpy_s failed");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* re encrypt hidden data */
    uint8_t temp_buff[MAX_KEY_BUFFER_LEN] = { 0 };
    keymaster_blob_t blob = { temp_buff, hidden_size };
    keymaster_blob_t crypto_blob = { (uint8_t *)keyblob_new + keyblob_new->hidden_offset, hidden_size };
    struct keyblob_crypto_ctx ctx = {
        keyblob_new->version, (uint32_t)TEE_MODE_ENCRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        NO_EXTRA_ITERATE,
#endif
        { keyblob_new->hidden_iv, IV_LEN },
        *factors
    };

    if (memcpy_s(blob.data_addr, blob.data_length, crypto_blob.data_addr, crypto_blob.data_length) != EOK) {
        tloge("memcpy_s failed");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto erase_temp_buf;
    }
    ret = keyblob_crypto(&blob, &crypto_blob, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("re-encrypt hidden data failed");
        goto erase_temp_buf;
    }

erase_temp_buf:
    (void)memset_s(temp_buff, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
    return ret;
}

static TEE_Result convert_keymaterial_dx2gp(keymaster_blob_t *key_blob)
{
    TEE_Result ret = TEE_SUCCESS;
    uint8_t temp_buff[MAX_KEY_BUFFER_LEN] = { 0 };
    keymaster_blob_t gp_blob = { temp_buff, sizeof(temp_buff) };
    if (symm_key_dx2gp(key_blob, &gp_blob) != TEE_SUCCESS || gp_blob.data_length > MAX_KEY_BUFFER_LEN) {
        tloge("re-encrypt keymaterial: dx2gp fail %u, %u", key_blob->data_length, gp_blob.data_length);
        ret = TEE_ERROR_GENERIC;
        goto erase_temp_buf;
    }
    /* the max size of this key_blob is MAX_KEY_BUFFER_LEN and keyblob->data_length is less than gp_blob.data_length */
    if (memcpy_s(key_blob->data_addr, MAX_KEY_BUFFER_LEN, gp_blob.data_addr, gp_blob.data_length) != EOK) {
        tloge("memcpy_s failed");
        ret = TEE_ERROR_GENERIC;
        goto erase_temp_buf;
    }
    key_blob->data_length = gp_blob.data_length;

erase_temp_buf:
    (void)memset_s(temp_buff, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
    return ret;
}

static TEE_Result re_encrypt_keymaterial(uint32_t old_version, uint32_t new_version,
    const struct kb_crypto_factors *old_factors, const struct kb_crypto_factors *new_factors,
    keymaster_blob_t *new_material)
{
    TEE_Result ret;
    struct keymaterial_symmetric_header *new_material_header;
    new_material_header = (struct keymaterial_symmetric_header *)new_material->data_addr;

    uint8_t crypto_buff[MAX_KEY_BUFFER_LEN] = { 0 };

    /* decrypt key material */
    keymaster_blob_t blob = { new_material_header->key, new_material_header->key_buff_len };
    keymaster_blob_t crypto_blob = { crypto_buff, new_material_header->key_buff_len };
    struct keyblob_crypto_ctx ctx = {
        old_version, (uint32_t)TEE_MODE_DECRYPT,
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        EXTRA_ITERATE,
#endif
        { new_material_header->iv, IV_LEN }, *old_factors
    };
    ret = keyblob_crypto(&blob, &crypto_blob, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("re-encrypt keymaterial: decrypt symm key fail");
        goto erase_temp_buf;
    }

    /* convert keymaterial from dx to gp */
    if (old_version == VERSION_340) {
        if (convert_keymaterial_dx2gp(&crypto_blob) != TEE_SUCCESS) {
            tloge("re-encrypt keymaterial: dx2gp fail %u", crypto_blob.data_length);
            goto erase_temp_buf;
        }
    }

    /* re encrypt keymaterial with new factor */
    blob.data_length = crypto_blob.data_length;
    ctx.keyblob_version = new_version;
    ctx.op_mode = (uint32_t)TEE_MODE_ENCRYPT;
    ctx.factors = *new_factors;

    ret = keyblob_crypto(&crypto_blob, &blob, &ctx);
    if (ret != TEE_SUCCESS) {
        tloge("re-encrypt keymaterial: encrypt symm key fail");
        goto erase_temp_buf;
    }

    /* build new keymasterial */
    new_material_header->key_buff_len = blob.data_length;
    if (new_material->data_length < four_bytes_align_up(sizeof(*new_material_header) + blob.data_length)) {
        tloge("new material is too short\n");
        return TEE_ERROR_SHORT_BUFFER;
    }
    new_material->data_length = four_bytes_align_up(sizeof(*new_material_header) + blob.data_length);

erase_temp_buf:
    (void)memset_s(crypto_buff, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);
    return ret;
}

TEE_Result re_encrypt_keyblob(const struct kb_crypto_factors *old_factors, const struct kb_crypto_factors *new_factors,
    const keyblob_head *keyblob_old, keyblob_head *keyblob_new, keymaster_blob_t *keyblob_gp)
{
    if (old_factors == NULL || new_factors == NULL || keyblob_old == NULL || keyblob_new == NULL ||
        km_buffer_vaild(keyblob_gp)) {
        tloge("get factor: bad parameters");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* re encrypt hidden */
    TEE_Result ret = re_encrypt_hidden(new_factors, keyblob_old, keyblob_new);
    if (ret != TEE_SUCCESS) {
        tloge("re encrypt hidden data failed");
        return TEE_ERROR_GENERIC;
    }

    /* re encrypt keymaterial */
    uint8_t temp_buff[MAX_KEY_BUFFER_LEN] = { 0 };
    keymaster_blob_t old_material;
    keymaster_blob_t new_material = { temp_buff, MAX_KEY_BUFFER_LEN };
    old_material.data_addr = (uint8_t *)keyblob_old + keyblob_old->keymaterial_offset;
    old_material.data_length = keyblob_old->keymaterial_size;

    if (old_material.data_length < sizeof(struct keymaterial_symmetric_header) ||
        new_material.data_length < old_material.data_length) {
        tloge("convert symm material: material len %u %u", old_material.data_length, new_material.data_length);
        return TEE_ERROR_SHORT_BUFFER;
    }
    if (memcpy_s(new_material.data_addr, new_material.data_length, old_material.data_addr,
        old_material.data_length) != EOK) {
        tloge("convert symm material: copy fail");
        ret = TEE_ERROR_GENERIC;
        goto erase_temp_buf;
    }

    ret = re_encrypt_keymaterial(keyblob_old->version, keyblob_new->version, old_factors, new_factors, &new_material);
    if (ret != TEE_SUCCESS) {
        tloge("re encrypt key material data failed");
        goto erase_temp_buf;
    }

    /* build keyblob */
    ret = build_new_key_blob(keyblob_new, &new_material, keyblob_gp);

erase_temp_buf:
    (void)memset_s(temp_buff, MAX_KEY_BUFFER_LEN, 0x0, MAX_KEY_BUFFER_LEN);

    return ret;
}

#endif
