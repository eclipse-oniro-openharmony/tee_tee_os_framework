/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster command extension handle for productline provision functions
 * Create: 2020-10-04
 */

#include "keymaster_defs.h"
#include "km_types.h"
#include "keyblob.h"
#include "km_attest.h"
#include "wb_aes_decrypt.h"
#include "rpmb_fcntl.h"
#include "km_attest_factory.h"
#include "cmd_params_check.h"
#include "km_rollback_resistance.h"
#include "km_env.h"
#include "km_key_params.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "km_key_enhanced.h"
#endif
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
static TEE_Result param_check_and_metafile_lock(uint32_t param_types, const TEE_Param *params)
{
    if (params == NULL) {
        tloge("null pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = check_policy_set(param_types, params);
    if (ret != TEE_SUCCESS)
        return ret;

    /* check key_blob */
    ret = keyblob_integrity_check((keyblob_head *)params[0].memref.buffer, (uint32_t)params[0].memref.size);
    if (ret != 0) {
        tloge("keyblob_integrity_check failed, ret 0x%x\n", ret);
        return ret;
    }

    int32_t ret_lock = pthread_mutex_lock(get_opera_metafile_lock());
    if ((ret_lock) != TEE_SUCCESS) {
        tloge("pthread_mutex_lock failed. ret=0x%x\n", ret_lock);
        return ret_lock;
    }
    return ret;
}

/* add for key policy set (BYOD) */
TEE_Result km_key_policy_set(uint32_t param_types, const TEE_Param *params)
{
    int32_t ret_unlock;
    char file_name[FILE_NAME_LEN] = { '0' };
    uint32_t file_size = sizeof(meta_file_t);
    TEE_Result ret = param_check_and_metafile_lock(param_types, params);
    if (ret != TEE_SUCCESS) {
        tloge("param check and lock metafile failed\n");
        return ret;
    }
    uint8_t *read_buff = (uint8_t *)TEE_Malloc(file_size, 0);
    if (read_buff == NULL) {
        tloge("read_buffer malloc failed\n");
        ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
        check_if_unlock_failed_only_printf(ret_unlock);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    keyblob_head *key_blob = (keyblob_head *)params[0].memref.buffer;
    /* find metadata in rpmb and write policy to meta data */
    if (kb_metafile_load(key_blob->hmac, HMAC_SIZE, file_name, FILE_NAME_LEN, (meta_file_t *)read_buff) !=
        TEE_SUCCESS) {
        tloge("keyblob->hmac not found\n");
        ret = TEE_ERROR_ITEM_NOT_FOUND;
        goto free_buff;
    }
    /* Now ,the fileName and read_buff have real data. */
    ret = kmds_set_keypolicy(read_buff, key_blob->hmac, (ctl_eima_policy_t *)params[1].memref.buffer);
    if (ret != TEE_SUCCESS) {
        tloge("kmds_set_keypolicy failed ret=0x%x,fileName=%s\n", ret, file_name);
        goto free_buff;;
    }
    /* write the buffer into the file. */
    meta_file_t *file_p = (meta_file_t *)read_buff;
    if (((UINT32_MAX - (sizeof(uint32_t) * DOUBLE_SIZE)) / sizeof(meta_element_t)) < file_p->count_used) {
        tloge("invalid file_p->count_used %u\n", file_p->count_used);
        ret = TEE_ERROR_BAD_PARAMETERS;
        goto free_buff;
    }

    ret = TEE_RPMB_FS_Write(file_name, (uint8_t *)read_buff,
        (sizeof(uint32_t) * DOUBLE_SIZE) + (sizeof(meta_element_t) * file_p->count_used));
    check_rpmb_write(ret);
free_buff:
    TEE_Free(read_buff);
    read_buff = NULL;
    ret_unlock = pthread_mutex_unlock(get_opera_metafile_lock());
    if ((ret_unlock) != TEE_SUCCESS) {
        tloge("pthread_mutex_unlock failed. ret=0x%x\n", ret_unlock);
        return ret_unlock;
    }
    return ret;
}
#endif
static TEE_Result get_dev_key(const uint8_t *kb_buf, uint32_t kb_len, uint8_t **decrypt_buf, struct dev_key_t **dev_key,
    uint32_t *de_len)
{
    /* get iv */
    int32_t ret;
    uint8_t iv_at[CBC_IV_LENGTH] = { 0 };
    ret = (int32_t)get_iv(iv_at, kb_len, kb_buf);
    if (ret)
        return ret;

    /* get tlv */
    const uint8_t *encrypt_buf = kb_buf + CBC_IV_LENGTH;
    uint32_t en_len = kb_len - CBC_IV_LENGTH;

    /* whitebox decrypt */
    *decrypt_buf = (uint8_t *)TEE_Malloc(en_len, 0);
    if (*decrypt_buf == NULL) {
        tloge("TEE_Malloc decrypt_buf failed\n");
        return (TEE_Result)AT_MEM_ERR;
    }
    if (wb_aes_decrypt_cbc(iv_at, encrypt_buf, en_len, *decrypt_buf, de_len)) {
        tloge("error in cbc_decryption\n");
        free_all(NULL, decrypt_buf, en_len);
        return (TEE_Result)AT_WB_DECRYPT_ERR;
    } else {
        tlogd("success in cbc_decryption\n");
    }
    /* decode tlv to into struct dev_key_t */
    *dev_key = (struct dev_key_t *)TEE_Malloc(sizeof(struct dev_key_t), 0);
    if (*dev_key == NULL) {
        tloge("TEE_Malloc dev_key failed\n");
        free_all(dev_key, decrypt_buf, en_len);
        return (TEE_Result)AT_MEM_ERR;
    }
    ret = decode_tlv(*decrypt_buf, *de_len, *dev_key, ATTLVNODE_DEVKEY);
    if (ret != 0) {
        tloge("error in decode_tlv\n");
        free_all(dev_key, decrypt_buf, en_len);
        return (TEE_Result)ret;
    }
    return TEE_SUCCESS;
}

TEE_Result km_store_kb(uint32_t param_types, TEE_Param *params)
{
    TEE_Result result;
    if (params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    /* check params */
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* params check */
    int32_t ret = (int32_t)km_store_verify_params_check(params, CBC_IV_LENGTH);
    if (ret)
        return TEE_ERROR_BAD_PARAMETERS;

    /* get the params buf */
    keymaster_blob_t keybox_buf = { (uint8_t *)params[0].memref.buffer, (uint32_t)params[0].memref.size };
    keymaster_blob_t signed_text_buf = { (uint8_t *)params[PARAM_NBR_TWO].memref.buffer,
        (uint32_t)params[PARAM_NBR_TWO].memref.size };

    struct dev_key_t *dev_key = NULL;
    keymaster_blob_t decrypt_buff = { NULL, 0 };
    result = get_dev_key(keybox_buf.data_addr, keybox_buf.data_length, &(decrypt_buff.data_addr), &dev_key,
        &(decrypt_buff.data_length));
    if (result != TEE_SUCCESS) {
        tloge("get_dev_key failed.\n");
        return result;
    }
    /* check hash.. return AT_HASH_CHECK_ERR */
    keymaster_blob_t txt_to_sign = { params[1].memref.buffer, params[1].memref.size };
    ret = (int32_t)check_and_store_keybox(&decrypt_buff, dev_key, &signed_text_buf, &txt_to_sign, params,
        params[PARAM_NBR_THREE].memref.size, params[PARAM_NBR_THREE].memref.buffer);
    free_all(&dev_key, &(decrypt_buff.data_addr), keybox_buf.data_length - CBC_IV_LENGTH);
    return (TEE_Result)ret;
}

TEE_Result km_verify_kb(uint32_t param_types, TEE_Param *params)
{
    int ret;

    if (params == NULL)
        return TEE_ERROR_BAD_PARAMETERS;
    /* check params */
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT))
        tloge("Bad expected parameter types\n");

    /* params check */
    ret = (int32_t)km_store_verify_params_check(params, 0);
    if (ret != 0)
        return TEE_ERROR_BAD_PARAMETERS;

    /* get the params buf */
    keymaster_blob_t text_to_sign = { params[1].memref.buffer, params[1].memref.size };
    keymaster_blob_t text_signed = { params[PARAM_NBR_TWO].memref.buffer, params[PARAM_NBR_TWO].memref.size };
    keymaster_blob_t chain = { params[PARAM_NBR_THREE].memref.buffer, params[PARAM_NBR_THREE].memref.size };

    /* decode tlv into struct verify_info */
    struct verify_info *v_info = (struct verify_info *)TEE_Malloc(sizeof(struct verify_info), 0);
    if (v_info == NULL) {
        tloge("TEE_Malloc v_info failed\n");
        return AT_MEM_ERR;
    }

    ret = decode_tlv(params[0].memref.buffer, params[0].memref.size, v_info, ATTLVNODE_VB_INFO);
    if (ret != 0) {
        tloge("error in decode_tlv\n");
        goto free_v_info;
    }

    /* compare files */
    ret = (int)compare_files_and_sign_digest(v_info, &(text_signed.data_length), text_to_sign.data_addr,
        text_signed.data_addr, text_to_sign.data_length);
    if (ret != TEE_SUCCESS) {
        tloge("compare files error\n");
        goto free_v_info;
    }
    params[PARAM_NBR_TWO].memref.size = text_signed.data_length;

    /* format out chain */
    uint32_t out_len = chain.data_length;
    if (chain.data_length != CHAIN_MAX_LEN) {
        tloge("invliad output param:out chain buffer, len=%u\n", chain.data_length);
        ret = AT_CHAIN_OUT_ERR;
        goto free_v_info;
    }
    ret = format_provision_chain(chain.data_addr, &out_len, v_info->src, v_info->alg);
    if (ret != 0) {
        tloge("error in format_provision_chain\n");
        goto free_v_info;
    }
    params[PARAM_NBR_THREE].memref.size = out_len;

free_v_info:
    TEE_Free(v_info);
    return ret;
}

TEE_Result km_verify_attestationids_with_param(uint32_t param_types, const TEE_Param *params)
{
    TEE_Result ret;
    /* in consideration of simplifying process, we are still use CA params order for TA2TA */
    if (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if ((params[1].memref.buffer == NULL) || (sizeof(uint32_t) > params[1].memref.size)) {
        tloge("null:params[1].memref.buffer is NULL or params[1].memref.size is %zu\n", params[1].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    const keymaster_key_param_set_t *attest_params = (keymaster_key_param_set_t *)params[1].memref.buffer;
    uint32_t attest_params_len = params[1].memref.size;

    if ((attest_params == NULL) || (attest_params_len == 0) || key_param_set_check(attest_params, attest_params_len)) {
        tloge("need poper params_enforced\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    ret = unsupport_enhanced_key((const keymaster_key_param_set_t *)attest_params);
    if (ret != TEE_SUCCESS) {
        tloge("check unsupported tags failed\n");
        return ret;
    }
#endif

    ret = verify_identifiers_with_param(attest_params);
    if (ret != TEE_SUCCESS) {
        tloge("verify_identifiers_with_param failed, ret 0x%x\n", ret);
        return KM_ERROR_CANNOT_ATTEST_IDS;
    }
    return ret;
}
