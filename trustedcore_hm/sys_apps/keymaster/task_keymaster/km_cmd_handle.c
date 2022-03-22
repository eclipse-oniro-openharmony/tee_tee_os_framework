/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster command handle functions
 * Create: 2020-10-04
 */

#include "keymaster_defs.h"
#include "km_attest_factory.h"
#include "keyblob.h"
#include "km_key_check.h"
#include "km_rollback_resistance.h"
#include "cmd_handle.h"
#include "crypto_wrapper.h"
#include "km_tag_operation.h"
#include "km_auth.h"
#include "km_attest.h"
#include "km_attest_check.h"
#include "km_crypto_check.h"
#include "km_env.h"
#include "km_crypto.h"
#include "km_key_params.h"

TEE_Result km_generate_key(uint32_t param_types, TEE_Param *params)
{
    /*
     * input:
     *  params[PARAM_ZERO]:keymaster_key_param_set_t[] for generate key
     *  |--hw_enforced length--|--hw_enforced params[]--
     *  |--sw_enforced length--|--sw_enforced params[]--
     *  |--extend buffer(only sw_enforced, and params[].blob.data means
     *  the offset of extend buffer)--|
     *  params[PARAM_ONE]:revserved
     *  output:
     *      params[PARAM_TWO]:key_blob
     *      params[PARAM_THREE]:keymaster_key_param_set_t hw_enforced sw_enforced
     */
    tlogd("km generate key entry\n");
    keymaster_algorithm_t algorithm;
    uint32_t key_size_bits = 0;
    keymaster_key_param_set_t *params_hw_enforced = NULL;
    TEE_Result tee_ret;

    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;

    tee_ret = km_generate_param_check(param_types, params, &params_hw_enforced);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;
    tee_ret = get_alg_keysize_from_paramsets(&algorithm, &key_size_bits, params_hw_enforced);
    if (tee_ret != TEE_SUCCESS) {
        tloge("get alg, keysize failed\n");
        return tee_ret;
    }
    tlogd("algorithm is 0x%x\n", algorithm);
    tee_ret = check_gen_key_params(algorithm, key_size_bits, params_hw_enforced);
    if (tee_ret != TEE_SUCCESS) {
        tloge("check tags failed\n");
        return tee_ret;
    }

    tee_ret = generate_key(algorithm, key_size_bits, params_hw_enforced, params);
    if (tee_ret != TEE_SUCCESS) {
        tloge("generate key failed\n");
        return tee_ret;
    }

    tlogd("km_generate_key success\n");
    return TEE_SUCCESS;
}

static TEE_Result km_begin_check_app_id(struct kb_crypto_factors *factors, const TEE_Param *params,
    uint32_t param_types, keymaster_key_param_set_t **params_enforced, keyblob_head *key_blob)
{
    TEE_Result ret;
    keymaster_blob_t application_id = { NULL, 0 };
    ret = check_begin_param(param_types, params, params_enforced);
    if (ret) {
        tloge("km_begin_param_check failed, ret 0x%x\n", ret);
        return ret;
    }
    get_application_id(&application_id, *params_enforced);
    ret = keyblob_check(key_blob, params[PARAM_ZERO].memref.size, &application_id);
    if (ret != TEE_SUCCESS) {
        tloge("keyblob_check failed, ret 0x%x\n", ret);
        return ret;
    }
    /* decrypt hidden param to verify APPLICATION_ID and APPLICATION_DATA if needed */
    if (get_kb_crypto_factors((keymaster_key_param_set_t *)((uint8_t *)key_blob + key_blob->hw_enforced_offset),
        *params_enforced, key_blob->version, &application_id, factors) != 0) {
        tloge("get keyblob crypto factors failed");
        return TEE_ERROR_GENERIC;
    }
    ret = decrypt_keyblob_hidden(key_blob, factors);
    if (ret != TEE_SUCCESS) {
        tloge("decrypt keyblob hidden failed:0x%x\n", ret);
        return ret;
    }
    /* verify APPLICATION_ID and APPLICATION_DATA , error return KM_ERROR_INVALID_KEY_BLOB; required by google in v1 */
    if (authentication_key(key_blob, *params_enforced)) {
        tloge("verify APPLICATION_ID and APPLICATION_DATA failed\n");
        return KM_ERROR_INVALID_KEY_BLOB;
    }
    return TEE_SUCCESS;
}

static keymaster_algorithm_t g_supported_algorithms[] = { KM_ALGORITHM_RSA, KM_ALGORITHM_EC, KM_ALGORITHM_AES,
    KM_ALGORITHM_TRIPLE_DES, KM_ALGORITHM_HMAC };

static keymaster_purpose_t g_supported_purposes[] = { KM_PURPOSE_ENCRYPT, KM_PURPOSE_DECRYPT, KM_PURPOSE_SIGN,
    KM_PURPOSE_VERIFY, KM_PURPOSE_DERIVE_KEY, KM_PURPOSE_WRAP_KEY, KM_PURPOSE_ROLLBACK_RESISTANT };

static keymaster_error_t is_algorithm_support(keymaster_algorithm_t algorithm)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_supported_algorithms) / sizeof(g_supported_algorithms[0]); i++) {
        if (g_supported_algorithms[i] == algorithm)
            return KM_ERROR_OK;
    }
    tloge("unsupport algorithm %d\n", algorithm);
    return (keymaster_error_t)TEE_ERROR_NOT_SUPPORTED;
}

static keymaster_error_t is_purpose_support(keymaster_purpose_t purpose)
{
    uint32_t i;
    for (i = 0; i < sizeof(g_supported_purposes) / sizeof(g_supported_purposes[0]); i++) {
        if (g_supported_purposes[i] == purpose)
            return KM_ERROR_OK;
    }
    tloge("purpose error, %u\n", purpose);
    return KM_ERROR_UNSUPPORTED_PURPOSE;
}

static TEE_Result init_key_node_public_element(key_auth *key_node, const keymaster_key_param_set_t *hw_enforced,
    keymaster_purpose_t purpose)
{
    bool check_fail = (key_node == NULL || hw_enforced == NULL);
    if (check_fail) {
        tloge("null pointers\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keymaster_algorithm_t algorithm;
    if (get_key_param(KM_TAG_ALGORITHM, &algorithm, hw_enforced)) {
        tloge("get_key_param of keymaster_algorithm_t failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = (is_purpose_support(purpose) != KM_ERROR_OK || is_algorithm_support(algorithm) != KM_ERROR_OK);
    if (check_fail) {
        tloge("purpose or algorithm check failed\n");
        return TEE_ERROR_NOT_SUPPORTED;
    }
    key_node->purpose = purpose;
    key_node->algorithm = algorithm;
    return TEE_SUCCESS;
}

/*
 * input:
 * params[PARAM_ZERO]:key_blob
 * params[PARAM_ONE]:keymaster_key_param_set_t in_params (may be NULL)
 * output
 * params[PARAM_TWO]:keymaster_key_param_set_t out_params if needed
 * params[PARAM_THREE]:operation_handle (in:purpose; out:handle(value.b<<32+value.a))
 */
TEE_Result km_begin(uint32_t param_types, TEE_Param *params)
{
    TEE_Result tee_ret;
    keymaster_key_param_set_t *params_enforced = NULL;
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    tlogd("km_begin engtry\n");
    keyblob_head *key_blob = (keyblob_head *)params[PARAM_ZERO].memref.buffer;
    tee_ret = km_begin_check_app_id(&factors, params, param_types, &params_enforced, key_blob);
    if (tee_ret != TEE_SUCCESS) {
        tloge("km_begin_check_app_id failed.\n");
        return tee_ret;
    }
    key_auth *key_node = generate_keynode(key_blob);
    if (key_node == NULL) {
        tloge("key_node malloc failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    tee_ret = init_key_node_public_element(key_node,
        (keymaster_key_param_set_t *)((uint8_t *)key_blob + key_blob->hw_enforced_offset),
        (keymaster_purpose_t)(params[PARAM_THREE].value.a));
    if (tee_ret != TEE_SUCCESS) {
        tloge("init key node public element failed, 0x%x\n", tee_ret);
        goto error;
    }
    tee_ret = (TEE_Result)process_authorize_begin(key_blob, params_enforced, key_node);
    if (tee_ret != KM_ERROR_OK) {
        tloge("process authorize begin failed, %u\n", tee_ret);
        goto error;
    }
    tee_ret = (TEE_Result)km_algorithm_begin(params_enforced, key_blob, key_node, &factors, params);
    if (tee_ret != KM_ERROR_OK) {
        tloge("km algorithm begin failed, %u\n", tee_ret);
        goto error;
    }
    if (add_auth_node(key_node) != TEE_SUCCESS) {
        tloge("add auth node is failed\n");
        tee_ret = TEE_ERROR_GENERIC;
        goto error;
    }
    params[PARAM_THREE].value.a = get_low_32bits(key_node->operation_handle);
    params[PARAM_THREE].value.b = get_high_32bits(key_node->operation_handle);
    return TEE_SUCCESS;
error:
    free_key_node(key_node);
    TEE_Free(key_node);
    return tee_ret;
}

/*
 * input:
 * params[PARAM_ZERO]:keymaster_key_param_set_t in_params
 * params[PARAM_ONE]:in_data
 * output
 * params[PARAM_TWO]:|--operation_handle--|keymaster_key_param_set_t out_params if needed
 * params[PARAM_THREE]:out_data
 */
TEE_Result km_update(uint32_t param_types, TEE_Param *params)
{
    keymaster_key_param_set_t *params_enforced = NULL;
    keymaster_blob_t in_data = { NULL, 0 };
    uint64_t op_handle;
    tlogd("km update entry\n");
    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    TEE_Result tee_ret = check_update_params(param_types, params, &params_enforced, &in_data);
    if (tee_ret != TEE_SUCCESS) {
        tloge("check_km_update_params failed:0x%x\n", tee_ret);
        return tee_ret;
    }
    if (params[PARAM_TWO].memref.size < sizeof(uint64_t)) {
        tloge("invalid param buffer of operation_handle\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    op_handle = *(uint64_t *)params[PARAM_TWO].memref.buffer;
    params[PARAM_TWO].memref.size = 0;
    keymaster_blob_t out_data = { params[PARAM_THREE].memref.buffer, params[PARAM_THREE].memref.size };
    tee_ret = change_node_usage_count(op_handle, ADD_USAGE_COUNT);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;
    /* Authorize key */
    keymaster_error_t ret = authorize_update_finish(op_handle, params_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("authorize_update_finish failed, ret is %d\n", ret);
        ret = (keymaster_error_t)TEE_ERROR_ACCESS_DENIED;
        goto error;
    }
    /* update operation */
    ret = operation_update(op_handle, params_enforced, &in_data, &out_data);
    if (ret != KM_ERROR_OK) {
        tloge("operation_update failed\n");
        goto error;
    }
    tee_ret = change_node_usage_count(op_handle, SUB_USAGE_COUNT);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;
    params[PARAM_THREE].memref.size = out_data.data_length;
    tlogd("out data size is %u\n", out_data.data_length);
    return TEE_SUCCESS;
error:
    in_data.data_addr = NULL;
    in_data.data_length = 0;
    out_data.data_addr = NULL;
    out_data.data_length = 0;
    operation_finish(op_handle, NULL, &in_data, &out_data, 1);
    (void)free_auth_node(op_handle);
    return (TEE_Result)ret;
}

/*
 * input:
 * params[PARAM_ZERO]:keymaster_key_param_set_t in_params
 * params[PARAM_ONE]:signature
 * output
 * params[PARAM_TWO]:|--operation_handle--|keymaster_key_param_set_t out_params if needed
 * params[PARAM_THREE]:out_data
 */
TEE_Result km_finish(uint32_t param_types, TEE_Param *params)
{
    /* Authorize key */
    keymaster_error_t ret;
    keymaster_key_param_set_t *params_enforced = NULL;
    keymaster_blob_t final_data = { NULL, 0 };
    uint64_t op_handle;
    TEE_Result tee_ret;
    tlogd("km finish entry\n");

    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    tee_ret = check_finish_params(param_types, params, &params_enforced, &final_data);
    if (tee_ret != TEE_SUCCESS) {
        tloge("check_km_finish_params failed\n");
        return tee_ret;
    }
    op_handle = *(uint64_t *)params[PARAM_TWO].memref.buffer;
    params[PARAM_TWO].memref.size = 0;
    keymaster_blob_t out_data = { params[PARAM_THREE].memref.buffer, params[PARAM_THREE].memref.size };
    tee_ret = change_node_usage_count(op_handle, ADD_USAGE_COUNT);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;
    /* Authorize key */
    ret = authorize_update_finish(op_handle, params_enforced);
    if (ret != KM_ERROR_OK) {
        tloge("authorize finish failed, ret is %d\n", ret);
        ret = (keymaster_error_t)TEE_ERROR_ACCESS_DENIED;
        goto error;
    }
    /* finish operation */
    ret = operation_finish(op_handle, params_enforced, &final_data, &out_data, 0);
    if (ret != KM_ERROR_OK) {
        tloge("operation_finish failed\n");
        goto error;
    }
    params[PARAM_THREE].memref.size = out_data.data_length;
    tlogd("out data size=%u\n", out_data.data_length);
    (void)free_auth_node(op_handle);
    return TEE_SUCCESS;
error:
    (void)free_auth_node(op_handle);
    return (TEE_Result)ret;
}

TEE_Result km_abort(uint32_t param_types, const TEE_Param *params)
{
    uint64_t op_handle;
    keymaster_error_t ret;

    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    if (km_abort_params_check(param_types, params) != TEE_SUCCESS) {
        tloge("params check failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    op_handle = *(uint64_t *)params[PARAM_ZERO].memref.buffer;
    keymaster_blob_t input = { NULL, 0 };
    keymaster_blob_t output = { NULL, 0 };
    TEE_Result tee_ret = change_node_usage_count(op_handle, ADD_USAGE_COUNT);
    if (tee_ret != TEE_SUCCESS)
        return tee_ret;
    ret = operation_finish(op_handle, NULL, &input, &output, 1);
    if (ret == KM_ERROR_INVALID_OPERATION_HANDLE) {
        tloge("can't find abort handle\n");
        return (TEE_Result)ret;
    }

    (void)free_auth_node(op_handle);

    return TEE_SUCCESS;
}

static TEE_Result pull_characteristics(const keyblob_head *key_blob, TEE_Param *params)
{
    /* copy enforced param to output, check output param size */
    uint32_t key_characteristics_len =
        key_blob->extend1_buf_offset - key_blob->hw_enforced_offset + key_blob->extend1_size;
    if (key_characteristics_len > params[PARAM_TWO].memref.size) {
        tloge("invalid params buffer size\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (resort_key_characteristics((uint8_t *)params[PARAM_TWO].memref.buffer,
        (uint8_t *)key_blob + key_blob->hw_enforced_offset, key_characteristics_len) != 0) {
        tloge("resort key characteristics failed\n");
        return TEE_ERROR_GENERIC;
    }
    params[PARAM_TWO].memref.size = key_characteristics_len;
    return TEE_SUCCESS;
}

static TEE_Result do_get_key_characteristics(TEE_Param *params, keymaster_blob_t *app_id,
                                             const keymaster_key_param_set_t *params_enforced)
{
    keyblob_head *key_blob  = (keyblob_head *)params[PARAM_ZERO].memref.buffer;
    /* decrypt hidden param to verify APPLICATION_ID and APPLICATION_DATA */
    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors((keymaster_key_param_set_t *)((uint8_t *)key_blob + key_blob->hw_enforced_offset),
        params_enforced, key_blob->version, app_id, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        return TEE_ERROR_GENERIC;
    }
    TEE_Result tee_ret = decrypt_keyblob_hidden(key_blob, &factors);
    if (tee_ret != TEE_SUCCESS) {
        tloge("decrypt keyblob hidden failed\n");
        return tee_ret;
    }
    /* verify APPLICATION_ID and APPLICATION_DATA ,error return KM_ERROR_INVALID_KEY_BLOB;
     * required by google in v1 */
    if (authentication_key(key_blob, params_enforced) != 0) {
        tloge("verify APPLICATION_ID and APPLICATION_DATA failed\n");
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }

    return pull_characteristics(key_blob, params);
}

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
static TEE_Result get_enhanced_key_characteristics(TEE_Param *params, keymaster_blob_t *application_id)
{
    keyblob_head *key_blob = (keyblob_head *)params[PARAM_ZERO].memref.buffer;
    uint32_t keyblob_size = params[PARAM_ZERO].memref.size;
    TEE_Result ret = verify_keyblob(key_blob, keyblob_size, application_id);
    if (ret != TEE_SUCCESS) {
        tloge("verify keyblob failed:0x%x\n", ret);
        return ret;
    }
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    ret = check_keyblob_rollback(key_blob);
    if (ret != TEE_SUCCESS) {
        tloge("check_keyblob_rollback() failed\n");
        return ret;
    }
#endif
    return pull_characteristics(key_blob, params);
}
#endif

/*
 * input:
 * params[PARAM_ZERO]:key_blob
 * params[PARAM_ONE]:keymaster_key_param_set_t in_params
 * output
 * params[PARAM_TWO]:keymaster_key_param_set_t out_params
 */
TEE_Result km_get_key_characteristics(uint32_t param_types, TEE_Param *params)
{
    keymaster_key_param_set_t *params_enforced = NULL;
    TEE_Result tee_ret;
    keymaster_blob_t app_id = { NULL, 0 };
    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    tee_ret = km_get_key_params_check(param_types, params, &params_enforced);
    if (tee_ret != TEE_SUCCESS) {
        tloge("km_get_key_params_check failed: 0x%x\n", tee_ret);
        return tee_ret;
    }
    get_application_id(&app_id, params_enforced);
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    keyblob_head *key_blob = (keyblob_head *)params[PARAM_ZERO].memref.buffer;
    if (key_blob->version == VERSION_340 || key_blob->version == VERSION_540 ||
        key_blob->version == VERSION_341 || key_blob->version == VERSION_541) {
        tlogd("version 340/540/341/541 keyblob could not be verified");
        return get_enhanced_key_characteristics(params, &app_id);
    }
#endif
    /* check key_blob, which is params[0] */
    tee_ret = keyblob_check((keyblob_head *)params[PARAM_ZERO].memref.buffer, params[PARAM_ZERO].memref.size, &app_id);
    if (tee_ret != TEE_SUCCESS) {
        tloge("keyblob is invalid\n");
        return tee_ret;
    }
    return do_get_key_characteristics(params, &app_id, params_enforced);
}

TEE_Result km_import_key(uint32_t param_types, TEE_Param *params)
{
    /*
     * input:
     * params[PARAM_ZERO]:keymaster_key_param_set_t[] for generate key
     * |--hw_enforced length--|--hw_enforced params[]--
     * |--sw_enforced length--|--sw_enforced params[]--
     * |--extend buffer(only sw_enforced, and params[].blob.data means
     * the offset of extend buffer)--|
     * params[PARAM_ONE]:import keypair info(RSA or aes/hmac)
     * output:
     * params[PARAM_TWO]:key_blob
     * params[PARAM_THREE]:keymaster_key_param_set_t hw_enforced sw_enforced
     */
    keymaster_algorithm_t algorithm;
    TEE_Result ret = km_import_param_check(param_types, params);
    if (ret != TEE_SUCCESS) {
        tloge("km import key param check failed, ret 0x%x\n", ret);
        return ret;
    }
    keymaster_key_param_set_t *params_hw_enforced = (keymaster_key_param_set_t *)params[PARAM_ZERO].memref.buffer;
    if (key_param_set_check(params_hw_enforced, params[PARAM_ZERO].memref.size) != 0) {
        tloge("km import key need proper params_hw_enforced\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (get_key_param(KM_TAG_ALGORITHM, &algorithm, params_hw_enforced) != 0) {
        tloge("get algorithm failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* get application_id & version */
    uint32_t version;
    ret = get_cur_version(params_hw_enforced, algorithm, &version);
    if (ret != TEE_SUCCESS) {
        tloge("get version failed");
        return ret;
    }

    bool sym_algorithm = (algorithm == KM_ALGORITHM_AES || algorithm == KM_ALGORITHM_TRIPLE_DES ||
        algorithm == KM_ALGORITHM_HMAC);
    if (algorithm == KM_ALGORITHM_RSA) {
        ret = (import_rsa_key(params, params_hw_enforced, version) != TEE_SUCCESS) ?
            ((TEE_Result)KM_ERROR_IMPORT_PARAMETER_MISMATCH) : TEE_SUCCESS;
    } else if (algorithm == KM_ALGORITHM_EC) {
        ret = (import_ec_key(params, params_hw_enforced, version) != TEE_SUCCESS) ?
            ((TEE_Result)KM_ERROR_IMPORT_PARAMETER_MISMATCH) : TEE_SUCCESS;
    } else if (sym_algorithm) {
        ret = import_symmetric_key(params, algorithm, params_hw_enforced, version);
    } else {
        tloge("unsupported algorithm %d\n", algorithm);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    tlogd("km import key end, ret = %d\n", ret);
    return ret;
}

/*
 * input:
 * params[0]:key_blob
 * params[1]:keymaster_key_param_set_t in_params
 * output
 * params[2]:n and e
 */
TEE_Result km_export_key(uint32_t param_types, TEE_Param *params)
{
    keymaster_key_param_set_t *params_enforced = NULL;

    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    TEE_Result tee_ret = km_export_param_check(param_types, params, &params_enforced);
    if (tee_ret != TEE_SUCCESS) {
        tloge("km_export_param_check is failed\n");
        return tee_ret;
    }
    keyblob_head *key_blob = (keyblob_head *)params[PARAM_ZERO].memref.buffer;
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    if (key_blob->version == VERSION_340 || key_blob->version == VERSION_540 ||
        key_blob->version == VERSION_341 || key_blob->version == VERSION_541) {
        tloge("this keyblob version %u is not supported", key_blob->version);
        return TEE_ERROR_NOT_SUPPORTED;
    }
#endif
    struct kb_crypto_factors factors = { { NULL, 0 }, { NULL, 0 } };
    get_application_id(&(factors.app_id), params_enforced);
    /* check key_blob */
    tee_ret = keyblob_check(key_blob, params[PARAM_ZERO].memref.size, &(factors.app_id));
    if (tee_ret != TEE_SUCCESS) {
        tloge("keyblob is invalid\n");
        return tee_ret;
    }
    /* decrypt hidden param to verify APPLICATION_ID and APPLICATION_DATA */
    tee_ret = decrypt_keyblob_hidden(key_blob, &factors);
    if (tee_ret != TEE_SUCCESS) {
        tloge("decrypt keyblob hidden failed:0x%x\n", tee_ret);
        return tee_ret;
    }

    /* verify APPLICATION_ID and APPLICATION_DATA ,error return KM_ERROR_INVALID_KEY_BLOB required by google in v1 */
    if (authentication_key(key_blob, params_enforced) != 0) {
        tloge("verify APPLICATION_ID and APPLICATION_DATA failed\n");
        return (TEE_Result)KM_ERROR_INVALID_KEY_BLOB;
    }

    /* get algorithm */
    keymaster_key_param_set_t *hw_enforced = (keymaster_key_param_set_t *)((uint8_t *)params[PARAM_ZERO].memref.buffer +
        key_blob->hw_enforced_offset);
    keymaster_algorithm_t algorithm;
    if (get_key_param(KM_TAG_ALGORITHM, &algorithm, hw_enforced) != 0) {
        tloge("get_key_param of keymaster_algorithm_t failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* format pub key out */
    tee_ret = process_public_key_out(algorithm, params, hw_enforced, &factors);
    if (tee_ret != TEE_SUCCESS) {
        tloge("process_public_key_out failed\n");
        return tee_ret;
    }
    return TEE_SUCCESS;
}

/*
 * params[PARAM_ZERO]:key_blob [in]
 * params[PARAM_ONE]:----
 */
TEE_Result km_delete_key(uint32_t param_types, const TEE_Param *params)
{
    if (params == NULL) {
        tloge("Input parameter is a NULL pointer\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    keyblob_head *key_blob = NULL;
    TEE_Result ret;
    tlogd("km delete key begin\n");

    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    /* VTS test only accept KM_ERROR_OK, or KM_ERROR_UNIMPLEMENTED. */
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
        tloge("invalid param types\n");
        return (TEE_Result)KM_ERROR_UNIMPLEMENTED;
    }

    /* params check VTS test only accept KM_ERROR_OK, or KM_ERROR_UNIMPLEMENTED. */
    bool check_fail = (((params[PARAM_ZERO].memref.buffer == NULL) ||
        (sizeof(keyblob_head) > params[PARAM_ZERO].memref.size) ||
        (params[PARAM_ZERO].memref.size > KEY_BLOB_MAX_SIZE)));
    if (check_fail) {
        tloge("params[0] buffer is null or invalid size is %zu\n", params[PARAM_ZERO].memref.size);
        return (TEE_Result)KM_ERROR_UNIMPLEMENTED;
    }
    key_blob = (keyblob_head *)params[PARAM_ZERO].memref.buffer;
    ret = verify_keyblob_before_delete(key_blob, (uint32_t)params[PARAM_ZERO].memref.size,
        (uint8_t *)params[PARAM_ZERO].memref.buffer);
    if (ret != TEE_SUCCESS) {
        tloge("verify key_blob before delete failed\n");
        return ret;
    }
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
    /* get KM_TAG_PURPOSE */
    /* If KM_PURPOSE_ROLLBACK_RESISTANT supports, then check whether KM_TAG_ROLLBACK_RESISTANT is true. */
    bool kb_rollback_resistant = true;
    keymaster_key_param_set_t *hw_params = (keymaster_key_param_set_t *)((uint8_t *)key_blob +
        key_blob->hw_enforced_offset);
    int32_t iret = is_key_param_suport(KM_TAG_ROLLBACK_RESISTANT, (void *)&kb_rollback_resistant, hw_params);
    if (iret != 0) {
        ret = (TEE_Result)kb_metafile_delete(key_blob->hmac, HMAC_SIZE);
        if (ret != TEE_SUCCESS) {
            tloge("Delete key rollback-resistance metadata failed, ret=0x%x\n", ret);
            return ret;
        }
        tlogd("Delete key rollback-reistance metadata successfully.\n");
    }
#endif
    tlogd("km_delete_key succeed\n");
    return (TEE_Result)KM_ERROR_OK;
}

TEE_Result km_delete_all_keys(void)
{
    return TEE_SUCCESS;
}

TEE_Result km_attest_key(uint32_t param_types, TEE_Param *params)
{
    TEE_Result ret = km_attest_key_check(param_types, params);
    if (ret != TEE_SUCCESS)
        return ret;
    /* check id */
    keymaster_blob_t app_id = { NULL, 0 };
    get_application_id(&app_id, (keymaster_key_param_set_t *)params[1].memref.buffer);
    /* check key blob */
    ret = keyblob_check((keyblob_head *)params[PARAM_ZERO].memref.buffer, params[PARAM_ZERO].memref.size, &app_id);
    if (ret != TEE_SUCCESS) {
        tloge("keyblob is invalid\n");
        return ret;
    }
    return do_attest_key(params, &app_id);
}

static TEE_Result do_upgrade_check(const TEE_Param *params, keymaster_blob_t *app_id, uint32_t keyblob_out_size)
{
    if (app_id == NULL) {
        tloge("upgrade cannot get right applicatin id\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* make a copy of keyblob_in before decrypt keyblob_in; makey sure keyblob_out is large enough. */
    if (params[PARAM_NBR_TWO].memref.size < keyblob_out_size) {
        tloge("output buffer is too small %zu\n", params[PARAM_NBR_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

static TEE_Result do_upgrade(TEE_Param *params, keymaster_blob_t *app_id)
{
    /* all used info checked in km_upgrade with check functions */
    uint32_t keyblob_in_size  = params[0].memref.size;
    uint32_t keyblob_out_size = keyblob_in_size + (sizeof(keymaster_key_param_t) * PARAM_SIZE_TWO);
    keyblob_head *keyblob_in  = (keyblob_head *)params[0].memref.buffer;
    keyblob_head *keyblob_out = NULL;
    TEE_Result tee_ret;

    tee_ret = do_upgrade_check(params, app_id, keyblob_out_size);
    if (tee_ret != TEE_SUCCESS) {
        tloge("do upgrade check failed\n");
        return tee_ret;
    }

    keyblob_out = TEE_Malloc(keyblob_out_size, TEE_MALLOC_FILL_ZERO);
    if (keyblob_out == NULL) {
        tloge("alloc keyblob_out failed, size=%u\n", keyblob_out_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint8_t inse_factor[MAX_INSE_FACTOR_LEN] = { 0 };
    struct kb_crypto_factors factors = { { NULL, 0 }, { inse_factor, sizeof(inse_factor) } };
    if (get_kb_crypto_factors((keymaster_key_param_set_t *)((uint8_t *)keyblob_in + keyblob_in->hw_enforced_offset),
        (keymaster_key_param_set_t *)params[1].memref.buffer, keyblob_in->version, app_id, &factors) != 0) {
        tloge("get keyblob crypto factors failed");
        tee_ret = TEE_ERROR_GENERIC;
        goto free_keyblob_out;
    }

    tee_ret = km_copy_keyblob(keyblob_in, keyblob_in_size, &factors, keyblob_out, keyblob_out_size);
    if (tee_ret != TEE_SUCCESS) {
        tloge("copy and encrypto key blob fail\n");
        goto free_keyblob_out;
    }
    if (authentication_key(keyblob_in, (keymaster_key_param_set_t *)params[1].memref.buffer) != 0) {
        tloge("verify APPLICATION_ID and APPLICATION_DATA failed\n");
        tee_ret = KM_ERROR_INVALID_KEY_BLOB;
        goto free_keyblob_out;
    }
    /* check KM_TAG_OS_VERSION and KM_TAG_OS_PATCHLEVEL */
    tee_ret = km_upgrade_version_patch_level(params, keyblob_in, keyblob_in_size, keyblob_out, &keyblob_out_size);
    if (tee_ret != (TEE_Result)KM_ERROR_KEY_REQUIRES_UPGRADE)
        goto free_keyblob_out;

    tee_ret = km_upgrade_end(params, keyblob_in, keyblob_out, app_id);
    if (tee_ret != TEE_SUCCESS)
        tloge("km upgrade fail");

free_keyblob_out:
    TEE_Free(keyblob_out);
    keyblob_out = NULL;
    return tee_ret;
}

/*
* input:
* params[0]:keyblob - key_to_upgrade
* params[1]:km_params
* output:
* params[2]:keyblob - key_upgraded
*/
TEE_Result km_upgrade(uint32_t param_types, TEE_Param *params)
{
    tlogd("km_upgrade entry\n");
    keyblob_head *keyblob_in = (keyblob_head *)params[0].memref.buffer;
    uint32_t keyblob_in_size = params[0].memref.size;
    /* check all in params */
    TEE_Result tee_ret = km_upgrade_check(param_types, params);
    if (tee_ret != TEE_SUCCESS) {
        tloge("km_upgrade in params invalid\n");
        return tee_ret;
    }
    /* check keyblob */
    keymaster_blob_t app_id = { NULL, 0 };
    int ret = get_key_param(KM_TAG_APPLICATION_ID, &app_id, (keymaster_key_param_set_t *)params[1].memref.buffer);
    if (ret != 0) {
        tlogd("get_key_param of application_id failed\n");
        app_id.data_addr = NULL;
    }
    tee_ret = upgrading_keyblob_check(keyblob_in, keyblob_in_size, &app_id);
    if (tee_ret != TEE_SUCCESS) {
        tloge("km upgrade in keyblob is invalid\n");
        return tee_ret;
    }
    return do_upgrade(params, &app_id);
}

TEE_Result km_id_identifiers(uint32_t param_types, const TEE_Param *params, uint32_t cmd)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    /* check params */
    bool check_fail = ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_NUM_TWO) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_NUM_THREE)) != TEE_PARAM_TYPE_NONE);
    if (check_fail) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = ((params[0].memref.buffer == NULL) ||
        (params[0].memref.size != (ID_IDENTIFIERS_MAX * sizeof(struct identifiers_str))));
    if (check_fail) {
        tloge("invalid params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint8_t *buf = params[0].memref.buffer;

    identifiers_stored *identifiers = (identifiers_stored *)TEE_Malloc(sizeof(identifiers_stored), 0);
    if (identifiers == NULL) {
        tloge("identifiers malloc failed\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        return ret;
    }

    /* generate identifiers from buffer to struct */
    if (generate_identifiers(buf, identifiers)) {
        tloge("parser_identifiers faild\n");
        ret = TEE_ERROR_GENERIC;
        goto exit;
    }

    /* store or verify identifiers */
    if (cmd == KM_CMD_ID_STORE_IDENTIFIERS) {
        ret = store_identifiers(identifiers);
    } else if (cmd == KM_CMD_ID_VERIFY_IDENTIFIERS) {
        ret = verify_identifiers(identifiers);
    } else {
        tloge("invalid cmd 0x%x\n", cmd);
        ret = TEE_ERROR_BAD_PARAMETERS;
    }
exit:
    TEE_Free(identifiers);
    return ret;
}

TEE_Result km_destroy_identifiers(uint32_t param_types, TEE_Param *params)
{
    TEE_Result ret;
    (void)params;
    if (!check_param_type(param_types, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    ret = destroy_identifiers();
    return ret;
}

TEE_Result km_configure(uint32_t param_types, const TEE_Param *params)
{
    if (params == NULL) {
        tloge("the input parameter params is null!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (get_cfg_state() == STATE_CFGED)
        return (TEE_Result)KM_ERROR_OK;
    if (!check_param_type(param_types, TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)) {
        tloge("invalid param types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tloge("Info:sys_os_version is %u\n", params[0].value.a);
    tloge("Info:sys_patch_level is %u\n", params[0].value.b);
    set_sys_os_version(params[0].value.a);
    set_sys_patch_level(params[0].value.b);
    /* vendor patch level is not ready, set 0 */
    set_vendor_patch_level(0);

    set_cfg_state(STATE_CFGED);

    return (TEE_Result)KM_ERROR_OK;
}
