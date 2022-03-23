/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: keymaster command params check
 * Create: 2020-10-04
 */

#include "keymaster_defs.h"
#include "keyblob.h"
#include "km_key_check.h"
#include "km_tag_operation.h"
#include "km_rollback_resistance.h"
#include "km_key_params.h"
#include "km_env.h"
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
#include "km_key_enhanced.h"
#endif
TEE_Result km_generate_param_check(uint32_t param_types, const TEE_Param *params,
                                   keymaster_key_param_set_t **params_hw_enforced)
{
    bool condition_check = ((!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE) &&
        !check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
            TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT)) || params == NULL);
    if (condition_check) {
        tloge("invalid param types or params buffer points null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* params check */
    condition_check = (params[PARAM_ZERO].memref.buffer == NULL) || params_hw_enforced == NULL ||
        (params[PARAM_ZERO].memref.size < sizeof(uint32_t));
    if (condition_check) {
        tloge("input has null point\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    condition_check = (params[PARAM_TWO].memref.buffer == NULL || params[PARAM_TWO].memref.size != KEY_BLOB_MAX_SIZE);
    if (condition_check) {
        tloge("params[2] buffer is null or invalid size %zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    condition_check = ((TEE_PARAM_TYPE_GET(param_types, PARAM_THREE) == TEE_PARAM_TYPE_MEMREF_OUTPUT) &&
         (params[PARAM_THREE].memref.buffer == NULL || params[PARAM_THREE].memref.size != KEY_BLOB_MAX_SIZE));
    if (condition_check) {
        tloge("params[3] buffer is null or invalid size %zu\n", params[PARAM_THREE].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    *params_hw_enforced = (keymaster_key_param_set_t *)params[PARAM_ZERO].memref.buffer;
    if (key_param_set_check(*params_hw_enforced, params[PARAM_ZERO].memref.size)) {
        tloge("km_generate_key need poper params_hw_enforced\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    TEE_Result ret = unsupport_enhanced_key((const keymaster_key_param_set_t *)*params_hw_enforced);
    if (ret != TEE_SUCCESS) {
        tloge("check unsupported tags failed\n");
        return ret;
    }
#endif

    return TEE_SUCCESS;
}

int32_t key_param_set_len_check(const keymaster_key_param_set_t *param_keymaster, uint32_t param_size)
{
    if (param_keymaster == NULL) {
        tloge("the param_keymaster is null\n");
        return -1;
    }
    /* check hw_enforced key param set buf size */
    if (param_size < ((sizeof(uint32_t) * KM_FACTOR_2))) {
        tloge("param size is invalid!\n");
        return -1;
    }

    uint32_t hw_enforced_len = *(uint32_t *)param_keymaster;
    if (((param_size - sizeof(uint32_t)) / sizeof(keymaster_key_param_t)) < hw_enforced_len) {
        tloge("hw_enforced_len is invalid!\n");
        return -1;
    }
    uint32_t hw_enforced_buf_size = hw_enforced_len * sizeof(keymaster_key_param_t) + sizeof(uint32_t);
    if ((param_size - hw_enforced_buf_size) < (uint32_t)sizeof(uint32_t)) {
        tloge("hw_enforced_buf_size invalid, hw_enforce_buf_size:%u, param_size:%u!!!\n",
            hw_enforced_buf_size, param_size);
        return -1;
    }
    /* check sw_enforced key param set buf size */
    uint32_t sw_enforced_len = *(uint32_t *)((uint8_t *)param_keymaster + hw_enforced_buf_size);
    if (((param_size - hw_enforced_buf_size - sizeof(uint32_t)) / sizeof(keymaster_key_param_t)) < sw_enforced_len) {
        tloge("key_param_set_check sw_enforced_buf size is invalid!!!\n");
        return -1;
    }
    uint32_t sw_enforced_buf_size = sw_enforced_len * sizeof(keymaster_key_param_t) + sizeof(uint32_t);
    if ((param_size - hw_enforced_buf_size) < sw_enforced_buf_size) {
        tloge("key_param_set_check sw_enforced size invalid hw_enforced_buf_size:%u, \
            param_size:%u, sw_enforced_buf_size %u\n", hw_enforced_buf_size, param_size, sw_enforced_buf_size);
        return -1;
    }
    return 0;
}

/*
 * input:
 * param_keymaster:keymaster_key_param_set_t[] for generate key
 *           |--hw_enforced length--|--hw_enforced params[]--
 *           |--sw_enforced length--|--sw_enforced params[]--
 *           |--extend buffer(only sw_enforced, and params[].blob.data means
 *           the offset of extend buffer)--|
 */
int32_t key_param_set_check(const keymaster_key_param_set_t *param_keymaster, uint32_t param_size)
{
    if (key_param_set_len_check(param_keymaster, param_size) != 0) {
        tloge("key_param_set_len check is invalid!!!\n");
        return -1;
    }
    uint32_t hw_enforced_buf_size = param_keymaster->length * sizeof(keymaster_key_param_t) + sizeof(uint32_t);
    keymaster_key_param_set_t *sw_enforced = (keymaster_key_param_set_t *)((uint8_t *)param_keymaster +
        hw_enforced_buf_size);

    uint32_t hw_sw_size = hw_enforced_buf_size + sw_enforced->length * sizeof(keymaster_key_param_t) + sizeof(uint32_t);

    /* check hw_enforced extend buf range and sum size */
    uint32_t hw_extend_buf_size = 0;
    if (param_keymaster->length != 0) { /* it's hw_enforced->length */
        if (check_enforce_info(param_keymaster->length, hw_sw_size, param_size,
            (keymaster_key_param_t *)((uint8_t *)param_keymaster + sizeof(uint32_t)), &hw_extend_buf_size) != 0) {
            tloge("check_enforce_info failed\n");
            return -1;
        }
    }
    if ((param_size - hw_sw_size) < hw_extend_buf_size) {
        tloge("Error: key_param_set_check hw extend buffer size is large than param_size!!!\n");
        return -1;
    }

    /* check sw_enforced extend buf range and sum size */
    uint32_t sw_extend_buf_size = 0;
    if (sw_enforced->length != 0) {
        if (check_enforce_info(sw_enforced->length, hw_sw_size, param_size,
            (keymaster_key_param_t *)((uint8_t *)sw_enforced + sizeof(uint32_t)), &sw_extend_buf_size) != 0) {
            tloge("check_enforce_info failed\n");
            return -1;
        }
    }
    if ((param_size - hw_sw_size - hw_extend_buf_size) < sw_extend_buf_size) {
        tloge("Error: key_param_set_check sw extend buffer size is large than param_size!!!\n");
        return -1;
    }

    return 0;
}

TEE_Result km_get_key_params_check(uint32_t param_types, const TEE_Param *params,
                                   keymaster_key_param_set_t **params_enforced)
{
    if (params == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check_fail = (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE) &&
        !check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                          TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE));
    if (check_fail) {
        tloge("invalid param types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = ((params[PARAM_ZERO].memref.buffer == NULL) ||
        (params[PARAM_ZERO].memref.size < sizeof(keyblob_head)) ||
        (params[PARAM_ZERO].memref.size > KEY_BLOB_MAX_SIZE));
    if (check_fail) {
        tloge("params[0] buffer is null or invalid size is %zu\n", params[PARAM_ZERO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        check_fail = ((params[PARAM_ONE].memref.buffer == NULL) || params_enforced == NULL ||
            (params[PARAM_ONE].memref.size < sizeof(uint32_t)));
        if (check_fail) {
            tloge("input is null in get key params check\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }

        *params_enforced = (keymaster_key_param_set_t *)params[PARAM_ONE].memref.buffer;
        if (key_param_set_check(*params_enforced, params[PARAM_ONE].memref.size) != 0) {
            tloge("km_get_key_characteristics need poper params_enforced\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        TEE_Result ret = unsupport_enhanced_key((const keymaster_key_param_set_t *)*params_enforced);
        if (ret != TEE_SUCCESS) {
            tloge("check unsupported tags failed\n");
            return ret;
        }
#endif
    }
    check_fail = ((params[PARAM_TWO].memref.buffer == NULL) || (params[PARAM_TWO].memref.size != KEY_BLOB_MAX_SIZE));
    if (check_fail) {
        tloge("null:params[2].memref.buffer is null or params[2].memref.size is %zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result km_import_param_check(uint32_t param_types, const TEE_Param *params)
{
    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                          TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_INOUT)) {
        tloge("invalid param types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* params check */
    bool check_fail = ((params[PARAM_ZERO].memref.buffer == NULL) ||
         (params[PARAM_ZERO].memref.size < sizeof(uint32_t)));
    if (check_fail) {
        tloge("params[0] buffer is null or invalid size %zu\n", params[PARAM_ZERO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = ((params[PARAM_ONE].memref.buffer == NULL) || (params[PARAM_ONE].memref.size == 0));
    if (check_fail) {
        tloge("params[1] buffer is null or invalid size %zu\n", params[PARAM_ONE].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = ((params[PARAM_TWO].memref.buffer == NULL) || (params[PARAM_TWO].memref.size != KEY_BLOB_MAX_SIZE));
    if (check_fail) {
        tloge("params[2] buffer is null or invalid size %zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = (params[PARAM_THREE].memref.buffer == NULL || params[PARAM_THREE].memref.size != KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("params[3] buffer is null or invalid size is %zu\n", params[PARAM_THREE].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result km_export_param_check(uint32_t param_types, const TEE_Param *params,
                                 keymaster_key_param_set_t **params_enforced)
{
    bool check_fail = ((TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        ((TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) != TEE_PARAM_TYPE_MEMREF_INPUT) &&
        (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) != TEE_PARAM_TYPE_NONE)) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_TWO) != TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_THREE) != TEE_PARAM_TYPE_NONE));
    if (check_fail) {
        tloge("invalid param types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = (params[PARAM_ZERO].memref.buffer == NULL || params[PARAM_ZERO].memref.size < sizeof(keyblob_head) ||
        params[PARAM_ZERO].memref.size > KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("params[0] buffer is null or invalid size %zu\n", params[PARAM_ZERO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        check_fail = (params[PARAM_ONE].memref.buffer == NULL || params_enforced == NULL ||
            params[PARAM_ONE].memref.size < sizeof(uint32_t));
        if (check_fail) {
            tloge("export param check input is null");
            return TEE_ERROR_BAD_PARAMETERS;
        }
        *params_enforced = (keymaster_key_param_set_t *)params[PARAM_ONE].memref.buffer;
        if (key_param_set_check(*params_enforced, params[PARAM_ONE].memref.size) != 0) {
            tloge("km_export_key need poper params_enforced.\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
        TEE_Result ret = unsupport_enhanced_key((const keymaster_key_param_set_t *)*params_enforced);
        if (ret != TEE_SUCCESS) {
            tloge("check unsupported tags failed\n");
            return ret;
        }
#endif
    }
    check_fail = (params[PARAM_TWO].memref.buffer == NULL || params[PARAM_TWO].memref.size != KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("params[2] buffer is null or invalid size %zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}


TEE_Result check_begin_param(uint32_t param_types, const TEE_Param *params, keymaster_key_param_set_t **params_enforced)
{
    bool check_fail = (params == NULL || params_enforced == NULL);
    if (check_fail) {
        tloge("the input parameter params or params_enforced is NULL.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!is_cfg_state_ready())
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    bool ret1 = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                                 TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_INOUT);
    bool ret2 = check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                                 TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_VALUE_INOUT);
    if (!ret1 && !ret2) {
        tloge("invalid param types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = (params[PARAM_ZERO].memref.buffer == NULL || params[PARAM_ZERO].memref.size < sizeof(keyblob_head) ||
        params[PARAM_ZERO].memref.size > KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("params[0] buffer is null or invalid size %zu\n", params[PARAM_ONE].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        check_fail = (params[PARAM_ONE].memref.buffer == NULL || params[PARAM_ONE].memref.size < sizeof(uint32_t));
        if (check_fail) {
            tloge("params[1] buffer is null or invalid size %zu\n", params[PARAM_ONE].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        *params_enforced = (keymaster_key_param_set_t *)params[PARAM_ONE].memref.buffer;
        /* check input params. */
        if (key_param_set_check(*params_enforced, params[PARAM_ONE].memref.size)) {
            tloge("km_begin need poper params_enforced\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    check_fail = (params[PARAM_TWO].memref.buffer == NULL || params[PARAM_TWO].memref.size != KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("params[2] buffer is null invalid size %zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result check_update_params(uint32_t param_types, const TEE_Param *params,
    keymaster_key_param_set_t **params_enforced, keymaster_blob_t *in_data)
{
    bool check_fail = (((TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) != TEE_PARAM_TYPE_MEMREF_INPUT &&
        TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) != TEE_PARAM_TYPE_MEMREF_INPUT &&
        TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) != TEE_PARAM_TYPE_NONE) ||
        TEE_PARAM_TYPE_GET(param_types, PARAM_TWO) != TEE_PARAM_TYPE_MEMREF_INOUT ||
        TEE_PARAM_TYPE_GET(param_types, PARAM_THREE) != TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        params == NULL);
    if (check_fail) {
        tloge("invalid param types or params null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        check_fail = (params[PARAM_ZERO].memref.buffer == NULL || params[PARAM_ZERO].memref.size < sizeof(uint32_t));
        if (check_fail) {
            tloge("params[0].memref.buffer is null or params[0].memref.size is %zu\n", params[PARAM_ZERO].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        *params_enforced = (keymaster_key_param_set_t *)params[PARAM_ZERO].memref.buffer;
        if (key_param_set_check(*params_enforced, params[PARAM_ZERO].memref.size)) {
            tloge("km_update need poper params_enforced\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    if (params[PARAM_THREE].memref.buffer == NULL) {
        tloge("output buffer is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        check_fail = (params[PARAM_ONE].memref.buffer == NULL || params[PARAM_ONE].memref.size == 0 || in_data == NULL);
        if (check_fail) {
            tloge("params[1].memref.buffer is null or params[1].memref.size is %zu\n", params[PARAM_ONE].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        if (params[PARAM_THREE].memref.size < params[PARAM_ONE].memref.size) {
            tloge("out size %zu < input size %zu\n", params[PARAM_THREE].memref.size, params[PARAM_ONE].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        in_data->data_addr = params[PARAM_ONE].memref.buffer;
        in_data->data_length = params[PARAM_ONE].memref.size;
    }
    check_fail = (params[PARAM_TWO].memref.buffer == NULL || params[PARAM_TWO].memref.size != KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("null:params[2].memref.buffer is null or params[2].memref.size is %zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result check_finish_params(uint32_t param_types, const TEE_Param *params,
    keymaster_key_param_set_t **params_enforced, keymaster_blob_t *final_data)
{
    bool check_fail = (((TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) != TEE_PARAM_TYPE_MEMREF_INPUT &&
        TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) != TEE_PARAM_TYPE_MEMREF_INPUT &&
        TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) != TEE_PARAM_TYPE_NONE) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_TWO) != TEE_PARAM_TYPE_MEMREF_INOUT) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_THREE) != TEE_PARAM_TYPE_MEMREF_OUTPUT)) ||
        params == NULL);
    if (check_fail) {
        tloge("invalid param types or params null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (TEE_PARAM_TYPE_GET(param_types, PARAM_ZERO) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        check_fail = (params[PARAM_ZERO].memref.buffer == NULL || params[PARAM_ZERO].memref.size < sizeof(uint32_t));
        if (check_fail) {
            tloge("params[0] buffer is null or size %zu too short\n", params[PARAM_ZERO].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        *params_enforced = (keymaster_key_param_set_t *)params[PARAM_ZERO].memref.buffer;
        if (key_param_set_check(*params_enforced, params[PARAM_ZERO].memref.size)) {
            tloge("km_finish need poper params_enforced\n");
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    if (TEE_PARAM_TYPE_GET(param_types, PARAM_ONE) == TEE_PARAM_TYPE_MEMREF_INPUT) {
        check_fail = ((params[PARAM_ONE].memref.buffer == NULL) || (params[PARAM_ONE].memref.size == 0) ||
            final_data == NULL);
        if (check_fail) {
            tloge("params[1] buffer is null or size %zu too short\n", params[PARAM_ONE].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
        final_data->data_addr = params[PARAM_ONE].memref.buffer;
        final_data->data_length = params[PARAM_ONE].memref.size;
    }
    check_fail = ((params[PARAM_TWO].memref.buffer == NULL) || (params[PARAM_TWO].memref.size != KEY_BLOB_MAX_SIZE));
    if (check_fail) {
        tloge("params[2] buffer is null or invalid size %zu\n", params[PARAM_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = (params[PARAM_THREE].memref.buffer == NULL || params[PARAM_THREE].memref.size != KEY_BLOB_MAX_SIZE);
    if (check_fail) {
        tloge("params[2] buffer is null or invalid size %zu\n", params[PARAM_THREE].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result km_abort_params_check(uint32_t param_types, const TEE_Param *params)
{
    bool check_fail = ((params == NULL) || (check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) == false));
    if (check_fail) {
        tloge("invalid param types or params null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params[PARAM_ZERO].memref.buffer == NULL) {
        tloge("The param buffer is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* check memref.buffer size >= sizeof(uint64) */
    if (params[PARAM_ZERO].memref.size < sizeof(uint64_t)) {
        tloge("invalid param buffer of operation_handle\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

TEE_Result km_upgrade_check(uint32_t param_types, const TEE_Param *params)
{
    if (params == NULL) {
        tloge("the input parameter params is null!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                          TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE)) {
        tloge("invalid param types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* params check */
    bool check_fail = (params[0].memref.buffer == NULL || sizeof(keyblob_head) > params[0].memref.size);
    if (check_fail) {
        tloge("params[0] buffer is null or invalid size %zu\n", params[0].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = (params[1].memref.buffer == NULL || sizeof(uint32_t) > params[1].memref.size);
    if (check_fail) {
        tloge("params[1] buffer is null or invalid size %zu\n", params[1].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key_param_set_check((keymaster_key_param_set_t *)params[1].memref.buffer, params[1].memref.size) != 0) {
        tloge("km_upgrade need poper params_enforced\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    check_fail = (params[PARAM_NBR_TWO].memref.buffer == NULL ||
        sizeof(keyblob_head) > params[PARAM_NBR_TWO].memref.size);
    if (check_fail) {
        tloge("params[2] buffer is null or invalid size %zu\n", params[PARAM_NBR_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
TEE_Result km_attest_key_check(uint32_t param_types, TEE_Param *params)
{
    if (!is_cfg_state_ready()) {
        tloge("keymaster is not configured correctly\n");
        return (TEE_Result)KM_ERROR_KEYMASTER_NOT_CONFIGURED;
    }
    bool invalid = ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
        (TEE_PARAM_TYPE_GET(param_types, PARAM_NBR_TWO)) != TEE_PARAM_TYPE_MEMREF_OUTPUT);
    if (invalid) {
        tloge("Bad expected parameter types\n"); /* check params types */
        return TEE_ERROR_BAD_PARAMETERS;
    }
    /* params check */
    if (params == NULL) {
        tloge("the input parameter params is NULL\n");
        return (TEE_Result)KM_ERROR_UNEXPECTED_NULL_POINTER;
    }
    invalid = ((params[0].memref.buffer == NULL) || (sizeof(keyblob_head) > params[0].memref.size));
    if (invalid) {
        tloge("null:params[0].memref.buffer is NULL or params[0].memref.size is %zu\n", params[0].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    invalid = ((params[1].memref.buffer == NULL) || (sizeof(uint32_t) > params[1].memref.size));
    if (invalid) {
        tloge("null:params[1].memref.buffer is null or params[1].memref.size is %zu\n", params[1].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (key_param_set_check((keymaster_key_param_set_t *)params[1].memref.buffer, params[1].memref.size) != 0) {
        tloge("need proper params_enforced\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    invalid = ((params[PARAM_NBR_TWO].memref.buffer == NULL) || (params[PARAM_NBR_TWO].memref.size != CHAIN_MAX_LEN));
    if (invalid) {
        tloge("null:params[2].memref.buffer is NULL or params[2].memref.size is %zu\n",
            params[PARAM_NBR_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
#if (defined(TEE_SUPPORT_RPMB_64BIT) || defined(TEE_SUPPORT_RPMB_32BIT))
TEE_Result check_policy_set(uint32_t param_types, const TEE_Param *params)
{
    /* param[0]:keyblob;param[1]:policy */
    bool condition_check = ((TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT) ||
                            (TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_INPUT));
    if (condition_check) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    condition_check = ((params[0].memref.buffer == NULL) || (params[0].memref.size < sizeof(keyblob_head)) ||
                       (params[0].memref.size > KEY_BLOB_MAX_SIZE));
    if (condition_check) {
        tloge("null:params[0].memref.buffer is null or params[0].memref.size is %zu\n", params[0].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    condition_check = ((params[1].memref.buffer == NULL) || (params[1].memref.size != sizeof(ctl_eima_policy_t)));
    if (condition_check) {
        tloge("null:params[1].memref.buffer is null or params[1].memref.size is %zu\n", params[1].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
#ifdef CFG_TEE_KEYMASTER_ENHANCED_KEY
    keyblob_head *key_blob = (keyblob_head *)params[0].memref.buffer;
    if (key_blob->version == VERSION_340 || key_blob->version == VERSION_540 ||
        key_blob->version == VERSION_341 || key_blob->version == VERSION_541) {
        tloge("this keyblob version %u unsupported\n", key_blob->version);
        return TEE_ERROR_BAD_PARAMETERS;
    }
#endif
    return TEE_SUCCESS;
}
#endif
static TEE_Result km_store_verify_params0_check(const TEE_Param *params, int flag)
{
    bool check = false;
    if (flag == 0) {
        check = (params[0].memref.buffer == NULL) || (params[0].memref.size == 0);
        if (check) {
            tloge("null:params[0].memref.buffer is null or params[0].memref.size is %zu\n", params[0].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    } else {
        check = ((params[0].memref.buffer == NULL) || (params[0].memref.size <= CBC_IV_LENGTH));
        if (check) {
            tloge("null:params[0].memref.buffer is null or params[0].memref.size is %zu\n", params[0].memref.size);
            return TEE_ERROR_BAD_PARAMETERS;
        }
    }
    return TEE_SUCCESS;
}

TEE_Result km_store_verify_params_check(const TEE_Param *params, int flag)
{
    TEE_Result ret = km_store_verify_params0_check(params, flag);
    if (ret != TEE_SUCCESS)
        return ret;
    bool check = (params[1].memref.buffer == NULL) || (params[1].memref.size != TEXT_TO_SIGN_SIZE);
    if (check) {
        tloge("null:params[1].memref.buffer is null or params[1].memref.size is %zu\n", params[1].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check = (params[PARAM_NBR_TWO].memref.buffer == NULL) || (params[PARAM_NBR_TWO].memref.size != SIG_MAX_LEN);
    if (check) {
        tloge("null:params[2].memref.buffer is null or params[2].memref.size is %zu\n",
            params[PARAM_NBR_TWO].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    check = (params[PARAM_NBR_THREE].memref.buffer == NULL) || (params[PARAM_NBR_THREE].memref.size != CHAIN_MAX_LEN);
    if (check) {
        tloge("null:params[3].memref.buffer is null or params[3].memref.size is %zu\n",
            params[PARAM_NBR_THREE].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
