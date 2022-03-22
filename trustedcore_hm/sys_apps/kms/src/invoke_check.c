/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: self consensus
 * Author: wangwenyuan.wang@huawei.com
 * Create: 2020-04-14
 */
#include "invoke.h"
#include "tee_log.h"
#include "kms_pub_def.h"
#include "product_uuid_public.h"
#include "tee_ext_api.h"

int32_t kms_cmd_create_key_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE) || params == NULL) {
        tloge("kms create key: Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("kms create key: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT
 * TEE_PARAM_TYPE_MEMREF_OUTPUT check
 */
int32_t kms_cmd_iiio_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT) || params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_2].memref.buffer == NULL || params[INDEX_2].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_3].memref.buffer == NULL || params[INDEX_3].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("iiio check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_NONE
 * TEE_PARAM_TYPE_MEMREF_OUTPUT check
 */
int32_t kms_cmd_iino_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_MEMREF_OUTPUT) || params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_3].memref.buffer == NULL || params[INDEX_3].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("iino check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_OUTPUT
 * TEE_PARAM_NONE check
 */
int32_t kms_cmd_iion_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE) || params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_2].memref.buffer == NULL || params[INDEX_2].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("iino check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT
 * TEE_PARAM_TYPE_MEMREF_INPUT check
 */
int32_t kms_cmd_iiii_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT) ||
        params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_2].memref.buffer == NULL || params[INDEX_2].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_3].memref.buffer == NULL || params[INDEX_3].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("iiii check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_NONE
 * TEE_PARAM_TYPE_MEMREF_INPUT check
 */
int32_t kms_cmd_iini_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_MEMREF_INPUT) || params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_3].memref.buffer == NULL || params[INDEX_3].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("iini check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT
 * TEE_PARAM_TYPE_NONE check
 */
int32_t kms_cmd_iiin_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE) ||
        params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_2].memref.buffer == NULL || params[INDEX_2].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("iiin check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_NONE
 * TEE_PARAM_TYPE_NONE check
 */
int32_t kms_cmd_iinn_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) || params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("iinn check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
int32_t kms_cmd_begin_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT) ||
        params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_1].memref.buffer == NULL || params[INDEX_1].memref.size != sizeof(uint32_t) ||
        params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN ||
        params[INDEX_2].memref.buffer == NULL || params[INDEX_2].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("input buffer is invalid %lu", params[INDEX_1].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

int32_t kms_cmd_update_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (TEE_PARAM_TYPE_GET(param_types, INDEX_0) != TEE_PARAM_TYPE_MEMREF_INPUT) {
        tloge("update check: bad param type");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL || params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size != sizeof(uint32_t)) {
        tloge("update check bad input");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t mode = *(uint32_t *)params[INDEX_0].memref.buffer;
    if (mode == KMS_MODE_ENCRYPT || mode == KMS_MODE_DECRYPT) {
        return kms_cmd_iiio_check(params, param_types);
    } else {
        return kms_cmd_iiin_check(params, param_types);
    }
}

int32_t kms_cmd_finish_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (TEE_PARAM_TYPE_GET(param_types, INDEX_0) != TEE_PARAM_TYPE_MEMREF_INPUT) {
        tloge("finish check: bad param type");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (params == NULL || params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size != sizeof(uint32_t)) {
        tloge("finish check bad input invalid");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    uint32_t mode = *(uint32_t *)params[INDEX_0].memref.buffer;
    if (TEE_PARAM_TYPE_GET(param_types, INDEX_2) == TEE_PARAM_TYPE_NONE) {
        if (mode == KMS_MODE_VERIFY) {
            return kms_cmd_iini_check(params, param_types);
        } else {
            return kms_cmd_iino_check(params, param_types);
        }
    } else {
        if (mode == KMS_MODE_VERIFY) {
            return kms_cmd_iiii_check(params, param_types);
        } else {
            return kms_cmd_iiio_check(params, param_types);
        }
    }
}
/*
 * param is TEE_PARAM_TYPE_MEMREF_OUTPUT TEE_PARAM_TYPE_NONE TEE_PARAM_TYPE_NONE
 * TEE_PARAM_TYPE_NONE check
 */
int32_t kms_cmd_random_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) ||
        params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("cmd random check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
/*
 * param is TEE_PARAM_TYPE_MEMREF_INPUT TEE_PARAM_TYPE_NONE TEE_PARAM_TYPE_NONE
 * TEE_PARAM_TYPE_NONE check
 */
int32_t kms_cmd_abort_check(TEE_Param params[CMD_PARAMS_LEN], uint32_t param_types)
{
    if (!check_param_type(param_types, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE) || params == NULL) {
        tloge("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    bool check = (params[INDEX_0].memref.buffer == NULL || params[INDEX_0].memref.size > MAX_IN_BUFFER_LEN);
    if (check) {
        tloge("cmd abort check: input buffer is null");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}
