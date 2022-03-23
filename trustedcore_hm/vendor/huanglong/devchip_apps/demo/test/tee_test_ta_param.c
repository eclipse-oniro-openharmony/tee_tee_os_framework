/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee test TA code for invoke param test
 * Author: Hisilicon
 * Created: 2020-04-16
 */

#include "tee_test_ta_param.h"
#include "tee_log.h"
#include "securec.h"

TEE_Result ta_test_params_value(unsigned int param_types, TEE_Param params[4]) /* 4, param num */
{
    unsigned int type = TEE_PARAM_TYPE_GET(param_types, 0);
    TEE_Result result = TEE_SUCCESS;

    switch (type) {
        case TEE_PARAM_TYPE_VALUE_INPUT:
            if (params[0].value.a != TEE_TEST_VALUE_FROM_REE) {
                result = TEE_ERROR_GENERIC;
            }
            break;
        case TEE_PARAM_TYPE_VALUE_OUTPUT:
            params[0].value.b = TEE_TEST_VALUE_TO_REE;
            break;
        case TEE_PARAM_TYPE_VALUE_INOUT:
            if (params[0].value.a != TEE_TEST_VALUE_FROM_REE) {
                result = TEE_ERROR_GENERIC;
                break;
            }
            params[0].value.b = TEE_TEST_VALUE_TO_REE;
            break;
        default:
            tloge("invalud param type\n");
            result = TEE_ERROR_BAD_PARAMETERS;
            break;
    }

    return result;
}

TEE_Result ta_test_params_memref(unsigned int param_types, TEE_Param params[4]) /* 4, param num */
{
    unsigned int type = TEE_PARAM_TYPE_GET(param_types, 0);
    TEE_Result result = TEE_SUCCESS;

    switch (type) {
        case TEE_PARAM_TYPE_MEMREF_INPUT:
            if (strcmp(params[0].memref.buffer, TEE_TEST_STR_FROM_REE)) {
                result = TEE_ERROR_GENERIC;
            }
            break;
        case TEE_PARAM_TYPE_MEMREF_OUTPUT:
            if (memset_s(params[0].memref.buffer, params[0].memref.size, 0, params[0].memref.size) != EOK ||
                snprintf_s(params[0].memref.buffer, params[0].memref.size,
                           strlen(TEE_TEST_STR_TO_REE), TEE_TEST_STR_TO_REE) == -1) {
                result = TEE_ERROR_GENERIC;
            }
            break;
        case TEE_PARAM_TYPE_MEMREF_INOUT:
            if (strcmp(params[0].memref.buffer, TEE_TEST_STR_FROM_REE) ||
                memset_s(params[0].memref.buffer, params[0].memref.size, 0, params[0].memref.size) != EOK ||
                snprintf_s(params[0].memref.buffer, params[0].memref.size,
                           strlen(TEE_TEST_STR_TO_REE), TEE_TEST_STR_TO_REE) == -1) {
                result = TEE_ERROR_GENERIC;
            }
            break;
        default:
            tloge("invalud param type\n");
            result = TEE_ERROR_BAD_PARAMETERS;
            break;
    }

    return result;
}

TEE_Result ta_test_params_expand(unsigned int param_types, TEE_Param params[4]) /* 4, param num */
{
    unsigned int type = TEE_PARAM_TYPE_GET(param_types, 0);
    TEE_Result result = TEE_SUCCESS;

    switch (type) {
        case TEE_PARAM_TYPE_NSSMMU_HAND_INPUT:
            hi_tee_printf("TEE_PARAM_TYPE_NSSMMU_HAND_INPUT\n");
            break;
        case TEE_PARAM_TYPE_SECSMMU_HAND_INPUT:
            hi_tee_printf("TEE_PARAM_TYPE_SECSMMU_HAND_INPUT\n");
            break;
        case TEE_PARAM_TYPE_PHYS_HAND_INPUT:
            hi_tee_printf("TEE_PARAM_TYPE_PHYS_HAND_INPUT\n");
            break;
        default:
            tloge("invalud param type\n");
            result = TEE_ERROR_BAD_PARAMETERS;
            break;
    }

    return result;
}
