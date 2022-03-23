/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee test ta code
 * Author: Hisilicon
 * Create: 2020-04-16
 */

#include "tee_test_ta.h"
#include "tee_test_ta_param.h"
#include "tee_test_ta_mem_api.h"
#include "tee_test_ta_storage.h"
#include "tee_test_ta_time.h"
#include "tee_internal_api.h"
#include "hi_tee_demo.h"
#include "tee_log.h"

TEE_Result tee_test_main(unsigned int cmd, unsigned int param_types, TEE_Param params[4])  /* 4, param num */
{
    TEE_Result ret;

    switch (cmd) {
        case TEE_TEST_CMD_PARAMS_VALUE:
            ret = ta_test_params_value(param_types, params);
            break;
        case TEE_TEST_CMD_PARAMS_TMPREF:
            ret = ta_test_params_memref(param_types, params);
            break;
        case TEE_TEST_CMD_PARAMS_MEMREF:
            ret = ta_test_params_memref(param_types, params);
            break;
        case TEE_TEST_CMD_PARAMS_MEM_HAND:
            ret = ta_test_params_expand(param_types, params);
            break;
        case TEE_TEST_CMD_MEM_API:
            ret = ta_test_mem_api(params[0].value.a, params[0].value.b);
            break;
        case TEE_TEST_CMD_STORAGE:
            ret = ta_test_storage(params[0].value.a);
            break;
        case TEE_TEST_CMD_TIME:
            ret = ta_test_time(params[0].value.a, params[0].value.b);
            break;
        case TEE_TEST_CMD_DRV_HAL:
            ret = hi_tee_demo_test(0, NULL, 0);
            break;
        default:
            tloge("invalud cmd[0x%x]!\n", cmd);
            ret = TEE_ERROR_INVALID_CMD;
            break;
    }

    return ret;
}

