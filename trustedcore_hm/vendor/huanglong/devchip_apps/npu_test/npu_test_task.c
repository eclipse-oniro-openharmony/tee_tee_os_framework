/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020. All rights reserved.
 * Description: test task function file for Hisilicon NPU
 * Author: ai group
 * Create: 2020/02/17
 * Notes:
 */

#include "hi_tee_hal.h"
#include "hi_type_dev.h"
#include "tee_npu_utils.h"
#include "tee_npu_test.h"

#define TEEC_CMD_NPU_INIT            0
#define TEEC_CMD_NPU_DEINIT          1
#define TEEC_CMD_NPU_TEST_HWTS       2

#define hi_error_npu(fmt...)    tloge(fmt)

static hi_bool npu_check_param_type(const hi_u32 cmd_id, const hi_u32 param_type)
{
    hi_u32 cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    switch (cmd_id) {
        case TEEC_CMD_NPU_INIT: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_NPU_DEINIT: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_NPU_TEST_HWTS: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        default: {
            return HI_FALSE;
        }
    }

    if (cmd_param_type != param_type) {
        hi_error_npu("TA command not valid\n");
        return HI_FALSE;
    }

    return HI_TRUE;
}

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    return AddCaller_CA_exec((char *)"default", 0);
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], /* 4 params */
                                              hi_void **sessionContext)
{
    (void)paramTypes;
    (void)params;
    (void)sessionContext;
    return TEE_SUCCESS;
}

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *sessionContext, uint32_t commandID, uint32_t paramTypes,
                                                TEE_Param params[4]) /* 4 params  */
{
    TEE_Result ret;

    (void)paramTypes;
    (void)params;
    (void)sessionContext;

    if (HI_TRUE != npu_check_param_type(commandID, paramTypes)) {
        hi_error_npu("check param fail\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (commandID) {
        case TEEC_CMD_NPU_INIT: {
            ret = tee_npu_init();
            break;
        }

        case TEEC_CMD_NPU_DEINIT: {
            ret = tee_npu_deinit();
            break;
        }

        case TEEC_CMD_NPU_TEST_HWTS: {
            ret = tee_npu_test_hwts();
            break;
        }

        default: {
            tloge("Invalid command!\n");
            break;
        }
    }

    if (ret == TEE_SUCCESS) {
        tloge("Invoke command[0x%x] suc\n", commandID);
    } else {
        tloge("Invoke command[0x%x] failed, ret[0x%x]\n", commandID, ret);
    }

    return  ret;
}

__DEFAULT void TA_CloseSessionEntryPoint(hi_void *sessionContext)
{
    (void)sessionContext;
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
}

