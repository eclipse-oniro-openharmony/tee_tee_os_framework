/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.
 * Description: test task function file for Hisilicon SSM
 * Author: ssm group
 * Create: 2019/12/11
 * Notes:
 */

#include "hi_tee_hal.h"
#include "hi_type_dev.h"
#include "hi_tee_ssm.h"

#define TEEC_CMD_SSM_CREATE         0
#define TEEC_CMD_SSM_DESTROY        1
#define TEEC_CMD_SSM_ADD_RESOUCE    2
#define TEEC_CMD_SSM_ATTACH_BUFFER  3
#define TEEC_CMD_SSM_GET_INTENT     4
#define TEEC_CMD_SSM_IOMMU_CONFIG   5
#define TEEC_CMD_SSM_SET_UUID       6
#define TEEC_CMD_SSM_CHECK_UUID     7

#define hi_error_ssm(fmt...)    tloge(fmt)

static hi_bool ssm_check_param_type(const hi_u32 cmd_id, const hi_u32 param_type)
{
    hi_u32 cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    switch (cmd_id) {
        case TEEC_CMD_SSM_CREATE: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_SSM_DESTROY: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_SSM_ADD_RESOUCE: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_SSM_ATTACH_BUFFER: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INOUT,
                TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_SSM_GET_INTENT: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_SSM_IOMMU_CONFIG: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_SSM_SET_UUID: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        case TEEC_CMD_SSM_CHECK_UUID: {
            cmd_param_type = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
                TEE_PARAM_TYPE_NONE);
            break;
        }

        default: {
            return HI_FALSE;
        }
    }

    if (cmd_param_type != param_type) {
        hi_error_ssm("TA command not valid\n");
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
                                                TEE_Param params[4]) /* 4 params */
{
    TEE_Result ret;

    (void)paramTypes;
    (void)sessionContext;

    if (HI_TRUE != ssm_check_param_type(commandID, paramTypes)) {
        hi_error_ssm("check param fail\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    switch (commandID) {
        case TEEC_CMD_SSM_CREATE: {
            hi_u32    get_handle = HI_INVALID_HANDLE;
            ret = hi_tee_ssm_create(params[0].value.a, &get_handle);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm create fail:%x\n", ret);
                return ret;
            }

            params[0].value.b = get_handle;
            break;
        }

        case TEEC_CMD_SSM_DESTROY: {
            ret = hi_tee_ssm_destroy(params[0].value.a);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm destroy fail:%x\n", ret);
                return ret;
            }
            break;
        }

        case TEEC_CMD_SSM_ADD_RESOUCE: {
            hi_tee_ssm_module_info mod_info = {0};

            ret = memcpy_s(&mod_info, sizeof(mod_info), (hi_void *)params[1].memref.buffer, params[1].memref.size);
            if (ret != 0) {
                hi_error_ssm("ssm copy param fail\n");
                return ret;
            }

            ret = hi_tee_ssm_add_resource(params[0].value.a, &mod_info);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm add resource fail:%x\n", ret);
                return ret;
            }
            break;
        }

        case TEEC_CMD_SSM_ATTACH_BUFFER: {
            hi_tee_ssm_buffer_attach_info attach_info = {0};
            hi_u64                        get_addr = 0;

            ret = memcpy_s(&attach_info, sizeof(hi_tee_ssm_buffer_attach_info),
                (hi_void *)params[0].memref.buffer, (hi_u32)params[0].memref.size);
            if (ret != 0) {
                hi_error_ssm("ssm copy param fail\n");
                return ret;
            }

            if ((attach_info.buf_smmu_handle == 0) ||
                (attach_info.module_handle == HI_INVALID_HANDLE) ||
                (attach_info.session_handle == HI_INVALID_HANDLE)) {
                hi_error_ssm("ssm attach param invalid\n");
                return HI_FAILURE;
            }

            if ((attach_info.buf_id <= BUFFER_ID_INVALID) || (attach_info.buf_id >= BUFFER_ID_MAX)) {
                hi_error_ssm("ssm attach param invalid\n");
                return HI_FAILURE;
            }

            ret = hi_tee_ssm_attach_buffer(&attach_info, &get_addr);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm attach info fail:%x\n", ret);
                return ret;
            }

            params[1].value.b = get_addr;
            break;
        }

        case TEEC_CMD_SSM_GET_INTENT: {
            hi_tee_ssm_intent get_intent = HI_TEE_SSM_INTENT_MAX;

            ret = hi_tee_ssm_get_intent(params[0].value.a, &get_intent);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm get intent fail:%x\n", ret);
                return ret;
            }

            params[0].value.b = get_intent;
            break;
        }

        case TEEC_CMD_SSM_IOMMU_CONFIG: {
            ret = hi_tee_ssm_set_iommu_tag(params[0].value.a);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm set iommu tag fail:%x\n", ret);
                return ret;
            }

            break;
        }

        case TEEC_CMD_SSM_SET_UUID: {
            ret = hi_tee_ssm_set_uuid(params[0].value.a);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm hi_tee_ssm_set_uuid fail:%x\n", ret);
                return ret;
            }

            break;
        }

        case TEEC_CMD_SSM_CHECK_UUID: {
            ret = hi_tee_ssm_check_uuid(params[0].value.a);
            if (ret != HI_SUCCESS) {
                hi_error_ssm("ssm hi_tee_ssm_check_uuid fail:%x\n", ret);
                return ret;
            }

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

