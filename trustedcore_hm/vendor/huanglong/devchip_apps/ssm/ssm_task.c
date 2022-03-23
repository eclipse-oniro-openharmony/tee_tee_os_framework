/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019. All rights reserved.
 * Description: ssm task function file for Hisilicon SSM
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
#define TEEC_CMD_SSM_INIT           6
#define TEEC_CMD_SSM_SET_REG        7

#ifdef CFG_HI_TEE_SSM_TEST_SUPPORT
#define TEEC_CMD_SSM_SEND_POLICY_TBL      0xfe
#define TEEC_CMD_SSM_CHECK_BUF            0xff
#endif

#define hi_error_ssm(fmt...)    tloge(fmt)

typedef struct {
    hi_u32 cmd;
    hi_u32 param_type;
} ssm_check_map;

typedef struct {
    hi_u32 cmd;
    hi_s32 (*ssm_cmd_handler)(TEE_Param params[4]); /* 4 params for tee cmd */
} ssm_cmd_map;

static ssm_check_map g_check_map[] = {
    {TEEC_CMD_SSM_CREATE, TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_DESTROY, TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_ADD_RESOUCE, TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_ATTACH_BUFFER, TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_SECSMMU_HAND_INPUT,
        TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_GET_INTENT, TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_IOMMU_CONFIG, TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_INIT, TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_SET_REG, TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
#ifdef CFG_HI_TEE_SSM_TEST_SUPPORT
    {TEEC_CMD_SSM_CHECK_BUF, TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_SECSMMU_HAND_INPUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)},
    {TEEC_CMD_SSM_SEND_POLICY_TBL, TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INOUT,
        TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)}
#endif
};

static hi_bool ssm_check_param_type(const hi_u32 cmd_id, const hi_u32 param_type)
{
    hi_u32 i;

    for (i = 0; i < sizeof(g_check_map) / sizeof(g_check_map[0]); i++) {
        if (g_check_map[i].cmd == cmd_id) {
            if (param_type != g_check_map[i].param_type) {
                hi_error_ssm("param types are not match cmd : %d\n", cmd_id);
                return HI_FALSE;
            }
            break;
        }
    }

    if (i >= sizeof(g_check_map) / sizeof(g_check_map[0])) {
        hi_error_ssm("cannot find right cmd : %d\n", cmd_id);
        return HI_FALSE;
    }

    return HI_TRUE;
}

__DEFAULT TEE_Result TA_CreateEntryPoint(void)
{
    return AddCaller_CA_exec((char *)"tee_ssm_session", 0);
}

__DEFAULT TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes, TEE_Param params[4], /* 4 param */
                                              hi_void **sessionContext)
{
    (void)paramTypes;
    (void)params;
    (void)sessionContext;
    return TEE_SUCCESS;
}

hi_s32 ssm_cmd_create_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    hi_s32 ret;
    hi_u32 get_handle = HI_INVALID_HANDLE;

    ret = hi_tee_ssm_create(params[0].value.a, &get_handle);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm create fail:%x\n", ret);
        return ret;
    }

    params[0].value.b = get_handle;
    return ret;
}

hi_s32 ssm_cmd_destroy_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    hi_s32 ret;

    ret = hi_tee_ssm_destroy(params[0].value.a);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm destroy fail:%x\n", ret);
        return ret;
    }
    return ret;
}

hi_s32 ssm_cmd_add_resource_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    hi_s32 ret;
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

    return ret;
}

hi_s32 ssm_cmd_attach_buf_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    hi_s32 ret;
    hi_tee_ssm_buffer_attach_info attach_info = {0};
    hi_u64                        get_addr = 0;

    ret = memcpy_s(&attach_info, sizeof(hi_tee_ssm_buffer_attach_info),
        (hi_void *)params[0].memref.buffer, (hi_u32)params[0].memref.size);
    if (ret != 0) {
        hi_error_ssm("ssm copy param fail\n");
        return ret;
    }

    attach_info.buf_smmu_handle = params[1].value.a | ((unsigned long long)params[1].value.b << 32); /* 32 is offset */

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

    params[2].value.b = get_addr; /* 2 is offset */

    return ret;
}

hi_s32 ssm_cmd_get_intent_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    hi_s32 ret;
    hi_tee_ssm_intent get_intent = HI_TEE_SSM_INTENT_MAX;

    ret = hi_tee_ssm_get_intent(params[0].value.a, &get_intent);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm get intent fail:%x\n", ret);
        return ret;
    }

    params[0].value.b = get_intent;
    return ret;
}

hi_s32 ssm_cmd_iommu_cfg_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    hi_s32 ret;

    ret = hi_tee_ssm_set_iommu_tag(params[0].value.a);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm set iommu tag fail:%x\n", ret);
        return ret;
    }

    return ret;
}

hi_s32 ssm_cmd_init_handler()
{
    hi_s32 ret;

    ret = hi_tee_ssm_init();
    if (ret != HI_SUCCESS) {
        hi_error_ssm("hi_tee_ssm_init fail:%x\n", ret);
        return ret;
    }

    return ret;
}

hi_s32 ssm_cmd_set_reg_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    return hi_tee_ssm_set_reg(params[0].value.a, params[0].value.b);
}
#ifdef CFG_HI_TEE_SSM_TEST_SUPPORT
hi_s32 ssm_cmd_check_buf_handler(TEE_Param params[4]) /* 4 params for tee cmd */
{
    hi_s32 ret;
    hi_tee_ssm_buffer_check_info check_info = {0};

    ret = memcpy_s(&check_info, sizeof(hi_tee_ssm_buffer_check_info),
        (hi_void *)params[0].memref.buffer, (hi_u32)params[0].memref.size);
    if (ret != 0) {
        hi_error_ssm("ssm copy param fail\n");
        return ret;
    }

    check_info.buf_handle = params[1].value.a | ((unsigned long long)params[1].value.b << 32); /* 32 is offset */

    if ((check_info.buf_handle == 0) ||
        (check_info.module_handle == HI_INVALID_HANDLE) ||
        (check_info.session_handle == HI_INVALID_HANDLE)) {
        hi_error_ssm("ssm attach param invalid\n");
        return HI_FAILURE;
    }

    if (((check_info.buf_id <= BUFFER_ID_INVALID) || (check_info.buf_id >= BUFFER_ID_MAX))) {
        hi_error_ssm("ssm attach param invalid\n");
        return HI_FAILURE;
    }

    ret = hi_tee_ssm_check_buf(&check_info);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("ssm attach info fail:%x\n", ret);
        return ret;
    }

    return ret;
}

hi_s32 ssm_cmd_send_policy_handler(TEE_Param params[4]) /* 4 is param num */
{
    hi_tee_ssm_policy_table get_tbl = {0};
    hi_s32 ret;

    ret = memcpy_s(&get_tbl, sizeof(hi_tee_ssm_policy_table),
        (hi_void *)params[0].memref.buffer, (hi_u32)params[0].memref.size);
    if (ret != EOK) {
        hi_error_ssm("cpy policy tbl fail\n");
        return HI_FAILURE;
    }

    ret = hi_tee_ssm_send_policy_table(params[1].value.a, &get_tbl);
    if (ret != HI_SUCCESS) {
        hi_error_ssm("call hi_tee_ssm_send_policy_table fail : 0x%x\n", ret);
        return ret;
    }

    return HI_SUCCESS;
}

#endif

static ssm_cmd_map g_cmd_map[] = {
    {TEEC_CMD_SSM_CREATE, ssm_cmd_create_handler},
    {TEEC_CMD_SSM_DESTROY, ssm_cmd_destroy_handler},
    {TEEC_CMD_SSM_ADD_RESOUCE, ssm_cmd_add_resource_handler},
    {TEEC_CMD_SSM_ATTACH_BUFFER, ssm_cmd_attach_buf_handler},
    {TEEC_CMD_SSM_GET_INTENT, ssm_cmd_get_intent_handler},
    {TEEC_CMD_SSM_IOMMU_CONFIG, ssm_cmd_iommu_cfg_handler},
    {TEEC_CMD_SSM_INIT, ssm_cmd_init_handler},
    {TEEC_CMD_SSM_SET_REG, ssm_cmd_set_reg_handler},
#ifdef CFG_HI_TEE_SSM_TEST_SUPPORT
    {TEEC_CMD_SSM_CHECK_BUF, ssm_cmd_check_buf_handler},
    {TEEC_CMD_SSM_SEND_POLICY_TBL, ssm_cmd_send_policy_handler},
#endif
};

__DEFAULT TEE_Result TA_InvokeCommandEntryPoint(hi_void *sessionContext, uint32_t commandID, uint32_t paramTypes,
                                                TEE_Param params[4]) /* 4 params for tee cmd */
{
    TEE_Result ret;
    hi_u32 i;

    (void)paramTypes;
    (void)sessionContext;

    if (ssm_check_param_type(commandID, paramTypes) != HI_TRUE) {
        hi_error_ssm("check param fail\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    for (i = 0; i < sizeof(g_cmd_map) / sizeof(g_cmd_map[0]); i++) {
        if (g_cmd_map[i].cmd == commandID) {
            ret = g_cmd_map[i].ssm_cmd_handler(params);
            break;
        }
    }

    if (i >= sizeof(g_cmd_map) / sizeof(g_cmd_map[0])) {
        tloge("invalid command[0x%x] failed\n", commandID);
        ret = HI_FAILURE;
    }

    return ret;
}

__DEFAULT void TA_CloseSessionEntryPoint(hi_void *sessionContext)
{
    (void)sessionContext;
}

__DEFAULT void TA_DestroyEntryPoint(void)
{
}

