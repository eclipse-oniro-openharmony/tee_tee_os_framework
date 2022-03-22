/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: rpmb key and wrapping key ta in equipment
 * Author: huawei
 * Create: 2020-06-02
 */
#include "tee_defines.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"

#include "hsm_ta_public.h"
#include "hsm_rpmb_api.h"
#include "rpmb_fcntl.h"
#include "rpmb_key_ta.h"

#define OPEN_SESSION_PARA_NUM 4

STATIC uint32_t rpmb_key_test(void)
{
    uint32_t ret;
    uint32_t out_len;
    uint8_t rpmb_file_name[HSM_RPMB_FILE_LEN] = {"hsm_rpmb"};
    uint8_t rpmb_buffer_in[HSM_RPMB_BUFFER_LEN] = {
        0x7d, 0xb1, 0x9e, 0x29, 0xe8, 0x71, 0x49, 0xd3, 0x1d, 0xe9, 0x86, 0x04, 0x7e, 0x5b, 0xda, 0x75,
        0x68, 0x70, 0x80, 0x56, 0xaa, 0xaa, 0x8b, 0x16, 0x07, 0x87, 0xc8, 0x87, 0x71, 0x51, 0x8e, 0x2f,
        0xe6, 0x23, 0xed, 0x5f, 0x52, 0xe8, 0xcf, 0x56, 0xff, 0x89, 0xf7, 0x4e, 0xe9, 0x8f, 0xe9, 0x2a,
        0x36, 0x80, 0xb2, 0x62, 0xa3, 0x0f, 0x03, 0xf8, 0xef, 0xe8, 0xe8, 0x23, 0x69, 0xe3, 0x98, 0x4b
    };
    uint8_t rpmb_key_buffer_out[HSM_RPMB_BUFFER_LEN] = {0};

    ret = TEE_RPMB_KEY_Status();
    if (ret != TEE_SUCCESS) {
        SLogError("test failed, 0x%x.\n", ret);
        return ret;
    }

    ret = TEE_RPMB_FS_Format();
    if (ret != TEE_SUCCESS) {
        SLogError("test failed, 0x%x.\n", ret);
        return ret;
    }

    ret = TEE_RPMB_FS_Write((const char *)rpmb_file_name, (uint8_t *)rpmb_buffer_in, HSM_RPMB_BUFFER_LEN);
    if (ret != TEE_SUCCESS) {
        SLogError("test failed, 0x%x.\n", ret);
        return ret;
    }

    ret = TEE_RPMB_FS_Read((const char *)rpmb_file_name, (uint8_t *)rpmb_key_buffer_out,
                           HSM_RPMB_BUFFER_LEN, &out_len);
    if (ret != TEE_SUCCESS) {
        SLogError("test failed, 0x%x.\n", ret);
        return ret;
    }

    ret = memcmp(rpmb_buffer_in, rpmb_key_buffer_out, HSM_RPMB_BUFFER_LEN);
    if (ret != TEE_SUCCESS) {
        SLogError("test failed, 0x%x.\n", ret);
        return ret;
    }

    ret = TEE_RPMB_FS_Format();
    if (ret != TEE_SUCCESS) {
        SLogError("test failed, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC TEE_Result tee_rpmb_key_test(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = rpmb_key_test();
    if (ret != TEE_SUCCESS) {
        SLogError("rpmb key test failed, 0x%x.\n", ret);
    }

    params[0].value.a = ret;

    return ret;
}

STATIC TEE_Result tee_gen_rpmb_key(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t rpmb_ak[RPMB_BAK_WORD_LEN] = {0};
    uint8_t *rpmb_ak_context = (uint8_t *)(uintptr_t)rpmb_ak;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.size == 0) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = TEE_HSM_GenRpmbKey(0, rpmb_ak_context);
    if (ret != TEE_SUCCESS) {
        SLogError("gen rpmb key 0x%x.\n", ret);
        return ret;
    }

    ret = memcpy_s(params[0].memref.buffer, RPMB_BAK_SIZE, rpmb_ak_context, RPMB_BAK_SIZE);
    if (ret != EOK) {
        SLogError("memory copy failed, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    params[0].memref.size = RPMB_BAK_SIZE;

    return TEE_SUCCESS;
}

/* ----------------------------------------------------------------------------
 *   Trusted Application Entry Points
 * ---------------------------------------------------------------------------- */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    SLogTrace("RPMB KEY TA IN!\n");

    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        SLogError("Add caller ta failed, 0x%x.\n", ret);
        return ret;
    }

    SLogError("rpmb add caller ta success.\n");

    ret = AddCaller_CA_exec(ROOTSCAN_RPMB, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add rpmb ca root error");
        return ret;
    }

    ret = AddCaller_CA_exec(ROOTSCAN_RPMB, HWHIAIUSER_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add rpmb ca hwhiaiuser error, 0x%x.", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_FUZZ_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add fuzz ca error, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[OPEN_SESSION_PARA_NUM], void** sessionContext)
{
    SLogTrace("--TA_OpenSessionEntryPoint--\n");

    (void)paramTypes;
    (void)params;
    (void)sessionContext;

    return TEE_SUCCESS;
}

__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
    uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    SLogTrace("--TA_InvokeCommandEntryPoint, cmd_id=0x%x.\n", cmd_id);

    (void)sessionContext;
    (void)paramTypes;

    switch (cmd_id) {
        case RPMB_KEY_GEN:
            return tee_gen_rpmb_key(paramTypes, params);
        case RPMB_KEY_TEST:
            return tee_rpmb_key_test(paramTypes, params);
        default:
            SLogError("Unknown CMD ID: %x\n", cmd_id);
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *sessionContext)
{
    SLogTrace("--TA_CloseSessionEntryPoint--\n");

    (void)sessionContext;
}
