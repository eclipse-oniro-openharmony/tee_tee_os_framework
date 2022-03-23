/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: firmware upgrade ta api function
 * Author: chenyao
 * Create: 2020-09-15
 */

#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"

#include "firmware_upgrade_api.h"
#include "firmware_upgrade.h"
#include "firmware_upgrade_ta_api.h"

uint32_t tee_sec_img_verify(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint64_t buffer_addr;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    buffer_addr = (((uint64_t)(params[FLASH_PARAM_INDEX2].value.b) << SHIFT_SIZE_32BIT) |
                              (params[FLASH_PARAM_INDEX2].value.a));
    ret = sec_img_verify(buffer_addr, params[1].value.b, params[0].value.a, params[1].value.a, params[0].value.b);
    if (ret != TEE_SUCCESS) {
        SLogError("img verify failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("img verify success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_img_update(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_img_update(params[0].value.a, params[1].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("img update failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("img update success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_update_finish(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_update_finish(params[0].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("img update finish failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("img update finish success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_img_sync_entry(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_img_sync_entry(params[0].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("img sync failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("img sync success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_rim_update(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[1].memref.size == 0) {
        SLogError("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_rim_update(params[0].value.a, params[1].memref.buffer, params[1].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("rim update failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("rim update success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_img_version_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[FLASH_PARAM_INDEX2].memref.size == 0) {
        SLogError("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_img_version_get(params[0].value.a, params[1].value.a,
                              params[FLASH_PARAM_INDEX2].memref.buffer, params[FLASH_PARAM_INDEX2].memref.size,
                              params[1].value.b);
    if (ret != TEE_SUCCESS) {
        SLogError("get img version failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("get img version success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_img_count_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t count = 0;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_img_count_get(params[0].value.a, &count);
    if (ret != TEE_SUCCESS) {
        SLogError("get img count failed, 0x%x.\n", ret);
        return ret;
    }

    params[1].value.a = count;

    SLogTrace("get img count success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_img_info_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[FLASH_PARAM_INDEX2].memref.size == 0) {
        SLogError("Bad expected parameter.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_img_info_get(params[0].value.a, params[1].value.a,
                           (uint8_t *)params[FLASH_PARAM_INDEX2].memref.buffer,
                           params[FLASH_PARAM_INDEX2].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("get img info failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("get img info success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_ufs_cnt_read(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    uint32_t ufs_out_value = 0;
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_ufs_cnt_read(params[0].value.a, &ufs_out_value);
    if (ret != TEE_SUCCESS) {
        SLogError("get ufs cnt failed, 0x%x.\n", ret);
        return ret;
    }

    params[1].value.a = ufs_out_value;

    SLogTrace("get img info success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_ufs_cnt_write(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_ufs_cnt_write(params[0].value.a, params[1].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("write ufs cnt failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("write ufs cnt success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_recovery_cnt_reset(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_recovery_cnt_reset(params[0].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("recovery cnt reset failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("recovery cnt reset success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_cnt_clear(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_cnt_clear(params[0].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("cnt clear reset failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("cnt clear success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_sec_img_sync_before_upgrade(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = sec_img_sync_before_upgrade(params[0].value.a);
    if (ret != TEE_SUCCESS) {
        SLogError("img sync before upgrade failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("img sync before upgrade success.\n");

    return TEE_SUCCESS;
}

uint32_t tee_get_cmdline_info(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t ufs_out_value = 0;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_cmdline_info(params[0].value.a, &ufs_out_value, sizeof(ufs_out_value));
    if (ret != TEE_SUCCESS) {
        SLogError("get cmdline info failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("get cmdline info success.\n");

    params[1].value.a = ufs_out_value;

    return TEE_SUCCESS;
}

uint32_t tee_get_efuse_nvcnt(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types, 0x%x.\n", paramTypes);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[0].memref.size < EFUSE_NVCNT_LEN_4BYTES) {
        SLogError("Bad expected parameter, 0x%x.\n", params[0].memref.size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_efuse_nvcnt(params[1].value.a, params[0].memref.buffer, params[0].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("get efuse nvcnt failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("get efuse nvcnt success.\n");

    return TEE_SUCCESS;
}
