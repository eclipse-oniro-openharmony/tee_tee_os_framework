/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: mdc flash read write erase
 * Author: huawei
 * Create: 2020-04-16
 */
#include "tee_internal_api.h"
#include "tee_defines.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "securec.h"

#include "hsm_ta_public.h"
#include "hsm_flash_ta.h"
#include "hsm_update_lib_api.h"
#include "sfc_lib_api.h"

const SEC_FLASH_ADDRESS_INFO_S g_addr_info[] = {
    {flashboot,            FLASHBOOT_OFFSET},
    {hboot1a,              HBOOT1A_OFFSET},
    {hlink,                HLINK_OFFSET},
    {hboot1a_bak,          HBOOT1A_BAK_OFFSET},
    {hlink_bak,            HLINK_BAK_OFFSET},
    {hboot1b,              HBOOT1B_OFFSET},
    {hboot1b_bak,          HBOOT1B_BAK_OFFSET},
    {hboot2,               HBOOT2_OFFSET},
    {hboot2_bak,           HBOOT2_BAK_OFFSET},
    {ddr_img,              DDR_IMG_OFFSET},
    {ddr_img_bak,          DDR_IMG_BAK_OFFSET},
    {hsm_img,              HSM_IMG_OFFSET},
    {hsm_img_bak,          HSM_IMG_BAK_OFFSET},
    {lp_img,               IP_IMG_OFFSET},
    {lp_img_bak,           IP_IMG_BAK_OFFSET},
    {safety_img,           SAFETY_IMG_OFFSET},
    {safety_img_bak,       SAFETY_IMG_BAK_OFFSET},
    {syscfg_img,           SYSCFG_IMG_OFFSET},
    {syscfg_img_bak,       SYSCFG_IMG_BAK_OFFSET},
    {nve,                  NVE_OFFSET},
    {user_config,          USER_CONFIG_OFFSET},
    {img_upgrade_flag,     IMG_UPGRADE_FLG_OFFSET},
    {img_upgrade_flag_bak, IMG_UPGRADE_FLG_BAK_OFFSET},
    {mac_addr,             MAC_ADDR_OFFSET},
    {test_area,            TEST_AREA_OFFSET},
    {reserved_area,        RESERVED_AREA_OFFSET}
}; /* lint +e42 */

static uint32_t g_dev_id_max = 0;

STATIC uint32_t flash_dev_id_verify(uint32_t dev_id)
{
    if (dev_id > g_dev_id_max) {
        tloge("dev id invaild %d.\n", dev_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t flash_op_right_check(uint32_t dev_id, uint32_t flash_addr,
    uint32_t buf_len)
{
    uint32_t ret;

    ret = flash_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

#ifndef MDC_HSM_EQUIP
    if ((buf_len == 0) || (buf_len > FLASH_LEN_MAX)) {
        SLogError("buf len wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((flash_addr >= 0) && (flash_addr < FIRMWARE_END_ADDR)) {
        SLogError("flash addr wrong in firmware!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    /* combine TAG & MAC area when check */
    if (((flash_addr >= UPGRADE_TAG_START_ADDR) && (flash_addr < UPGRADE_MAC_END_ADDR)) ||
        (((flash_addr + buf_len) >= UPGRADE_TAG_START_ADDR) && ((flash_addr + buf_len) < UPGRADE_MAC_END_ADDR)) ||
        ((flash_addr < UPGRADE_TAG_START_ADDR) && ((flash_addr + buf_len) >= UPGRADE_MAC_END_ADDR))) {
        SLogError("flash addr wrong in mac/tag!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((flash_addr >= FLASH_LEN_MAX) || ((flash_addr + buf_len) >= FLASH_LEN_MAX)) {
        SLogError("flash addr out of flash len max!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
#endif

    return TEE_SUCCESS;
}

STATIC uint32_t mdc_flash_op_check(uint32_t dev_id, uint32_t area_subscript, uint32_t buf_len, const uint8_t *buffer)
{
    uint32_t ret;

    ret = flash_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (buffer == NULL) {
        SLogError("buffer is wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((buf_len == 0) || (buf_len > MAC_MAX_SIZE)) {
        SLogError("buf length is wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (area_subscript >= (sizeof(g_addr_info) / sizeof(SEC_FLASH_ADDRESS_INFO_S))) {
        SLogError("area flag is wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t flash_operation(uint32_t mode, uint32_t dev_id, uint32_t flash_addr, uint8_t *buffer, uint32_t buf_len)
{
    uint32_t ret;

    ret = flash_op_right_check(dev_id, flash_addr, buf_len);
    if (ret != TEE_SUCCESS) {
        SLogError("flash right check fail, 0x%x.\n", ret);
        return ret;
    }

    switch (mode) {
        case FLASH_OP_READ:
            return lib_secure_flash_read(flash_addr, buffer, buf_len, dev_id);
        case FLASH_OP_WRITE:
            return lib_secure_flash_write(flash_addr, buffer, buf_len, dev_id);
        case FLASH_OP_ERASE:
            return lib_secure_flash_erase(flash_addr, buf_len, dev_id);
        default:
            SLogError("flash ops not support, 0x%x.\n", mode);
            break;
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

STATIC uint32_t mdc_flash_operation(uint32_t mode,
    uint32_t dev_id, uint32_t area_subscript,
    uint8_t *buffer, uint32_t buf_len)
{
    uint32_t ret;

    ret = mdc_flash_op_check(dev_id, area_subscript, buf_len, buffer);
    if (ret != TEE_SUCCESS) {
        SLogError("flash right check fail, 0x%x.\n", ret);
        return ret;
    }

    if (mode == FLASH_OP_READ) {
        ret = lib_mdc_flash_read(g_addr_info[area_subscript].flash_addr, buffer, buf_len, dev_id);
    } else {
        ret = lib_mdc_flash_write(g_addr_info[area_subscript].flash_addr, buffer, buf_len, dev_id);
    }

    return ret;
}

STATIC uint32_t recovery_flag_operation(uint32_t dev_id, uint32_t buf_val)
{
    uint32_t ret;
    uint32_t flash_addr = RECOVERY_MODE_SET_ADDR;
    uint32_t buffer = buf_val;

    ret = flash_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_secure_flash_write(flash_addr, (uint8_t *)&buffer, sizeof(buffer), dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("lib secure flash write fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t recovery_flag_get(uint32_t dev_id, uint8_t *buffer, uint32_t buffer_len)
{
    uint32_t ret;
    uint32_t flash_addr = RECOVERY_MODE_SET_ADDR;

    ret = flash_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = lib_secure_flash_read(flash_addr, buffer, buffer_len, dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("lib secure flash read fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t recovery_status_set(uint32_t dev_id, uint32_t ops, uint32_t type)
{
    uint32_t ret;
    uint32_t upgrade_sync_flag;
    uint32_t recovery_area_flag;

    ret = flash_dev_id_verify(dev_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if ((ops != RECOVERY_UPGRADE) && (ops != RECOVERY_SYNC)) {
        SLogError("recovery ops status invalid, 0x%x.\n", ops);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((type != RECOVERY_PARTITION_MASTER) && (type != RECOVERY_PARTITION_SLAVE)) {
        SLogError("recovery type status invalid, 0x%x.\n", type);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    upgrade_sync_flag = (ops == RECOVERY_UPGRADE) ? RECOVERY_UPGRADE_FLAG : RECOVERY_SYNC_FLAG;

    /* write upgrade/sync flag to flash */
    ret = lib_secure_flash_write(RECOVERY_UPGRADE_SYNC_ADDR, (uint8_t *)&upgrade_sync_flag, sizeof(uint32_t), dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("lib secure flash write fail, 0x%x.\n", ret);
        return ret;
    }

    recovery_area_flag = (type == RECOVERY_PARTITION_MASTER) ?  \
                         RECOVERY_PARTITION_MASTER_FLAG : RECOVERY_PARTITION_SLAVE_FLAG;

    /* write partition master/slave flag to flash */
    ret = lib_secure_flash_write((uint32_t)RECOVERY_MASTER_SLAVE_ADDR,
                                 (uint8_t *)&recovery_area_flag, sizeof(uint32_t), dev_id);
    if (ret != TEE_SUCCESS) {
        SLogError("lib secure flash write fail, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t tee_sec_flash_erase(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = flash_operation(FLASH_OP_ERASE, params[PARAMS_NUM_0].value.a,
                          params[PARAMS_NUM_1].value.a, NULL, params[PARAMS_NUM_1].value.b);
    if (ret != TEE_SUCCESS) {
        SLogError("flash erase failed, 0x%x\n", ret);
        return ret;
    }

    SLogTrace("flash erase success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_sec_flash_write(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[PARAMS_NUM_2].memref.size == 0) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = flash_operation(FLASH_OP_WRITE,
                          params[PARAMS_NUM_0].value.a, params[PARAMS_NUM_1].value.a,
                          params[PARAMS_NUM_2].memref.buffer, params[PARAMS_NUM_2].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("write flash failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("write flash success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_sec_flash_read(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[PARAMS_NUM_2].memref.size == 0) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = flash_operation(FLASH_OP_READ,
                          params[PARAMS_NUM_0].value.a, params[PARAMS_NUM_1].value.a,
                          params[PARAMS_NUM_2].memref.buffer, params[PARAMS_NUM_2].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("read flash failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("read flash success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_mdc_flash_write(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_INPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[PARAMS_NUM_2].memref.size == 0) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = mdc_flash_operation(FLASH_OP_WRITE,
                              params[PARAMS_NUM_0].value.a, params[PARAMS_NUM_1].value.a,
                              params[PARAMS_NUM_2].memref.buffer, params[PARAMS_NUM_2].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("write mdc flash failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("write mdc flash success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_mdc_flash_read(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_MEMREF_OUTPUT,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (params[PARAMS_NUM_2].memref.size == 0) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = mdc_flash_operation(FLASH_OP_READ,
                              params[PARAMS_NUM_0].value.a, params[PARAMS_NUM_1].value.a,
                              params[PARAMS_NUM_2].memref.buffer, params[PARAMS_NUM_2].memref.size);
    if (ret != TEE_SUCCESS) {
        SLogError("read mdc flash failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("read mdc flash success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_recovery_flag_set(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = recovery_flag_operation(params[PARAMS_NUM_0].value.a, RECOVERY_FORCE_ENTER_FLAG);
    if (ret != TEE_SUCCESS) {
        SLogError("recovery flag set failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("recovery flag set success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_recovery_flag_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;
    uint32_t recovery_flag = 0;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_OUTPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = recovery_flag_get(params[PARAMS_NUM_0].value.a, (uint8_t *)&recovery_flag, sizeof(recovery_flag));
    if (ret != TEE_SUCCESS) {
        SLogError("recovery flag get failed, 0x%x.\n", ret);
        return ret;
    }

    params[PARAMS_NUM_1].value.a = recovery_flag;

    SLogTrace("recovery flag get success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_recovery_flag_clr(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = recovery_flag_operation(params[PARAMS_NUM_0].value.a, RECOVERY_UNFORCE_ENTER_FLAG);
    if (ret != TEE_SUCCESS) {
        SLogError("recovery flag clr failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("recovery flag clr success.\n");

    return TEE_SUCCESS;
}

STATIC uint32_t tee_recovery_status_set(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    TEE_Result ret;

    if (!check_param_type(paramTypes,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_VALUE_INPUT,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE)) {
        SLogError("Bad expected parameter types\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = recovery_status_set(params[PARAMS_NUM_0].value.a, params[PARAMS_NUM_1].value.a,
                              params[PARAMS_NUM_1].value.b);
    if (ret != TEE_SUCCESS) {
        SLogError("recovery status set failed, 0x%x.\n", ret);
        return ret;
    }

    SLogTrace("recovery status set success.\n");

    return TEE_SUCCESS;
}

/* ----------------------------------------------------------------------------
 *   Trusted Application Entry Points
 * ---------------------------------------------------------------------------- */
__attribute__((visibility ("default"))) TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result ret;

    ret = AddCaller_TA_all();
    if (ret != TEE_SUCCESS) {
        SLogError("flash addcaller ta failed, 0x%x.\n", ret);
        return ret;
    }

    tlogd("flash addcaller ta success.\n");

    ret = AddCaller_CA_exec(FLASH_CA_PATH, 0);
    if (ret != TEE_SUCCESS) {
        SLogError("add flash ca error, 0x%x.\n", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_FLASH_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add flash ca in kernel error, 0x%x.", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_FLASH_CA, HWHIAIUSER_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add flash ca in HWHIAUSERerror, 0x%x.", ret);
        return ret;
    }

    ret = AddCaller_CA_exec(HSM_FUZZ_CA, ROOT_UID);
    if (ret != TEE_SUCCESS) {
        SLogError("add fuzz ca error, 0x%x.", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

__attribute__((visibility ("default"))) TEE_Result TA_OpenSessionEntryPoint(uint32_t paramTypes,
    TEE_Param params[OPEN_SESSION_PARA_NUM], void **sessionContext)
{
    uint32_t dev_num = 1;
    TEE_Result ret;

    SLogTrace("--TA_OpenSessionEntryPoint--\n");

    (void)paramTypes;
    (void)params;
    (void)sessionContext;

    ret = lib_get_device_num(&dev_num);
    if (ret != TEE_SUCCESS) {
        SLogError("get device num fail, 0x%x.\n", ret);
        return ret;
    }

    g_dev_id_max = (dev_num > 1) ? 1 : 0;

    return TEE_SUCCESS;
}

__attribute__((visibility ("default"))) TEE_Result TA_InvokeCommandEntryPoint(void *sessionContext,
    uint32_t cmd_id, uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM])
{
    SLogTrace("--TA_InvokeCommandEntryPoint--\n");

    (void)sessionContext;

    switch (cmd_id) {
        case TEE_HSM_FLASH_WRITE:
            return tee_sec_flash_write(paramTypes, params);
        case TEE_HSM_FLASH_READ:
            return tee_sec_flash_read(paramTypes, params);
        case TEE_HSM_FLASH_ERASE:
            return tee_sec_flash_erase(paramTypes, params);
        case TEE_MDC_FLASH_READ:
            return tee_mdc_flash_read(paramTypes, params);
        case TEE_MDC_FLASH_WRITE:
            return tee_mdc_flash_write(paramTypes, params);
        case TEE_HSM_RECOVERY_FLAG_SET:
            return tee_recovery_flag_set(paramTypes, params);
        case TEE_HSM_RECOVERY_FLAG_GET:
            return tee_recovery_flag_get(paramTypes, params);
        case TEE_HSM_RECOVERY_FLAG_CLR:
            return tee_recovery_flag_clr(paramTypes, params);
        case TEE_HSM_RECOVERY_STATUS_SET:
            return tee_recovery_status_set(paramTypes, params);
        default:
            SLogError("Unknown CMD ID: %x\n", cmd_id);
            break;
    }

    return TEE_ERROR_NOT_SUPPORTED;
}

__attribute__((visibility ("default"))) void TA_CloseSessionEntryPoint(void *sessionContext)
{
    (void)sessionContext;
    SLogTrace("--TA_CloseSessionEntryPoint--\n");
}
