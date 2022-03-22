/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: efuse api source file
* Author: huawei
* Create: 2019/09/18
*/
#include "tee_log.h"
#include "tee_defines.h"
#include <register_ops.h>
#include "tee_bit_ops.h"
#include "drv_param_type.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "drv_module.h"
#include <hmdrv_stub.h>

#include "securec.h"

#include "driver_common.h"
#include "efuse.h"
#include "efuse_internal_api.h"
#include "efuse_api.h"

STATIC uint32_t verify_efuse_block_num(uint32_t efuse_block_num)
{
    if ((efuse_block_num != EFUSE_BLOCK_NUM0) && (efuse_block_num != EFUSE_BLOCK_NUM1)) {
        tloge("Invalid efuse block num, 0x%x!\n", efuse_block_num);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

uint32_t write_efuse_api(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
                         uint8_t *input, uint32_t dev_id)
{
    uint32_t ret;

    if ((input == NULL) || (dest_size == 0)) {
        tloge("Invalid input/size param, 0x%x!\n", dest_size);
        return ERR_EFUSE_WRITE_INPUT_PARAM;
    }

    ret = verify_efuse_block_num(efuse_block_num);
    if (ret != TEE_SUCCESS) {
        return ERR_EFUSE_BLOCK_NUM_INPUT;
    }

    ret = itrustee_write_efuse(efuse_block_num, start_bit, dest_size, input, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Write efuse failed, 0x%x.\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t burn_efuse_api(uint32_t efuse_block_num, uint32_t dev_id)
{
    uint32_t ret;

    ret = verify_efuse_block_num(efuse_block_num);
    if (ret != TEE_SUCCESS) {
        return ERR_EFUSE_BURN_INPUT_PARAM;
    }

    ret = itrustee_burn_efuse(efuse_block_num, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Burn efuse failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t check_efuse_api(uint32_t efuse_block_num, uint32_t start_bit, uint32_t dest_size,
                         uint8_t *input, uint32_t dev_id)
{
    uint32_t ret;

    if ((dest_size == 0) || (input == NULL)) {
        tloge("check efuse input/size/out_flag param wrong!\n");
        return ERR_EFUSE_CHECK_INPUT_PARAM;
    }

    ret = verify_efuse_block_num(efuse_block_num);
    if (ret != TEE_SUCCESS) {
        return ERR_EFUSE_CHECK_INPUT_PARAM;
    }

    ret = itrustee_efuse_check(efuse_block_num, start_bit, dest_size, input, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Check efuse failed, 0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t control_efuse_flash_power_api(uint32_t onoff)
{
    if ((onoff != EFUSE_FLASH_POWER_OFF) && (onoff != EFUSE_FLASH_POWER_ON)) {
        tloge("efuse flash power input param wrong!\n");
        return ERR_EFUSE_FLASH_POWER_INPUT_PARAM;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t efuse_update_nv_cnt(uint32_t nv_cnt, uint32_t dev_id)
{
    uint32_t ret;

    ret = bisr_reset(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Bisr reset start fail, 0x%x\n", ret);
        return ret;
    }

    ret = write_efuse_api(EFUSE_BLOCK_NUM1, EFUSE_NVCNT_START, EFUSE_NVCNT_LEN, (uint8_t *)&nv_cnt, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Efuse write nv cnt fail, 0x%x\n", ret);
        return ret;
    }

    ret = burn_efuse_api(EFUSE_BLOCK_NUM1, dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Efuse burn nv cnt fail, 0x%x\n", ret);
        return ret;
    }

    ret = bisr_reset(dev_id);
    if (ret != TEE_SUCCESS) {
        tloge("Bisr reset end fail,0x%x\n", ret);
        return ret;
    }

    return TEE_SUCCESS;
}

uint32_t efuse_check_ns_forbid(uint32_t dev_id)
{
    uint32_t ret;
    uint64_t base = 0;

    ret = get_efuse_base_addr(dev_id, &base);
    if (ret != TEE_SUCCESS) {
        tloge("Get base addr failed, 0x%x\n", dev_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = read32(base + EFUSE_NS_FORBID);
    if (ret == 0x0) {
        return TEE_ERROR_BAD_STATE; /* ns forbid flag is not set */
    }

    return TEE_SUCCESS; /* ns forbid flag is set */
}

STATIC uint32_t efuse_check_nv_cnt(uint32_t nv_cnt, uint32_t dev_id)
{
    uint32_t hw_nvcnt;
    uint64_t base = 0;
    uint32_t ret;

    ret = get_efuse_base_addr(dev_id, &base);
    if (ret != TEE_SUCCESS) {
        tloge("Get base addr failed, 0x%x\n", dev_id);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    hw_nvcnt = read32(base + EFUSE_L2NVCNT);
    if (hw_nvcnt != nv_cnt) {
        return TEE_ERROR_BAD_STATE; /* nv cnt is not equal as check value */
    }

    return TEE_SUCCESS;
}

static void efuse_syscall_fill(uint64_t *args, uint32_t *efuse_block_num, uint32_t *start_bit,
                               uint32_t *dest_size, uint32_t *input_buf_len)
{
    *efuse_block_num = args[0];
    *start_bit = args[1];
    *dest_size = args[ARRAY_INDEX2];
    *input_buf_len = args[ARRAY_INDEX5];
}

int efuse_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint64_t *args = NULL;
    uint32_t efuse_block_num, start_bit, dest_size, input_buf_len;
    uint64_t input;
    uint32_t dev_id;

    if ((params == NULL) || (params->args == 0)) {
        return TEE_ERROR_BAD_PARAMETERS;
    }
    args = (uint64_t *)(uintptr_t)params->args;
    input = GET_64BIT_ADDR(args[ARRAY_INDEX3], args[ARRAY_INDEX4]);
    efuse_syscall_fill(args, &efuse_block_num, &start_bit, &dest_size, &input_buf_len);

    if ((swi_id == SYSCALL_HSM_EFUSE_CHECK) && ((input_buf_len * BYTE_TO_BIT) < dest_size)) {
        tloge("Invalid buffer length, 0x%x, 0x%x\n", input_buf_len, dest_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SYSCALL_HSM_EFUSE_WRITE, permissions, HSM_EFUSE_GROUP_PERMISSION)
        ACCESS_CHECK_A64(input, input_buf_len);
        ACCESS_READ_RIGHT_CHECK(input, input_buf_len);
        dev_id = args[ARRAY_INDEX6];
        args[0] = write_efuse_api(efuse_block_num, start_bit, dest_size, (uint8_t *)(uintptr_t)input, dev_id);
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_HSM_EFUSE_BURN, permissions, HSM_EFUSE_GROUP_PERMISSION)
        dev_id = args[1];
        args[0] = burn_efuse_api(efuse_block_num, dev_id);
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_HSM_EFUSE_CHECK, permissions, HSM_EFUSE_GROUP_PERMISSION)
        ACCESS_CHECK_A64(input, input_buf_len);
        ACCESS_READ_RIGHT_CHECK(input, input_buf_len);
        dev_id = args[ARRAY_INDEX6];
        args[0] = check_efuse_api(efuse_block_num, start_bit, dest_size, (uint8_t *)(uintptr_t)input, dev_id);
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_HSM_EFUSE_NV_CNT_BURN, permissions, HSM_EFUSE_GROUP_PERMISSION)
        uint32_t nv_cnt = args[0];
        dev_id = args[1];
        args[0] = efuse_update_nv_cnt(nv_cnt, dev_id);
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_HSM_EFUSE_NV_CNT_CHECK, permissions, HSM_EFUSE_GROUP_PERMISSION)
        uint32_t nv_cnt = args[0];
        dev_id = args[1];
        args[0] = efuse_check_nv_cnt(nv_cnt, dev_id);
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_HSM_EFUSE_NS_FORIBID_CHECK, permissions, HSM_EFUSE_GROUP_PERMISSION)
        dev_id = args[0];
        args[0] = efuse_check_ns_forbid(dev_id);
        SYSCALL_END
    default:
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

DECLARE_TC_DRV(
    efuse_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    efuse_syscall,
    NULL,
    NULL
);
