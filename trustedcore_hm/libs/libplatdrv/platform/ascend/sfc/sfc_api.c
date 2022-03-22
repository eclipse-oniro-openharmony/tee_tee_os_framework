/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: SFC driver api source file
* Author: huawei
* Create: 2020/3/25
*/
#include <register_ops.h>
#include <drv_module.h>
#include <sre_access_control.h>
#include <hmdrv_stub.h>
#include <drv_mem.h>
#include <sre_syscalls_id_ext.h>
#include <tee_log.h>
#include "tee_defines.h"

#include "driver_common.h"
#include "hsm_dev_id.h"
#include "sfc_driver.h"
#include "sfc_api.h"

#include "securec.h"

static uint32_t g_flash_buff_map_flag[DEV_NUM_MAX] = {
    FLASH_DATA_BUF_NOT_MAPPED, FLASH_DATA_BUF_NOT_MAPPED
};

uint64_t g_flash_buff[DEV_NUM_MAX] = { 0 };

STATIC uint32_t flash_params_check(uint32_t offset, uint32_t length, uint32_t chip_id)
{
    uint32_t ret;

    if ((length == 0) || (length > SPI_FLASH_SIZE) || (offset >= SPI_FLASH_SIZE)) {
        tloge("invalid parms, 0x%x, 0x%x.\n", length, offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if ((offset + length) >= SPI_FLASH_SIZE) {
        tloge("invalid parms, 0x%x, 0x%x.\n", length, offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t flash_wr_params_check(uint32_t offset,
    uint8_t *buffer, uint32_t length,
    uint32_t chip_id, bool check_buf)
{
    uint32_t ret;

    ret = flash_params_check(offset, length, chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (check_buf == false) {
        return TEE_SUCCESS; /* no need check buff. */
    }

    if (buffer == NULL) {
        tloge("invalid parms.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t flash_pre_operation(uint32_t offset,
    uint8_t *buffer, uint32_t length,
    uint32_t chip_id, bool check_buf)
{
    uint32_t ret;

    ret = flash_wr_params_check(offset, buffer, length, chip_id, check_buf);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (g_flash_buff_map_flag[chip_id] != FLASH_DATA_BUF_MAPPED) {
        ret = sre_mmap(SFC_DATA_STORE_PADDR_BASE + chip_id * SFC_CHIP_OFFSET,
                       FLASH_SECTOR_SIZE, (uintptr_t *)&g_flash_buff[chip_id],
                       secure, non_cache);
        if (ret != TEE_SUCCESS) {
            tloge("flash buf pa2va map failed, %d, 0x%x.\n", chip_id, ret);
            return ret;
        }

        g_flash_buff_map_flag[chip_id] = FLASH_DATA_BUF_MAPPED;
    }

    return get_spi_flash_index(chip_id);
}


uint32_t flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint32_t ret;
    uint32_t cfg;
    uint64_t chip_offset = (chip_id > 0) ? SFC_CHIP_OFFSET : 0;

    ret = flash_pre_operation(offset, buffer, length, chip_id, true);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    cfg = read32(SFC_REG_BUS_CONFIG1 + chip_offset);
    if ((cfg & BIT31) != 0) {
        tlogw("sfc bus read.\n");
        return sfc_bus_read(offset, buffer, length, chip_id);
    }

    tlogw("sfc cmd read.\n");

    return sfc_cmd_read(offset, buffer, length, chip_id);
}

uint32_t flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint32_t ret;

    ret = flash_pre_operation(offset, buffer, length, chip_id, true);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return sfc_cmd_write(offset, buffer, length, chip_id);
}

uint32_t flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id)
{
    uint32_t ret;

    if ((offset % (SPI_FLASH_SECTOR_SIZE) != 0) || (length % (SPI_FLASH_SECTOR_SIZE)) != 0) {
        tloge("Invalid len not align, 0x%x, 0x%x.\n", offset, length);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = flash_pre_operation(offset, NULL, length, chip_id, false);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    return sfc_cmd_erase(offset, length, chip_id);
}

uint32_t get_flash_info(uint8_t *out_flash_info, uint32_t len, uint32_t chip_id)
{
    uint32_t ret;
    uint32_t flash_id;
    uint32_t manu_id = ISSI_MANU_ID;
    uint32_t device_id = ISSI_DEVICE_ID;
    FLASHINFO *ptr_info = (FLASHINFO *)out_flash_info;

    if ((out_flash_info == NULL) || (len < sizeof(FLASHINFO)) || (chip_id > 1)) {
        tloge("flash info input params wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = get_device_id(&flash_id, 0, chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    get_manu_device_id(flash_id, &manu_id, &device_id);

    ptr_info->manufacturer_id = (uint16_t)manu_id;
    ptr_info->vendor_id = (uint16_t)manu_id;
    ptr_info->device_id = (uint16_t)device_id;
    ptr_info->flash_id = (uint64_t)(flash_id & SPI_DEVID_MASK);
    ptr_info->state = FLASH_STATE_OK;
    ptr_info->size = SPI_FLASH_SIZE;
    ptr_info->sector_cnt = SPI_FLASH_SIZE / SPI_FLASH_SECTOR_SIZE;

    return TEE_SUCCESS;
}

int sfc_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
    uint32_t ret;
    uint64_t *args = NULL;
    uint64_t buffer_addr;
    uint32_t offset;
    uint32_t length;
    uint32_t chip_id;

    if ((params == NULL) || (params->args == 0)) {
        tloge("err params in sfc syscall.\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    args = (uint64_t *)(uintptr_t)params->args;

    offset = args[ARRAY_INDEX0];
    length = args[ARRAY_INDEX1];
    chip_id = args[ARRAY_INDEX2];

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(SYSCALL_MDC_FLASH_ERASE, permissions, FLASH_GROUP_PERMISSION)
        ret = flash_erase(offset, length, chip_id);
        args[0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_MDC_FLASH_READ, permissions, FLASH_GROUP_PERMISSION)
        buffer_addr = args[ARRAY_INDEX3];
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = flash_read(offset, (uint8_t *)(uintptr_t)buffer_addr, length, chip_id);
        args[ARRAY_INDEX0] = ret;
        SYSCALL_END

        SYSCALL_PERMISSION(SYSCALL_MDC_FLASH_WRITE, permissions, FLASH_GROUP_PERMISSION)
        buffer_addr = args[ARRAY_INDEX3];
        ACCESS_CHECK_A64(buffer_addr, length);
        ACCESS_WRITE_RIGHT_CHECK(buffer_addr, length);
        ret = flash_write(offset, (uint8_t *)(uintptr_t)buffer_addr, length, chip_id);
        args[ARRAY_INDEX0] = ret;
        SYSCALL_END
    default:
        return TEE_ERROR_NOT_SUPPORTED;
    }

    return TEE_SUCCESS;
}

DECLARE_TC_DRV(
    sfc_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    sfc_syscall,
    NULL,
    NULL
);
