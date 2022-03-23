/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: update firmware source file
* Author: huawei
* Create: 2020/4/6
*/
#include <register_ops.h>
#include <tee_defines.h>
#include "tee_log.h"
#include "tee_bit_ops.h"
#include "drv_mem.h"

#include "securec.h"

#include "driver_common.h"
#include "hsm_dev_id.h"
#include "sfc_api.h"
#include "sfc_driver.h"
#include "sec_api.h"
#include "sec_a_hal.h"
#include "efuse_api.h"
#include "hsm_update_api.h"
#include "hsm_secure_rw.h"

static uint32_t g_img_baseline_flag[DEV_NUM_MAX] = { 0 };
static uint32_t g_img_sync_flag[DEV_NUM_MAX] = { HSM_SYNC_UNONE, HSM_SYNC_UNONE };

uint32_t secure_cal_hash(uint8_t *in_buf, uint32_t buf_len, uint8_t *hash)
{
    SEC_HASH_INFO_S hash_info;
    sec_bd_t bd;

    if (in_buf == NULL || buf_len > FIRMWARE_IMG_MAX_SIZE) {
        tloge("Invalid buf len, 0x%x.\n", buf_len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    hash_info.bd_addr = (uint64_t)(uintptr_t)bd.bd;
    hash_info.data_addr = (uint64_t)(uintptr_t)in_buf;
    hash_info.data_len = buf_len;
    hash_info.hash_type = SHA256;
    hash_info.mac_len = SHA256_OUT_WLEN;
    hash_info.result_addr = (uint64_t)(uintptr_t)hash;

    return sec_hash_simple(&hash_info);
}

uint32_t secure_flash_read(uint32_t chip_id, uint32_t flash_offset,
    uint8_t *buffer, uint32_t length)
{
    return flash_read(flash_offset, buffer, length, chip_id);
}

uint32_t secure_flash_write(uint32_t chip_id, uint32_t flash_offset,
    uint8_t *buffer, uint32_t length)
{
    return flash_write(flash_offset, buffer, length, chip_id);
}

uint32_t secure_flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id)
{
    return flash_erase(offset, length, chip_id);
}

/* get the number of flash, the count is fixed to 1 currently */
uint32_t secure_img_count_get(uint32_t chip_id, uint32_t *count)
{
    NO_USE_PARAMETER(chip_id);

    if (count != NULL) {
        *count = 1;
    }

    return TEE_SUCCESS;
}

uint32_t secure_ufs_reset_cnt_write(uint32_t chip_id, uint32_t in_value)
{
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    write32(UFS_CNT_DDR + (SFC_CHIPOFFSET * chip_id), in_value);

    return TEE_SUCCESS;
}

uint32_t secure_recovery_reset_cnt_write(uint32_t chip_id)
{
    uint32_t val;
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    val = read32(RECOVERY_CNT_DDR + SFC_CHIPOFFSET * chip_id);
    val &= RECOVERY_CLR_MASK;

    write32(RECOVERY_CNT_DDR + SFC_CHIPOFFSET * chip_id, val);

    return TEE_SUCCESS;
}

uint32_t secure_root_key_get(uint8_t *root_key, uint32_t key_size)
{
    if (key_size != ROOT_KEY_LEN) {
        tloge("invalid root key size, 0x%x.\n", key_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    return sfc_bus_read(HBOOT1_A_M + ROOTKEY_OFFSET, root_key, key_size, 0);
}

uint32_t secure_sysctrl_read(uint32_t chip_id, uint32_t offset, uint32_t *val)
{
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (offset > SYSCTRL_REG_SIZE) {
        tloge("read sram param err, 0x%x.\n", offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *val = read32(SYSCTRL_REG_BASE + offset + (SFC_CHIPOFFSET * chip_id));

    return TEE_SUCCESS;
}

uint32_t secure_sysctrl_write(uint32_t chip_id, uint32_t offset, uint32_t *val)
{
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    if (offset > SYSCTRL_REG_SIZE) {
        tloge("write sram param err, 0x%x.\n", offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    write32(SYSCTRL_REG_BASE + offset + (SFC_CHIPOFFSET * chip_id), *val);

    return TEE_SUCCESS;
}

/* get boot partitions info of img */
uint32_t secure_cmdline_get(uint32_t chip_id, uint32_t *buff, uint32_t size)
{
    uint32_t ret;

    NO_USE_PARAMETER(size);

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *buff = read32(CMDLINE_OFFSET + (SFC_CHIPOFFSET * chip_id));

    return TEE_SUCCESS;
}

uint32_t secure_get_efuse_nvcnt(uint32_t chip_id, uint64_t addr, uint32_t len)
{
    uint32_t *ptr = (uint32_t *)(uintptr_t)addr;
    uint32_t ret;

    if (len < EFUSE_NVCNT_LEN_4BYTES) {
        tloge("get efuse nvcnt params wrong!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *ptr = read32(EFUSE_L2NVCNT_OFFSET + (SFC_CHIPOFFSET * chip_id));

    return TEE_SUCCESS;
}

uint32_t secure_ufs_reset_cnt_read(uint32_t chip_id, uint32_t *out_value)
{
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *out_value = read32(UFS_CNT_DDR + (SFC_CHIPOFFSET * chip_id));

    return TEE_SUCCESS;
}

uint32_t secure_sram_read(uint32_t chip_id, uint32_t offset, uint8_t *buf, uint32_t length)
{
    uint64_t base_addr = (chip_id == 0) ? SRAM0_CTRL_BASE_ADDR : SRAM1_CTRL_BASE_ADDR;
    uint8_t *pos = NULL;
    uint32_t pos_len = length;
    int ret;

    if ((length == 0) || (length > L3_SRAM_MAX_SIZE) || (offset > L3_SRAM_MAX_SIZE)) {
        tloge("Invalid parms, 0x%x, 0x%x.\n", length, offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (length + offset > L3_SRAM_MAX_SIZE) {
        tloge("Invalid parms, 0x%x, 0x%x.\n", length, offset);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    pos = (uint8_t *)(uintptr_t)(base_addr + offset);

    ret = memcpy_s(buf, length, pos, pos_len);
    if (ret != EOK) {
        tloge("read sram fail, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

STATIC uint32_t secure_sram_write(uint32_t chip_id, uint32_t offset,
    uint8_t *buf, uint32_t length)
{
    uint64_t base_addr = (chip_id == 0) ? SRAM0_CTRL_BASE_ADDR : SRAM1_CTRL_BASE_ADDR;
    uint8_t *pos = NULL;
    int ret;

    pos = (uint8_t *)(uintptr_t)(base_addr + offset);

    ret = memcpy_s(pos, length, buf, length);
    if (ret != EOK) {
        tloge("write sram fail, 0x%x.\n", ret);
        return TEE_ERROR_BAD_STATE;
    }

    return TEE_SUCCESS;
}

/* get flash basic info, such as flash model_name and deviceID */
uint32_t secure_img_info_get(uint32_t chip_id, uint32_t flash_index,
    uint8_t *buffer, uint32_t *buffer_size)
{
    uint32_t ret;

    NO_USE_PARAMETER(flash_index);

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = get_flash_info(buffer, sizeof(FLASHINFO), chip_id);
    if (ret != TEE_SUCCESS) {
        tloge("get flash info fail, 0x%x\n", ret);
        return ret;
    }

    *buffer_size = sizeof(FLASHINFO);

    return TEE_SUCCESS;
}

/* get the basic hash tag value */
uint32_t secure_get_baseline_flag(uint32_t chip_id, uint32_t *flag)
{
    uint32_t ret;

    if (flag == NULL) {
        tloge("invalid flag buf.n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *flag = g_img_baseline_flag[chip_id];

    return TEE_SUCCESS;
}

/* set the basic hash tag value */
uint32_t secure_set_baseline_flag(uint32_t chip_id)
{
    uint32_t ret;

    NO_USE_PARAMETER(chip_id);

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    g_img_baseline_flag[chip_id] = 1;

    return TEE_SUCCESS;
}

uint32_t secure_get_sync_flag(uint32_t chip_id, uint32_t *sync_flag)
{
    uint32_t ret;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    *sync_flag = g_img_sync_flag[chip_id];

    g_img_sync_flag[chip_id] = HSM_SYNC_DONE;

    return TEE_SUCCESS;
}

uint32_t secure_reflash_hilink(uint32_t chip_id)
{
    int res;
    uint32_t ret;
    uintptr_t secure_vaddr = 0;

    ret = drv_dev_id_verify(chip_id);
    if (ret != TEE_SUCCESS) {
        return ret;
    }

    ret = (uint32_t)sre_mmap(HISS_SEC_DDR + (chip_id * SFC_CHIP_OFFSET), HILINK_SIZE,
                             (uintptr_t *)&secure_vaddr, secure, non_cache);
    if (ret != TEE_SUCCESS) {
        tloge("mmap secure addr failed, 0x%x.\n", ret);
        return ret;
    }

    ret = flash_read(HILINK_M, (uint8_t *)secure_vaddr, HILINK_SIZE, chip_id);
    if (ret != TEE_SUCCESS) {
        goto exit;
    }

    ret = secure_sram_write(chip_id, HILINK_SRAM_OFFSET, (uint8_t *)secure_vaddr, HILINK_SRAM_SIZE);
    if (ret != TEE_SUCCESS) {
        goto exit;
    }

exit:
    res = sre_unmap(secure_vaddr, HILINK_SIZE);
    if (res != TEE_SUCCESS) {
        tloge("sre unmap secure addr failed, 0x%x.\n", res);
        return (uint32_t)res;
    }

    return ret;
}
