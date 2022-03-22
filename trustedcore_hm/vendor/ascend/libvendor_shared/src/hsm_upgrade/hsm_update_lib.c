/*
* Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
* Description: firmware update libs source file
* Author: huawei
* Create: 2019/4/6
*/

#include "sre_syscalls_id_ext.h"
#include "hmdrv.h"

#include "syscall_api_common.h"
#include "hsm_update_lib_api.h"

uint32_t lib_secure_flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = (uint64_t)(uintptr_t)buffer;
    args[ARRAY_INDEX3] = length;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_FLASH_READ, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = (uint64_t)(uintptr_t)buffer;
    args[ARRAY_INDEX3] = length;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_FLASH_WRITE, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX3] = length;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_FLASH_ERASE, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_img_verify(uint64_t nsecure_addr, uint32_t length,
    uint32_t chip_id, uint32_t img_id, uint64_t *img_addr, uint32_t pss_cfg)
{
    uint64_t args[ARRAY_INDEX8] = {0};

    args[ARRAY_INDEX0] = img_id;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)nsecure_addr);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)nsecure_addr);
    args[ARRAY_INDEX3] = length;
    args[ARRAY_INDEX4] = chip_id;
    args[ARRAY_INDEX5] = upper_32_bits((uintptr_t)img_addr);
    args[ARRAY_INDEX6] = lower_32_bits((uintptr_t)img_addr);
    args[ARRAY_INDEX7] = pss_cfg;

    return hm_drv_call(SYSCALL_SECURE_IMG_VERIFY, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_verify_status_update(uint32_t chip_id, uint32_t img_id)
{
    uint64_t args[ARRAY_INDEX8] = {0};

    args[ARRAY_INDEX0] = img_id;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_VERIFY_STATUS_UPDATE, args, ARRAY_SIZE(args));
}
uint32_t lib_secure_img_update(uint32_t img_index, uint32_t chip_id, uint32_t *slice)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = img_index;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)slice);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)slice);
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_IMG_UPDATE, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_update_finish(uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_UPDATE_FINISH, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_version_get(uint32_t img_id, uint8_t *buffer, uint32_t buffer_size,
    uint32_t chip_id, uint32_t area_check)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = img_id;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX3] = buffer_size;
    args[ARRAY_INDEX4] = chip_id;
    args[ARRAY_INDEX5] = area_check;

    return hm_drv_call(SYSCALL_SECURE_VERSION_GET, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_count_get(uint32_t *count, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)count);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)count);
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_COUNT_GET, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_info_get(uint32_t flash_index, uint8_t *buffer, uint32_t *buffer_size, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = flash_index;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX3] = upper_32_bits((uintptr_t)buffer_size);
    args[ARRAY_INDEX4] = chip_id;
    args[ARRAY_INDEX5] = lower_32_bits((uintptr_t)buffer_size);

    return hm_drv_call(SYSCALL_SECURE_INFO_GET, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_ufs_cnt_read(uint32_t *out_value, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)out_value);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)out_value);
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_UFS_CNT_READ, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_ufs_cnt_write(uint32_t in_value, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = in_value;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_UFS_CNT_WRITE, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_recovery_cnt_write(uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_RECOVERY_CNT_WRITE, args, ARRAY_SIZE(args));
}

/* sram read */
uint32_t lib_secure_sram_read(uint32_t offset, uint8_t *buf, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)buf);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)buf);
    args[ARRAY_INDEX3] = length;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_UPGRADE_SRAM_READ, args, ARRAY_SIZE(args));
}

/* read flash api for imgs upgrade */
uint32_t lib_upgrade_flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX3] = length;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_UPGRADE_FLASH_READ, args, ARRAY_SIZE(args));
}

/* write flash api for imgs upgrade */
uint32_t lib_upgrade_flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX3] = length;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_UPGRADE_FLASH_WRITE, args, ARRAY_SIZE(args));
}

/* sysctrl read api */
uint32_t lib_secure_sysctrl_read(uint32_t offset, uint32_t *val, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)val);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)val);
    args[ARRAY_INDEX3] = 0x0;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_UPGRADE_RESET_CNT_READ, args, ARRAY_SIZE(args));
}

/* sysctrl write api */
uint32_t lib_secure_sysctrl_write(uint32_t offset, uint32_t *val, uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = offset;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)val);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)val);
    args[ARRAY_INDEX3] = 0x0;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_UPGRADE_RESET_CNT_WRITE, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_img_sync(uint32_t chip_id, uint32_t img_id, uint32_t base_part,
    uint32_t baseline_flag)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = img_id;
    args[ARRAY_INDEX1] = base_part;
    args[ARRAY_INDEX2] = baseline_flag;
    args[ARRAY_INDEX3] = 0x0;
    args[ARRAY_INDEX4] = chip_id;
    args[ARRAY_INDEX5] = 0x0;

    return hm_drv_call(SYSCALL_SECURE_IMG_SYNC, args, ARRAY_SIZE(args));
}

uint32_t lib_root_key_get(uint8_t *buffer, uint32_t buffer_size)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX3] = buffer_size;

    return hm_drv_call(SYSCALL_SECURE_ROOTKEY_GET, args, ARRAY_SIZE(args));
}
uint32_t lib_get_cmdline_info(uint32_t dev_id, uint32_t *buffer, uint32_t buffer_size)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = dev_id;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)buffer);
    args[ARRAY_INDEX3] = buffer_size;

    return hm_drv_call(SYSCALL_SECURE_CMDLINE_GET, args, ARRAY_SIZE(args));
}

uint32_t lib_reflash_hilink_ram(uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_REFLASH_HILINK, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_part_read(uint32_t chip_id, uint32_t img_id, uint64_t *img_addr,
    uint32_t *length, uint32_t base_part)
{
    uint64_t args[ARRAY_INDEX8] = { 0 };

    args[ARRAY_INDEX0] = img_id;
    args[ARRAY_INDEX1] = upper_32_bits((uintptr_t)length);
    args[ARRAY_INDEX2] = lower_32_bits((uintptr_t)length);
    args[ARRAY_INDEX3] = base_part;
    args[ARRAY_INDEX4] = chip_id;
    args[ARRAY_INDEX5] = upper_32_bits((uintptr_t)img_addr);
    args[ARRAY_INDEX6] = lower_32_bits((uintptr_t)img_addr);

    return hm_drv_call(SYSCALL_SECURE_PART_READ, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_get_baseline_flag(uint32_t chip_id, uint32_t *flag)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX4] = chip_id;
    args[ARRAY_INDEX1] = (uint64_t)(uintptr_t)flag;

    return hm_drv_call(SYSCALL_SECURE_GET_BLFLAG, args, ARRAY_SIZE(args));
}

uint32_t lib_secure_set_baseline_flag(uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_SET_BLFLAG, args, ARRAY_SIZE(args));
}

uint32_t lib_hboot1a_addr_get(uint32_t chip_id, uint32_t *image_addr, uint32_t *img_len)
{
    uint64_t args[ARRAY_INDEX8] = { 0 };

    args[ARRAY_INDEX1] = (uint64_t)(uintptr_t)(image_addr);
    args[ARRAY_INDEX2] = (uint64_t)(uintptr_t)(img_len);
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_HBOOT_TRANS, args, ARRAY_SIZE(args));
}

uint32_t lib_is_update_finished(uint32_t chip_id)
{
    uint64_t args[ARRAY_INDEX8] = { 0 };

    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_SECURE_UPDATE_STATUS, args, ARRAY_SIZE(args));
}

uint32_t lib_get_efuse_nvcnt(uint32_t *addr, uint32_t len, uint32_t dev_id)
{
    uint64_t args[ARRAY_INDEX8] = { 0 };

    args[ARRAY_INDEX0] = (uint64_t)dev_id;
    args[ARRAY_INDEX1] = (uint64_t)(uintptr_t)addr;
    args[ARRAY_INDEX2] = (uint64_t)len;

    return hm_drv_call(SYSCALL_GET_EFUSE_NVCNT, args, ARRAY_SIZE(args));
}

uint32_t lib_sync_flag_get(uint32_t chip_id, uint32_t *sync_flag)
{
    uint64_t args[ARRAY_INDEX6] = {0};

    args[ARRAY_INDEX0] = (uint64_t)(uintptr_t)sync_flag;
    args[ARRAY_INDEX4] = chip_id;

    return hm_drv_call(SYSCALL_GET_SYNC_FLAG, args, ARRAY_SIZE(args));
}

uint32_t lib_get_device_num(uint32_t *dev_num)
{
    uint64_t args[ARRAY_INDEX8] = { 0 };

    args[ARRAY_INDEX0] = (uint64_t)(uintptr_t)(dev_num);

    return hm_drv_call(SYSCALL_GET_DEV_NUM, args, ARRAY_SIZE(args));
}
