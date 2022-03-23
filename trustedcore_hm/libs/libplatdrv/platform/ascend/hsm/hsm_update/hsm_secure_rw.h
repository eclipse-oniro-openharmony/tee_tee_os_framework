/*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
* Description: secure read and write head file
* Author: huawei
* Create: 2021/09/23
*/

#ifndef HSM_SECURE_RW_H
#define HSM_SECURE_RW_H

#include <stdint.h>

uint32_t secure_cal_hash(uint8_t *in_buf, uint32_t buf_len, uint8_t *hash);

uint32_t secure_flash_read(uint32_t chip_id, uint32_t flash_offset,
    uint8_t *buffer, uint32_t length);

uint32_t secure_flash_write(uint32_t chip_id, uint32_t flash_offset,
    uint8_t *buffer, uint32_t length);

uint32_t secure_flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id);

uint32_t secure_img_count_get(uint32_t chip_id, uint32_t *count);

uint32_t secure_ufs_reset_cnt_write(uint32_t chip_id, uint32_t in_value);

uint32_t secure_recovery_reset_cnt_write(uint32_t chip_id);

uint32_t secure_root_key_get(uint8_t *root_key, uint32_t key_size);

uint32_t secure_sysctrl_read(uint32_t chip_id, uint32_t offset, uint32_t *val);

uint32_t secure_sysctrl_write(uint32_t chip_id, uint32_t offset, uint32_t *val);

uint32_t secure_cmdline_get(uint32_t chip_id, uint32_t *buff, uint32_t size);

uint32_t secure_get_efuse_nvcnt(uint32_t chip_id, uint64_t addr, uint32_t len);

uint32_t secure_ufs_reset_cnt_read(uint32_t chip_id,  uint32_t *out_value);

uint32_t secure_get_sync_flag(uint32_t chip_id, uint32_t *sync_flag);

uint32_t secure_sram_read(uint32_t chip_id, uint32_t offset, uint8_t *buf, uint32_t length);

uint32_t secure_img_info_get(uint32_t chip_id, uint32_t flash_index,
    uint8_t *buffer, uint32_t *buffer_size);

uint32_t secure_img_info_get(uint32_t chip_id, uint32_t flash_index,
    uint8_t *buffer, uint32_t *buffer_size);

uint32_t secure_get_baseline_flag(uint32_t chip_id, uint32_t *flag);

uint32_t secure_set_baseline_flag(uint32_t chip_id);

uint32_t secure_reflash_hilink(uint32_t chip_id);

#endif
