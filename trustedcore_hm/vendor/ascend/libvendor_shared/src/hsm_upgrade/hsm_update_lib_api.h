/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: update firmware libs api file
* Author: chenyao
* Create: 2020/4/6
*/

#ifndef HSM_UPDATE_LIB_API
#define HSM_UPDATE_LIB_API

#include <stdint.h>

uint32_t lib_secure_flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);
uint32_t lib_secure_flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);
uint32_t lib_secure_flash_erase(uint32_t offset, uint32_t length, uint32_t chip_id);
uint32_t lib_secure_img_verify(uint64_t nsecure_addr, uint32_t length,
    uint32_t chip_id, uint32_t img_id, uint64_t *img_addr, uint32_t pss_cfg);
uint32_t lib_secure_img_update(uint32_t img_index, uint32_t chip_id, uint32_t *slice);
uint32_t lib_secure_update_finish(uint32_t chip_id);
uint32_t lib_secure_version_get(uint32_t img_id, uint8_t *buffer, uint32_t buffer_size,
    uint32_t chip_id, uint32_t area_check);
uint32_t lib_secure_count_get(uint32_t *count, uint32_t chip_id);
uint32_t lib_secure_info_get(uint32_t flash_index, uint8_t *buffer, uint32_t *buffer_size, uint32_t chip_id);
uint32_t lib_secure_ufs_cnt_read(uint32_t *out_value, uint32_t chip_id);
uint32_t lib_secure_ufs_cnt_write(uint32_t in_value, uint32_t chip_id);
uint32_t lib_secure_verify_status_update(uint32_t chip_id, uint32_t img_id);
uint32_t lib_secure_sram_read(uint32_t offset, uint8_t *buf, uint32_t length, uint32_t chip_id);
uint32_t lib_upgrade_flash_read(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);
uint32_t lib_upgrade_flash_write(uint32_t offset, uint8_t *buffer, uint32_t length, uint32_t chip_id);
uint32_t lib_secure_sysctrl_read(uint32_t offset, uint32_t *val, uint32_t chip_id);
uint32_t lib_secure_sysctrl_write(uint32_t offset, uint32_t *val, uint32_t chip_id);
uint32_t lib_secure_img_sync(uint32_t chip_id, uint32_t img_id, uint32_t base_part, uint32_t baseline_flag);
uint32_t lib_root_key_get(uint8_t *buffer, uint32_t buffer_size);
uint32_t lib_get_cmdline_info(uint32_t dev_id, uint32_t *buffer, uint32_t buffer_size);
uint32_t lib_reflash_hilink_ram(uint32_t chip_id);
uint32_t lib_secure_part_read(uint32_t chip_id, uint32_t img_id, uint64_t *img_addr, uint32_t *length,
    uint32_t base_part);
uint32_t lib_secure_get_baseline_flag(uint32_t chip_id, uint32_t *flag);
uint32_t lib_secure_set_baseline_flag(uint32_t chip_id);
uint32_t lib_hboot1a_addr_get(uint32_t chip_id, uint32_t *image_addr, uint32_t *img_len);
uint32_t lib_get_efuse_nvcnt(uint32_t *addr, uint32_t len, uint32_t dev_id);
uint32_t lib_get_device_num(uint32_t *dev_num);
uint32_t lib_is_update_finished(uint32_t chip_id);
uint32_t lib_sync_flag_get(uint32_t chip_id, uint32_t *sync_flag);
uint32_t lib_secure_recovery_cnt_write(uint32_t chip_id);

#endif
