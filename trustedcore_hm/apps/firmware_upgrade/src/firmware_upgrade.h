/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: hsm firmware safety upgrade internal file
 * Author: chenyao
 * Create: 2020-06-30
 */
#ifndef FIRMWARE_UPGRADE_H
#define FIRMWARE_UPGRADE_H

#include <stdint.h>

#define SECURE_IMAGE_MAX_SIZE                           0x300000
#define SECURE_IMAGE_MIN_SIZE                           0x2100
/* 1:hisserika.bin
 * 2:silerika.bin
 * 3:lperika.bin
 * 4:lpddr_mcu.bin
 * 5:AS610_HBOOT2_UEFI.fd
 * 6:HBOOT1_b.bin
 * 7:HBOOT1_a.bin
 * 8:HiLinkFirmware.bin
 * 9:sysBaseConfig.bin
 */
#define SECURE_IMAGE_INDEX_MAX_SIZE                     9
#define SECURE_RIM_INFO_LEN                             544
#define NSECURE_IMAGE_PADDR_START                       0x31D00000
#define FLASH_INDEX_MAX                                 1
#define PSS_FLAG                                        1
#define FLASH_PARAM_INDEX2                              2
#define SHIFT_SIZE_32BIT                                32
#define IMG_VERSION_LEN                                 16

uint32_t firmware_dev_id_verify(uint32_t dev_id);
uint32_t soc_img_verify_para_check(uint64_t nsecure_addr, uint32_t length, uint32_t dev_id, uint32_t img_id,
    uint32_t pss_cfg);
uint32_t soc_img_update_para_check(uint32_t dev_id, uint32_t img_index);
uint32_t rim_update_para_check(uint32_t dev_id, uint8_t *rim_info, uint32_t rim_len);
uint32_t img_info_get_para_check(uint32_t dev_id, uint32_t flash_index, uint8_t *buffer, uint32_t buffer_size);
uint32_t img_version_get_para_check(uint32_t dev_id, uint32_t img_id, uint8_t *buffer,
    uint32_t buffer_size, uint32_t area_check);

#endif
