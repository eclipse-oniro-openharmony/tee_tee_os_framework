/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: firmware upgrade ta api head file
 * Author: chenyao
 * Create: 2019-09-15
 */
#ifndef FIRMWARE_UPGRADE_TA_API_H
#define FIRMWARE_UPGRADE_TA_API_H

#include <tee_defines.h>

uint32_t tee_sec_img_verify(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_img_update(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_update_finish(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_img_sync_entry(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_rim_update(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_img_version_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_img_count_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_img_info_get(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_ufs_cnt_read(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_ufs_cnt_write(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_cnt_clear(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_get_cmdline_info(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_img_sync_before_upgrade(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_get_efuse_nvcnt(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);
uint32_t tee_sec_recovery_cnt_reset(uint32_t paramTypes, TEE_Param params[OPEN_SESSION_PARA_NUM]);

#endif
