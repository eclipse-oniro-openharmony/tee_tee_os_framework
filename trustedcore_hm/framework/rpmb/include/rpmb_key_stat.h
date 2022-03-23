/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: rpmb key state.
 * Create: 2012-12-01
 */
#ifndef RPMB_RPMB_KEY_STAT_H
#define RPMB_RPMB_KEY_STAT_H
#include <tee_defines.h>

enum partition_info {
    RPMB_PARTITION_INFO_INVALID = -1,
    RPMB_PARTITION_INFO_READY   = 0,
};

enum key_info {
    RPMB_KEY_INFO_INVALID = -1,
    RPMB_KEY_INFO_READY   = 0,
    RPMB_KEY_INFO_SHORT_BUFFER,
};

enum mdt_info {
    MDT_UNKOWN = 0,
    MDT_EMMC,
    MDT_UFS,
};

#define RPMB_ROOTKEY_SIZE_MAX 100U
#define STUFF_SIZE            0x200U
#define RESERVE_NUM           32
struct rpmb_atf_info {
    uint8_t stuff[STUFF_SIZE];
    uint32_t ret;
    uint32_t start_blk;
    uint32_t total_blk;
    uint32_t data_len;
    uint32_t data_addr;
    uint32_t mdt; /* 1: EMMC 2: UFS */
    /*
     * the device's support bit map, for example, if it support 1,2,32,
     * then the value is 0x80000003
     */
    uint32_t support_bit_map;
    uint32_t version;
    uint8_t reserved[RESERVE_NUM]; /* add reserved to ensure end address aligned for 64 */
};

uint32_t rpmb_partition_info_write(const struct rpmb_atf_info *partition);
uint32_t rpmb_partition_info_read(struct rpmb_atf_info *partition);
uint32_t rpmb_keyinfo_info_write(const char *data, uint32_t len);
uint32_t rpmb_keyinfo_info_read(char *data, uint32_t *len);
#endif