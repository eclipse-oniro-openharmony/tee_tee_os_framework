/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: rpmb key state.
 * Create: 2012-12-01
 */
#include "rpmb_key_stat.h"
#include <securec.h>

/* save the rpmb partition SecureOS can access in kernel. */
static uint32_t g_rpmb_partition_stat = (uint32_t)RPMB_PARTITION_INFO_INVALID;
static uint32_t g_rpmb_start_blk;
static uint32_t g_rpmb_total_blk;
static uint32_t g_rpmb_mdt = MDT_UNKOWN;
static uint32_t g_rpmb_support_bit_map;
static uint32_t g_rpmb_version;

uint32_t rpmb_partition_info_write(const struct rpmb_atf_info *partition)
{
    if (partition != NULL) {
        g_rpmb_start_blk = partition->start_blk;
        g_rpmb_total_blk = partition->total_blk;
        g_rpmb_mdt = partition->mdt;
        g_rpmb_support_bit_map = partition->support_bit_map;
        g_rpmb_version = partition->version;
        g_rpmb_partition_stat = RPMB_PARTITION_INFO_READY;
    }

    return g_rpmb_partition_stat;
}

uint32_t rpmb_partition_info_read(struct rpmb_atf_info *partition)
{
    if (partition != NULL) {
        partition->start_blk = g_rpmb_start_blk;
        partition->total_blk = g_rpmb_total_blk;
        partition->mdt = g_rpmb_mdt;
        partition->support_bit_map = g_rpmb_support_bit_map;
        partition->version = g_rpmb_version;
    }

    return g_rpmb_partition_stat;
}

/* save the parameter of rootKey in kernel. */
static uint32_t g_rpmb_keyinfo_stat = (uint32_t)RPMB_KEY_INFO_INVALID;
static uint8_t g_rpmb_keyinfo_data[RPMB_ROOTKEY_SIZE_MAX];
static uint32_t g_rpmb_keyinfo_datalen;

uint32_t rpmb_keyinfo_info_write(const char *data, uint32_t len)
{
    errno_t rc;

    if (data == NULL)
        return (uint32_t)RPMB_KEY_INFO_INVALID;

    rc = memcpy_s(g_rpmb_keyinfo_data, sizeof(g_rpmb_keyinfo_data), data, len);
    if (rc != EOK) {
        g_rpmb_keyinfo_stat = (uint32_t)RPMB_KEY_INFO_INVALID;
        return g_rpmb_keyinfo_stat;
    }
    g_rpmb_keyinfo_datalen = len;
    g_rpmb_keyinfo_stat = RPMB_KEY_INFO_READY;

    return g_rpmb_keyinfo_stat;
}

uint32_t rpmb_keyinfo_info_read(char *data, uint32_t *len)
{
    errno_t rc;

    if (data == NULL || len == NULL)
        return (uint32_t)RPMB_KEY_INFO_INVALID;

    if (*len < g_rpmb_keyinfo_datalen)
        return RPMB_KEY_INFO_SHORT_BUFFER;

    rc = memcpy_s(data, *len, g_rpmb_keyinfo_data, g_rpmb_keyinfo_datalen);
    if (rc != EOK) {
        g_rpmb_keyinfo_stat = (uint32_t)RPMB_KEY_INFO_INVALID;
        return g_rpmb_keyinfo_stat;
    }
    *len = g_rpmb_keyinfo_datalen;

    return g_rpmb_keyinfo_stat;
}