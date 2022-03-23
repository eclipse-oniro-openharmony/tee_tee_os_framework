/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Drivers for seplat power operation.
 * Create: 2021/01/03
 */

#include "seplat_power.h"
#include "dl_service.h"
#include "seplat_data_link.h"
#include "seplat_common.h"
#include "seplat_define.h"
#include "seplat_errno.h"
#include <ipc.h>
#include <securec.h>
#include <sre_sys.h>
#include <types.h>

#define SEPLAT_THIS_MODULE                SEPLAT_MODULE_POWER

#define SEPLAT_ROM_BOOT_TIME              500 /* 500ms */

#define SEPLAT_IPC_CMD(src, obj, cmd, type) \
    (((src) << 24) | ((obj) << 16) | ((cmd) << 8) | (type))

/* Those define must be the same with lpmcu. */
#define OBJ_AP                            0
#define OBJ_SEPLAT                        19
#define CMD_ON                            0
#define TYPE_POWER                        1

static uint32_t seplat_power_on(uint32_t op_type);
static uint32_t seplat_power_off(uint32_t op_type);
static uint32_t seplat_reset(uint32_t op_type);

/* Define module err code */
enum {
    SEPLAT_INVALID_PARAM_ERR              = SEPLAT_ERRCODE(0x00),
    SEPLAT_POWER_SEND_IPC_ERR             = SEPLAT_ERRCODE(0x01),
    SEPLAT_POWER_INVALID_OP_TYPE_ERR      = SEPLAT_ERRCODE(0x02),
    SEPLAT_POWER_INVALID_RESET_TYPE_ERR   = SEPLAT_ERRCODE(0x03),
    SEPLAT_POWER_INVALID_CMD_ERR          = SEPLAT_ERRCODE(0x04),
};

struct seplat_power_cbs {
    uint32_t cmd;
    uint32_t (*func)(uint32_t op_type);
};

const struct seplat_power_cbs g_sepalt_power_cb[] = {
    { SEPLAT_POWER_ON_CMD,    seplat_power_on },
    { SEPLAT_POWER_OFF_CMD,   seplat_power_off },
    { SEPLAT_POWER_RESET_CMD, seplat_reset },
};

static inline void seplat_mdelay(uint32_t ms)
{
    SRE_DelayMs(ms);
}

static uint32_t seplat_power_ctrl(uint32_t cmd, uint32_t op_type)
{
    int32_t ret;
    uint32_t msg_buff[MAX_IPC_DATA_LEN] = {0};
    uint32_t ack_buff[MAX_IPC_DATA_LEN] = {0};
    struct ipc_msg msg;
    struct seplat_ap_msg *header = NULL;

    if (cmd >= SEPLAT_POWER_MAX_CMD) {
        SEPLAT_PRINT("%s:Invalid cmd:%x\n", __func__, cmd);
        return SEPLAT_INVALID_PARAM_ERR;
    }

    (void)memset_s((void *)&msg, sizeof(msg), 0, sizeof(msg));

    msg.ipc_id = PERI_S_IPC;
    msg.mbox_id = PERI_MBX29_TO_LPM3;
    msg.src_id = PERI_S_AP_L;
    msg.dest_id = PERI_S_LPMCU;
    msg.msg_len = MAX_IPC_DATA_LEN;
    msg.ipc_data = (union ipc_data *)msg_buff;
    header = (struct seplat_ap_msg *)msg_buff;
    header->ipc_cmd = SEPLAT_IPC_CMD(OBJ_AP, OBJ_SEPLAT, CMD_ON, TYPE_POWER);
    header->cmd = cmd;
    header->op_type = op_type;

    ret = ipc_sync_send(&msg, (union ipc_data *)ack_buff, MAX_IPC_DATA_LEN);
    if (ret != SRE_OK) {
        SEPLAT_PRINT("%s:send ipc failed:ret=%x\n", __func__, ret);
        return SEPLAT_POWER_SEND_IPC_ERR;
    }

    header = (struct seplat_ap_msg *)ack_buff;
    if (header->ack == SEPLAT_LPM3_ACK_MAGIC)
        return SEPLAT_OK;

    SEPLAT_PRINT("%s:ack error:%x,%x\n", __func__, header->ack, header->error);
    return header->error;
}

static uint32_t seplat_power_on(uint32_t op_type)
{
    uint32_t ret;

    if (op_type >= SEPLAT_POWER_OP_MAX) {
        SEPLAT_PRINT("%s:Invalid op_type:%x\n", __func__, op_type);
        return SEPLAT_POWER_INVALID_OP_TYPE_ERR;
    }

    ret = seplat_power_ctrl(SEPLAT_POWER_ON_CMD, op_type);
    if (ret != SEPLAT_OK) {
        SEPLAT_PRINT("%s:send power cmd failed:%x\n", __func__, ret);
        return ret;
    }

    seplat_mdelay(SEPLAT_ROM_BOOT_TIME);

    ret = seplat_data_link_init();
    if (ret != SRE_OK) {
        SEPLAT_PRINT("%s:dl init fail!\n", __func__);
        return ret;
    }
    ret = SEPLAT_OK;

    SEPLAT_PRINT("%s:success!\n", __func__);
    return ret;
}

static uint32_t seplat_power_off(uint32_t op_type)
{
    uint32_t ret;

    if (op_type >= SEPLAT_POWER_OP_MAX) {
        SEPLAT_PRINT("%s:Invalid op_type:%x\n", __func__, op_type);
        return SEPLAT_POWER_INVALID_OP_TYPE_ERR;
    }

    ret = seplat_power_ctrl(SEPLAT_POWER_OFF_CMD, op_type);
    if (ret != SEPLAT_OK)
        SEPLAT_PRINT("%s:send power cmd failed:%x\n", __func__, ret);
    else
        SEPLAT_PRINT("%s:success!\n", __func__);

    return ret;
}

static uint32_t seplat_reset(uint32_t op_type)
{
    uint32_t ret;
    struct dl_channel_index channel = {0};

    if (op_type >= SEPLAT_RESET_OP_MAX) {
        SEPLAT_PRINT("%s:Invalid reset_type:%x\n", __func__, op_type);
        return SEPLAT_POWER_INVALID_RESET_TYPE_ERR;
    }

    if (op_type == SEPLAT_SOFT_RESET_OP) {
        channel.service = DL_SYSTEM_SECURITY;
        channel.prior = DL_CHANNEL_NORMAL_LEVEL;
        return dl_chip_reset(DL_SOFT_RESET, channel);
    }

    ret = seplat_power_ctrl(SEPLAT_POWER_RESET_CMD, op_type);
    if (ret != SEPLAT_OK) {
        SEPLAT_PRINT("%s:send power cmd failed:%x\n", __func__, ret);
        return ret;
    }

    seplat_mdelay(SEPLAT_ROM_BOOT_TIME);
    ret = seplat_data_link_init();
    if (ret != SRE_OK) {
        SEPLAT_PRINT("%s:dl init fail!\n", __func__);
        return ret;
    }
    ret = SEPLAT_OK;

    SEPLAT_PRINT("%s:success!\n", __func__);
    return ret;
}

uint32_t seplat_power_process(uint32_t vote_id, uint32_t power_cmd, uint32_t op_type)
{
    uint32_t i;

    (void)vote_id;

    for (i = 0; i < ARRAY_SIZE(g_sepalt_power_cb); i++)
        if (power_cmd == g_sepalt_power_cb[i].cmd)
            return g_sepalt_power_cb[i].func(op_type);

    SEPLAT_PRINT("%s:Invalid cmd:%x, %x\n", __func__, power_cmd, op_type);
    return SEPLAT_POWER_INVALID_CMD_ERR;
}

