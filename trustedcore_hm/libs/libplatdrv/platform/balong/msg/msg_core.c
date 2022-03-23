/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#include "msg_plat.h"
#include "msg_mem.h"
#include "msg_core.h"
#include "msg_cmsg.h"

#define THIS_CORE MSG_CORE_TEE
#define MID_ATTR_INIT_MAGIC 0xAABBCCDE
#define MSG_CHN_OPEND 0xAAAAABCD
struct msg_chn_hdl {
    u32 state;
    u32 chnid;
    u32 core_mask;
    int (*func)(const struct msg_addr *info, void *buf, u32 len);
};

static struct msg_chn_hdl g_msg_fd_info[MSG_CHN_CNT_MAX];

int msg_lite_callback(const struct msg_addr *src_addr, const struct msg_addr *dst_addr, void *buf, u32 len)
{
    if (src_addr == NULL || dst_addr == NULL || buf == NULL || len == 0) {
        return MSG_ERR_EINVAL;
    }

    if (dst_addr->chnid > MSG_CHN_CNT_MAX || g_msg_fd_info[dst_addr->chnid].state != MSG_CHN_OPEND) {
        return MSG_ERR_EHOSTUNREACH;
    }
    if ((g_msg_fd_info[dst_addr->chnid].core_mask & MSG_CORE_MASK(src_addr->core)) == 0) {
        return MSG_ERR_EHOSTUNREACH;
    }

    if (g_msg_fd_info[dst_addr->chnid].func == NULL) {
        return MSG_ERR_EHOSTUNREACH;
    }

    g_msg_fd_info[dst_addr->chnid].func(src_addr, buf, len);

    return 0;
}

void bsp_msgchn_attr_init(struct msgchn_attr *pattr)
{
    if (pattr == NULL) {
        return;
    }
    pattr->magic = MID_ATTR_INIT_MAGIC;
}

int bsp_msg_lite_open(struct msg_chn_hdl **ppchn_hdl, struct msgchn_attr *pattr)
{
    u32 chn_id;
    if (ppchn_hdl == NULL || pattr == NULL) {
        return MSG_ERR_EINVAL;
    }
    if (pattr->magic != MID_ATTR_INIT_MAGIC || pattr->chnid >= MSG_CHN_CNT_MAX) {
        return MSG_ERR_ENXIO;
    }

    chn_id = pattr->chnid;

    if (g_msg_fd_info[chn_id].state == MSG_CHN_OPEND) {
        return MSG_ERR_EEXIST;
    }
    g_msg_fd_info[chn_id].chnid = pattr->chnid;
    g_msg_fd_info[chn_id].core_mask = pattr->coremask;
    g_msg_fd_info[chn_id].func = pattr->lite_notify;
    g_msg_fd_info[chn_id].state = MSG_CHN_OPEND;

    *ppchn_hdl = &g_msg_fd_info[chn_id];

    return 0;
}

int bsp_msg_lite_sendto(struct msg_chn_hdl *chn_hdl, const struct msg_addr *dst, void *msg, unsigned len)
{
    int ret;
    struct msg_addr src_addr;
    if (chn_hdl == NULL || dst == NULL || msg == NULL || len == 0) {
        return MSG_ERR_EINVAL;
    }
    if (chn_hdl->state != MSG_CHN_OPEND) {
        return MSG_ERR_EIO;
    }
    src_addr.core = THIS_CORE;
    src_addr.chnid = chn_hdl->chnid;

    if (dst->core != THIS_CORE) {
        return msg_crosscore_send_lite(&src_addr, dst, msg, len);
    }

    // self loop
    ret = msg_lite_callback(&src_addr, dst, msg, len);
    if (ret < 0) {
        return ret;
    }
    return 0;
}

int bsp_msg_init(void)
{
    int ret;
    ret = msg_plat_init();
    if (ret) {
        msg_err("msg_plat_init failed!\n");
        return ret;
    }
    ret = msg_crosscore_init();
    if (ret) {
        msg_err("msg_crosscore_init failed!\n");
        return ret;
    }
    msg_mntn_init();
    return 0;
}
