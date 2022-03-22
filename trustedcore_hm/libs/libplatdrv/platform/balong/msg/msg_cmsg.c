/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#include "bsp_eicc.h"

#include "msg_plat.h"
#include "msg_mem.h"
#include "msg_cmsg.h"
#include "msg_core.h"

#define MSG_MAX_SIZE 256
#define MSG_CHAN_RSV_SIZE 128
#define MSG_CHAN_BUFF_SIZE (MSG_MAX_SIZE * 2)

#define CMSG_SEND_TRY_WAIT_TIMES 200

struct msg_eicc_cfg {
    unsigned cid;
    unsigned smsg_sz;
    unsigned send_chn;
    unsigned sbuf_sz;
    unsigned recv_chn;
    unsigned rbuf_sz;
};

struct msg_eicc_cfg g_msg_eicc_cfg[] = {
    {MSG_CID_TSP, MSG_MAX_SIZE, EICC_CHN_SEND_TEE2TSP_MDRV_MSG, MSG_CHAN_BUFF_SIZE, EICC_CHN_RECV_TSP2TEE_MDRV_MSG,
     MSG_CHAN_BUFF_SIZE},
};

#define MSG_CHN_STATUS_UNINIT 0
#define MSG_CHN_STATUS_INITING 1
#define MSG_CHN_STATUS_INITED 2

struct cmsg_dbg {
    u32 seq_err;
    u32 segmsg_err;
    u32 ioctl_err;
    u32 recv_err;
    u32 lenchk_err;
    u32 alloc_err;
    u32 pktfw_err;
};

struct cmsg_ctrl {
    unsigned cid;
    unsigned status;
    eicc_chn_t s_handle;
    u32 s_max_pkt_len;
    eicc_chn_t r_handle;
    u16 s_seq;
    u16 r_seq;
    void *lmsg;
    u32 lmsg_off;
    struct cmsg_dbg dbg_info;
};

struct cmsg_ctrl g_cmsg_ctrl[MSG_CORE_MAX];

static inline struct cmsg_ctrl *cmsg_get_ctrl(unsigned cid)
{
    if (cid > MSG_CORE_MAX) {
        return NULL;
    }
    return &g_cmsg_ctrl[cid];
}

static int recv_lite_msg(struct cmsg_ctrl *ctrl, struct cmsg_hdr *phdr, void *buff)
{
    int ret;
    void *msg = NULL;
    struct cmsg_lite_exthdr lite_exthdr;
    struct msg_addr src_addr;
    struct msg_addr dst_addr;
    struct cmsg_dbg *dbg = &ctrl->dbg_info;

    ret = bsp_eicc_chn_recv(ctrl->r_handle, &lite_exthdr, sizeof(struct cmsg_lite_exthdr), 0);
    if (ret != sizeof(struct cmsg_lite_exthdr)) {
        dbg->recv_err++;
        msg_crit("recv_short_msg too small,phdr->len=%d, ret = %d\n", phdr->len, ret);
        return MSG_ERR_EBADMSG;
    }

    if (phdr->len > MSG_MAX_SIZE) {
        dbg->alloc_err++;
        msg_crit("recv_short_msg alloc %d failed\n", phdr->len);
        return MSG_ERR_ENOMEM;
    }
    msg = (void *)buff;
    ret = bsp_eicc_chn_recv(ctrl->r_handle, msg, phdr->len, 0);
    if (ret != (int)phdr->len) {
        dbg->recv_err++;
        msg_crit("recv_short_msg recv err len=%d ret=%d\n", phdr->len, ret);
        return MSG_ERR_EIO;
    }

    src_addr.core = (lite_exthdr.src >> 0x10);
    src_addr.chnid = (lite_exthdr.src & 0xFFFF);
    dst_addr.core = (lite_exthdr.dst >> 0x10);
    dst_addr.chnid = (lite_exthdr.dst & 0xFFFF);

    ret = msg_lite_callback(&src_addr, &dst_addr, msg, phdr->len);
    if (ret != 0) {
        dbg->pktfw_err++;
        msg_err("eicc crosscore forward failed ret=%d\n", ret);
        return 0; /* return ok here */
    }
    return 0;
}

static int msg_recv_header(struct cmsg_ctrl *ctrl, ioctl_nxtpkt *pktinfo, struct cmsg_hdr *phdr)
{
    int ret;
    struct cmsg_dbg *dbg = &ctrl->dbg_info;
    ret = bsp_eicc_chn_ioctl(ctrl->r_handle, EICC_IOCTL_CHN_NXTPKT_INF, pktinfo, sizeof(ioctl_nxtpkt));
    if (ret) {
        dbg->ioctl_err++;
        msg_err("eicc ioctrl err\n");
        return -1;
    }
    if (pktinfo->len == 0) {
        /* 这属于正常情况,不要打印 */
        return MSG_ERR_EAGAIN;
    }
    if (pktinfo->len < sizeof(struct cmsg_hdr)) {
        dbg->lenchk_err++;
        msg_crit("msg_recv_process unexpected\n");
        /* skip this packet */
        return -1;
    }
    ret = bsp_eicc_chn_recv(ctrl->r_handle, phdr, sizeof(struct cmsg_hdr), 0);
    if (ret != (int)sizeof(struct cmsg_hdr)) {
        dbg->recv_err++;
        msg_err("msg_recv_process unexpected\n");
        /* skip this packet */
        return MSG_ERR_EBADMSG;
    }
    return 0;
}

int msg_recv_process(struct cmsg_ctrl *ctrl)
{
    int ret;
    ioctl_nxtpkt pktinfo;
    struct cmsg_hdr hdr;
    struct cmsg_hdr *phdr = &hdr;
    struct cmsg_dbg *dbg = &ctrl->dbg_info;
    u32 hdr_len;
    u8 buff[MSG_MAX_SIZE];

    ret = msg_recv_header(ctrl, &pktinfo, phdr);
    if (ret) {
        return ret;
    }
    if (phdr->type == CMSG_TYPE_SINGLE) {
        hdr_len = sizeof(struct cmsg_hdr);
    } else if (phdr->type == CMSG_TYPE_LITE) {
        hdr_len = sizeof(struct cmsg_hdr) + sizeof(struct cmsg_lite_exthdr);
    } else {
        // drop packet
        msg_print("recv %d msg err\n", phdr->type);
        return -1;
    }

    /* 重要：这个检查成立，就可以认为phdr->len是可信的，这样后面不用再检查phdr->len溢出等 */
    if (pktinfo.len != phdr->len + hdr_len) {
        dbg->lenchk_err++;
        msg_crit("msg_recv_process len check failed\n");
        return MSG_ERR_EBADMSG;
    }
    if (phdr->seq != ctrl->r_seq) {
        dbg->seq_err++;
        msg_err("msg_recv_process seq check failed,resync\n");
        ctrl->r_seq = phdr->seq;
    }
    ctrl->r_seq++;
    if (phdr->type == CMSG_TYPE_LITE) {
        ret = recv_lite_msg(ctrl, phdr, buff);
    } else {
        ret = -1;
    }
    if (ret) {
        msg_print("recv %d msg err\n", phdr->type);
    }

    return ret;
}

int msg_eicc_recv_cb(eicc_event event, void *arg, const eicc_eventinfo *event_info)
{
    UNUSED(event_info);
    struct cmsg_ctrl *ctrl = NULL;

    msg_trace("msg_eicc_recv_cbk in\n");
    if (arg == NULL) {
        return -1;
    }
    if (event == EICC_EVENT_DATA_ARRV) {
        ctrl = (struct cmsg_ctrl *)arg;
        msg_recv_process(ctrl);
    } else {
        msg_err("eicc Something went wrong\n");
        return -1;
    }
    msg_trace("msg_eicc_recv_cbk out\n");
    return 0;
}

static int send_lite_msg(struct cmsg_ctrl *ctrl, const struct msg_addr *src_addr, const struct msg_addr *dst_addr,
    void *buf, u32 len)
{
    int ret;
    int try_times;

    struct cmsg_hdr hdr;
    struct cmsg_lite_exthdr lite_exthdr;

    eicc_blkx3_desc_t send_desc;

    hdr.type = CMSG_TYPE_LITE;
    hdr.rsv = 0;
    hdr.seq = ctrl->s_seq;
    hdr.flags = 0;
    hdr.len = len;

    lite_exthdr.src = (src_addr->core << 0x10) | (src_addr->chnid);
    lite_exthdr.dst = (dst_addr->core << 0x10) | (dst_addr->chnid);

    send_desc.cnt = 0x3;
    send_desc.datablk[0].len = sizeof(hdr);
    send_desc.datablk[0].buf = &hdr;
    send_desc.datablk[1].len = sizeof(lite_exthdr);
    send_desc.datablk[1].buf = &lite_exthdr;
    send_desc.datablk[0x2].len = len;
    send_desc.datablk[0x2].buf = buf;

    for (try_times = 0; try_times < CMSG_SEND_TRY_WAIT_TIMES; try_times++) {
        ret = bsp_eicc_chn_blks_send(ctrl->s_handle, (eicc_blk_desc_t *)&send_desc, 0);
        if (ret == EICC_ERR_EAGAIN) {
            continue;
        }
        break;
    };

    if (ret < 0) {
        msg_err("msg send err, ret=%d\n", ret);
        return -1;
    }
    ctrl->s_seq++;
    if ((unsigned)ret != sizeof(hdr) + sizeof(lite_exthdr) + len) {
        msg_err("msg send msg_len err,real send msg_len=%d, user send msg_len=%d\n", ret, sizeof(hdr) + len);
        return -1;
    }
    return 0;
}

int msg_crosscore_send_lite(const struct msg_addr *src_addr, const struct msg_addr *dst_addr, void *buf, u32 len)
{
    int ret;
    unsigned long lockflags;
    struct cmsg_ctrl *ctrl = NULL;
    ctrl = cmsg_get_ctrl(dst_addr->core);
    if (ctrl == NULL || ctrl->status != MSG_CHN_STATUS_INITED) {
        return -1;
    }
    local_irq_save(lockflags);
    ret = send_lite_msg(ctrl, src_addr, dst_addr, buf, len);
    local_irq_restore(lockflags);
    return ret;
}

static int msg_eicc_schan_open(struct msg_eicc_cfg *eicc_cfg, struct cmsg_ctrl *ctrl)
{
    int ret;
    unsigned long pa = 0;
    eicc_chn_attr_t attr;
    eicc_chn_attr_t *pattr = &attr;
    ret = bsp_eicc_chn_attr_init(&attr);
    if (ret) {
        msg_err("chan attr init error\n");
        return -1;
    }

    pattr->chnid = eicc_cfg->send_chn;
    pattr->type = EICC_CHN_TYPE_SEND;
    pattr->va = (void *)msg_dma_alloc(eicc_cfg->sbuf_sz, &pa, 0);
    pattr->pa = pa;
    pattr->size = eicc_cfg->sbuf_sz;
    pattr->cbk = NULL;
    pattr->cbk_arg = NULL;
    if (pattr->va == NULL) {
        msg_err("msg_dma_alloc error\n");
        return -1;
    }

    ret = bsp_eicc_chn_open(&ctrl->s_handle, &attr);
    if (ret) {
        msg_err("bsp_eicc_chn_open %d error ret=%x\n", pattr->chnid, ret);
        return -1;
    }
    ctrl->s_max_pkt_len = MSG_MAX_SIZE - MSG_CHAN_RSV_SIZE;

    return 0;
}

static int msg_eicc_rchan_open(struct msg_eicc_cfg *eicc_cfg, struct cmsg_ctrl *ctrl)
{
    int ret;
    unsigned long pa = 0;
    eicc_chn_attr_t attr;
    eicc_chn_attr_t *pattr = &attr;

    ret = bsp_eicc_chn_attr_init(&attr);
    if (ret) {
        msg_err("chan attr init error\n");
        return -1;
    }

    pattr->chnid = eicc_cfg->recv_chn;
    pattr->type = EICC_CHN_TYPE_RECV;
    pattr->va = (void *)msg_dma_alloc(eicc_cfg->rbuf_sz, &pa, 0);
    pattr->pa = pa;
    pattr->size = eicc_cfg->rbuf_sz;
    pattr->cbk = msg_eicc_recv_cb;
    pattr->cbk_arg = ctrl;
    if (pattr->va == NULL) {
        msg_err("msg_dma_alloc error\n");
        return -1;
    }

    ret = bsp_eicc_chn_open(&ctrl->r_handle, &attr);
    if (ret) {
        msg_err("bsp_eicc_chn_open %d error ret=%x\n", pattr->chnid, ret);

        return -1;
    }

    return 0;
}

static int msg_eicc_chan_init(struct msg_eicc_cfg *eicc_cfg)
{
    int ret;
    struct cmsg_ctrl *ctrl = NULL;

    ctrl = cmsg_get_ctrl(eicc_cfg->cid);
    if (ctrl == NULL || ctrl->status != MSG_CHN_STATUS_UNINIT) {
        return -1;
    }
    ctrl->cid = eicc_cfg->cid;
    ctrl->status = MSG_CHN_STATUS_INITING;
    ret = msg_eicc_schan_open(eicc_cfg, ctrl);
    if (ret) {
        return ret;
    }
    ret = msg_eicc_rchan_open(eicc_cfg, ctrl);
    if (ret) {
        return ret;
    }
    ctrl->status = MSG_CHN_STATUS_INITED;
    return 0;
}

int msg_crosscore_init(void)
{
    u32 i;
    int ret;
    for (i = 0; i < sizeof(g_msg_eicc_cfg) / sizeof(g_msg_eicc_cfg[0]); i++) {
        ret = msg_eicc_chan_init(&g_msg_eicc_cfg[i]);
        if (ret) {
            msg_err("msg_eicc_chan_init %d error ret=%x\n", i, ret);
            return ret;
        }
    }
    return ret;
}
