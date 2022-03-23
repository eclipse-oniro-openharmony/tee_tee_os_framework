/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#ifndef _EICC_CORE_H
#define _EICC_CORE_H

#include "eicc_platform.h"
#include "eicc_device.h"
#include "eicc_driver.h"
/*
 * usrchn_id 是用户使用的通道ID，
 * drvchn_id 给驱动用的通道ID ，由四部分组成，即devid,pipeid,core_id,rcore_id
 * |--devid--|-------pipeid-------|-----coreid-----|-----rcoreid-----|
 */
#define EICC_GET_DEV_ID(drv_chn_id) ((drv_chn_id) >> 28)
#define EICC_GET_PIPE_ID(drv_chn_id) (((drv_chn_id) >> 16) & 0xfff)
#define EICC_GET_CORE_ID(drv_chn_id) (((drv_chn_id) >> 8) & 0xff)
#define EICC_GET_RCORE_ID(drv_chn_id) ((drv_chn_id)&0xff)

#define EICC_GET_PHYCHN_ID(x_chn_id) ((x_chn_id) >> 16)
#define GET_DEV_ID(phy_chn_id) ((phy_chn_id) >> 12)
#define GET_PIPE_ID(phy_chn_id) ((phy_chn_id)&0xFFF)

#define EICC_PHYCHNID_MK(dev_id, pipe_id) (((dev_id) << 12) | (pipe_id))

#define EICC_ERR_ESRCH (-3)             /* No such process */
#define EICC_ERR_EIO (-5)               /* Input/output error */
#define EICC_ERR_ENXIO (-6)             /* No such device or address */
#define EICC_ERR_ENOMEM (-12)           /* Cannot allocate memory */
#define EICC_ERR_EEXIST (-17)           /* File exists */
#define EICC_ERR_EINVAL (-22)           /* Invalid argument */
#define EICC_ERR_ECHRNG (-44)           /* Channel number out of range */
#define EICC_ERR_ETIME (-62)            /* Timer expired */
#define EICC_ERR_EPROTO (-71)           /* Protocol error */
#define EICC_ERR_EBADMSG (-74)          /* Bad message */
#define EICC_ERR_EBADFD (-77)           /* File descriptor in bad state */
#define EICC_ERR_ENETUNREACH (-101)     /* Network is unreachable */
#define EICC_ERR_EHOSTUNREACH (-113)    /* No route to host */
#define EICC_ERR_ENOTRECOVERABLE (-131) /* State not recoverable */
#define EICC_ERR_PM_OPIPE_NOT_IDLE (-512)
#define EICC_ERR_PM_IPIPE_NOT_IDLE (-513)
#define EICC_ERR_PM_IPIPE_NEG_REFUSE (-514)
#define EICC_ERR_PM_IPIPE_NEG_TIMEOUT (-515)
#define EICC_ERR_PM_IPIPE_NEG_FAIL (-516)
#define EICC_ERR_PM_OPIPE_NOT_EMPTY (-517)
#define EICC_ERR_PM_IPIPE_NOT_EMPTY (-518)

struct eicc_send_helper {
    u32 channel_id;
    void *send_desc;
    u32 send_flags;
    u32 total_msglen;
    u32 head_len;
    u32 write_len;
    u32 space_left;
    u32 wptr;
};
struct eicc_recv_helper {
    u32 channel_id;
    void *buf;
    unsigned len;
    u32 recv_flags;
    u32 used_len;
    u32 rptr;
    u32 seek;
    u32 payloadskip_len;
};

int eicc_normal_event_notify(u32 inttype, struct eicc_device *pdev, u32 pipe_id);
int eicc_wakeup_event_notify(struct eicc_device *pdev, u32 pipe_id);
int eicc_opipe_rst_halt(struct eicc_device *pdev, u32 opipe_id);
void eicc_opipe_enable(struct eicc_device *pdev, struct eicc_channel *pchannel);
void eicc_ipipe_enable(struct eicc_device *pdev, struct eicc_channel *pchannel);
void eicc_shadow_ipipe_enable(struct eicc_device *pdev, struct eicc_channel *pchannel);

#endif /* EICC_CORE_H */
