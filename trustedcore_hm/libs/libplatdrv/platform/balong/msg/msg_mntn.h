/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#ifndef _MSG_MNTN_H
#define _MSG_MNTN_H

#define MSG_PKT_POINT_SEND 1
#define MSG_PKT_POINT_RECV 2
struct msg_pkt_info {
    u16 point;
    u16 srcid;
    u16 dstid;
    u16 timestamp;
    u32 len;
};
int msg_mntn_init(void);
#endif
