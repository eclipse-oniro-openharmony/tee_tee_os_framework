/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#ifndef _BSP_MSG_H
#define _BSP_MSG_H

#include <osl_balong.h>

enum {
    MSG_CORE_STUB = 0, /* 编号为0的空着不用 */
    MSG_CORE_APP = 1,
    MSG_CORE_TSP = 2,
    MSG_CORE_LPM = 4,
    MSG_CORE_TEE = 6,
    MSG_CORE_SENSOR = 7,
    MSG_CORE_CNTMAX,
};

#define MSG_CORE_MASK(x) (1 << (x))

struct msg_addr {
    u32 core;
    u32 chnid;
};

struct msgchn_attr {
    unsigned magic;
    unsigned chnid;
    unsigned coremask;
    int (*lite_notify)(const struct msg_addr *src, void *msg, u32 len);
};

int bsp_msg_init(void);

typedef struct msg_chn_hdl *msg_chn_t;
void bsp_msgchn_attr_init(struct msgchn_attr *pattr);
int bsp_msg_lite_open(msg_chn_t *phdl, struct msgchn_attr *notifier);
int bsp_msg_lite_sendto(msg_chn_t hdl, const struct msg_addr *addr, void *buf, u32 len);


#endif
