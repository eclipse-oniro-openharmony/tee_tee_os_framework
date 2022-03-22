/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */
#ifndef _MSG_CMSG_H
#define _MSG_CMSG_H

int msg_crosscore_init(void);
int msg_crosscore_send_lite(const struct msg_addr *src_addr, const struct msg_addr *dst_addr, void *buf, u32 len);

#endif
