/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 */

#ifndef _MSG_CORE_H
#define _MSG_CORE_H
#include "msg_plat.h"
#include "msg_mntn.h"

int msg_lite_callback(const struct msg_addr *src_addr, const struct msg_addr *dst_addr, void *buf, u32 len);

#endif
