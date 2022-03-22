/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: hpp rom keyladder.
 * Author: Hisilicon security team
 * Create: 2019-06-03
 */

#ifndef __MSG_QUEUE_H__
#define __MSG_QUEUE_H__

#include "hi_type_dev.h"
#include "securec.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define QUEUE_POOL_MAX_DEPTH     0x20
#define QUEUE_POOL_MAX_MSG_SIZE  0x100

hi_s32 mq_create(hi_u32 msg_size, hi_u32 depth);

hi_s32 mq_destroy(hi_void);

hi_s32 mq_resv(hi_void *msg, hi_u32 msg_size);

hi_s32 mq_snd(const hi_void *msg, hi_u32 msg_size);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif
