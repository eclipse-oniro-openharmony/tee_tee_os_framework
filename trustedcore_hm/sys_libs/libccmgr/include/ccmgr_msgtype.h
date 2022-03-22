/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: cc manager implementation
 * Create: 2018-05-18
 */

#ifndef __CCMGR_MSGTYPE_H
#define __CCMGR_MSGTYPE_H

#include <cs_msg/msgtype.h>

HM_MSG_CLASS(ccmgr, HM_MSG_TYPE(HM_SYSCALL_CC_CRYS_RND_GENERATE64, (ccmgr_req_msg_t), true, false)
             HM_MSG_TYPE(HM_SYSCALL_CC_CRYS_GET_PUSHED_RANDOM, (ccmgr_req_msg_t), true, false),
             HM_MSG_DEFAULT_TYPE(HM_EMPTY_REQ, false, false))
#endif
