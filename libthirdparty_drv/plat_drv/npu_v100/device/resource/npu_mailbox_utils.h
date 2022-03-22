/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu mailbox utils
 */
#ifndef __NPU_MAILBOX_UTILS_H
#define __NPU_MAILBOX_UTILS_H

#include "npu_common.h"

#define PTHREAD_STACK_SIZE   (128 * 1024)

void npu_mailbox_notifier_init();

int npu_create_mbx_send_thread();

void npu_mailbox_sending_thread_wake_up();

#endif
