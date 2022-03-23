/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu mailbox
 */
#ifndef __NPU_MAILBOX_H
#define __NPU_MAILBOX_H

#include "npu_common.h"
#include "npu_mailbox_msg.h"

#define DEVDRV_MAILBOX_SRAM 0

#define DEVDRV_MAILBOX_FREE 0
#define DEVDRV_MAILBOX_BUSY 1

#define DEVDRV_MAILBOX_VALID_MESSAGE   0
#define DEVDRV_MAILBOX_RECYCLE_MESSAGE 1

#define DEVDRV_MAILBOX_PAYLOAD_LENGTH 64

#define DEVDRV_MAILBOX_MESSAGE_VALID 0x5A5A

#define DEVDRV_DOORBEEL_TYPE 0

#define DEVDRV_MAILBOX_SYNC_MESSAGE  1
#define DEVDRV_MAILBOX_ASYNC_MESSAGE 2

#define DEVDRV_MAILBOX_SYNC          0
#define DEVDRV_MAILBOX_ASYNC         1

#define DEVDRV_MAILBOX_SEMA_TIMEOUT_SECOND 5

int npu_mailbox_init(int dev_id);
int npu_mailbox_message_send_for_res(u8 dev_id, u8 *buf, u32 len, int *result);
void npu_mailbox_exit(struct npu_mailbox *mailbox);
void npu_mailbox_recycle(struct npu_mailbox *mailbox);
void npu_mailbox_destroy(int dev_id);
void npu_set_mailbox_base_vaddr(struct npu_dev_ctx *dev_ctx, u64 vaddr);
int npu_get_mailbox_base_vaddr(struct npu_dev_ctx *dev_ctx, u64 *vaddr);
#endif
