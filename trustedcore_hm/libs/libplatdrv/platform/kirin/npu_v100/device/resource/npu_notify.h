/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu notify
 */
#ifndef __NPU_NOTIFY_H
#define __NPU_NOTIFY_H

#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include "npu_mailbox.h"

#define DEVDRV_NOTIFY_INFORM_TS 0
#define DEVDRV_NOTIFY_NOT_INFORM_TS 1
#define DEVDRV_MAILBOX_RESET_NOTIFY_ID 0x0010

struct npu_notify_info {
	int id;
	u32 devid;
	struct list_head list;
	spinlock_t spinlock;
};
struct npu_ts_notify_msg {
	struct npu_mailbox_message_header header;
	u16 notifyId;
	u16 resv[25];
	u8 reserved[3];
};

int npu_notify_list_init(int dev_ctx_id);

int npu_alloc_notify_id(int dev_ctx_id, unsigned long arg);

int npu_free_notify_id(int dev_ctx_id, unsigned long arg);

int npu_notify_list_destroy(int dev_ctx_id);

int npu_notify_software_register(int dev_ctx_id);

#endif
