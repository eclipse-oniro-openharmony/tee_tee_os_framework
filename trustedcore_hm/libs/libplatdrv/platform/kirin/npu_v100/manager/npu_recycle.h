/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu recycle
 */
#ifndef __NPU_RECYCLE_H
#define __NPU_RECYCLE_H

#include "npu_mailbox.h"
#include "npu_proc_ctx.h"

bool npu_is_proc_resource_leaks(struct npu_proc_ctx *proc_ctx);

void npu_resource_leak_print(struct npu_proc_ctx *proc_ctx);

void npu_recycle_npu_resources(struct npu_proc_ctx *proc_ctx);

#endif
