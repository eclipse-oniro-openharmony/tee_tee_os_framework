/*
 * npu_proc_ctx.h
 *
 * Copyright (c) 2012-2020 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __NPU_PROC_CTX_H__
#define __NPU_PROC_CTX_H__
#include <list.h>

#include "npu_base_define.h"
#include "npu_dev_ctx.h"

typedef struct npu_proc_ctx {
	struct list_head list_node;
	npu_dev_ctx_t *dev_ctx;

	struct list_head task_list;
	struct list_head stream_list;
	struct list_head model_list;
	struct list_head event_list;
	struct list_head sq_list;
} npu_proc_ctx_t;

#endif /* __DEVDRV_MANAGER_H */
