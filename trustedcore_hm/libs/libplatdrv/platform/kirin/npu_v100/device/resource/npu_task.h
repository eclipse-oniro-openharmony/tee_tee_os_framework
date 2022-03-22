/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu task
 */
#ifndef __NPU_TASK_H
#define __NPU_TASK_H

#include <list.h>

struct npu_task_info {
	int id;
	u32 devid;
	struct list_head list;
};

int npu_task_list_init(u8 dev_ctx_id);

struct npu_task_info *npu_alloc_task(u8 dev_ctx_id);

int npu_free_task_id(u8 dev_ctx_id, u32 model_id);

int npu_task_list_destroy(u8 dev_ctx_id);

#endif
