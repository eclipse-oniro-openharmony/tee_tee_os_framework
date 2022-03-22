/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu task
 */

#include "npu_task.h"

#include <errno.h>

#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "drv_log.h"

#include "npu_common.h"
#include "npu_custom_info_share.h"
#include "npu_spec_share.h"

static u32 npu_get_available_task_num(struct npu_dev_ctx *dev_ctx)
{
	u32 task_id_num;

	if (dev_ctx == NULL) {
		NPU_ERR("invaild param dev_ctx is null\n");
		return 0;
	}
	task_id_num = dev_ctx->task_id_num;

	return task_id_num;
}

static struct npu_task_info *npu_get_one_task_id(struct npu_dev_ctx *dev_ctx)
{
	struct npu_task_info *task_info = NULL;
	if (dev_ctx == NULL) {
		NPU_ERR("invaild param dev_ctx is null\n");
		return NULL;
	}
	if (list_empty_careful(&dev_ctx->task_available_list))
		return NULL;

	task_info = list_first_entry(&dev_ctx->task_available_list, struct npu_task_info, list);
	list_del(&task_info->list);
	if (dev_ctx->task_id_num <= 0) {
		NPU_ERR("dev_ctx->task_id_num is error\n");
		return NULL;
	}
	dev_ctx->task_id_num--;
	return task_info;
}

static struct npu_task_info *npu_find_one_task(struct npu_dev_ctx *dev_ctx, u32 task_id)
{
	if (dev_ctx == NULL) {
		NPU_ERR("invaild param dev_ctx is null\n");
		return NULL;
	}
	struct npu_task_info *task_info = NULL;
	task_info = (struct npu_task_info *)(dev_ctx->task_addr +
		(long)sizeof(struct npu_task_info) * task_id);

	return task_info->id != (int)task_id ? NULL : task_info;
}

int npu_task_list_init(u8 dev_ctx_id)
{
	u32 i;
	u32 task_num = DEVDRV_MAX_TASK_ID;
	unsigned long size;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_task_info *task_info = NULL;

	if (dev_ctx_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	INIT_LIST_HEAD(&dev_ctx->task_available_list);
	if (!list_empty_careful(&dev_ctx->task_available_list)) {
		NPU_ERR("available task list is not empty\n");
		return -EEXIST;
	}

	size = (long)(unsigned)sizeof(struct npu_task_info) * task_num;
	task_info = TEE_Malloc(size, 0);
	if (task_info == NULL) {
		NPU_ERR("task_info vmalloc failed\n");
		return -ENOMEM;
	}

	dev_ctx->task_id_num = 0;
	for (i = 0; i < task_num; i++) {
		task_info[i].id = i;
		task_info[i].devid = dev_ctx->devid;
		list_add_tail(&task_info[i].list, &dev_ctx->task_available_list);
		dev_ctx->task_id_num++;
	}
	dev_ctx->task_addr = task_info;

	return 0;
}

struct npu_task_info *npu_alloc_task(u8 dev_ctx_id)
{
	u32 task_num;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_task_info *task_info = NULL;

	if (dev_ctx_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return NULL;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return NULL;
	}

	task_num = npu_get_available_task_num(dev_ctx);
	if (task_num == 0) {
		NPU_ERR("no available task\n");
		return NULL;
	}

	task_info = npu_get_one_task_id(dev_ctx);
	if (task_info == NULL) {
		NPU_ERR("get one task info by dev_ctx failed\n");
		return NULL;
	}

	return task_info;
}

int npu_free_task_id(u8 dev_ctx_id, u32 task_id)
{
	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_task_info *task_info = NULL;

	if ((dev_ctx_id >= NPU_DEV_NUM) || (task_id >= DEVDRV_MAX_TASK_ID)) {
		NPU_ERR("invalid input argument\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	task_info = npu_find_one_task(dev_ctx, task_id);
	if (task_info == NULL) {
		NPU_ERR("can not find task by device context\n");
		return -ENODATA;
	}

	list_del(&task_info->list);
	list_add(&task_info->list, &dev_ctx->task_available_list);
	dev_ctx->task_id_num++;

	return 0;
}

int npu_task_list_destroy(u8 dev_ctx_id)
{
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	struct npu_dev_ctx *dev_ctx = NULL;

	if (dev_ctx_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL || dev_ctx->task_id_num == 0) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	if (!list_empty_careful(&dev_ctx->task_available_list)) {
		if (dev_ctx->task_id_num <= 0) {
			NPU_ERR("dev_ctx->task_id_num is error\n");
			return 0;
		}
		list_for_each_safe(pos, n, &dev_ctx->task_available_list) {
			dev_ctx->task_id_num--;
			list_del(pos);
		}
	}
	TEE_Free(dev_ctx->task_addr);
	dev_ctx->task_addr = NULL;
	dev_ctx->task_id_num = 0;
	return 0;
}
