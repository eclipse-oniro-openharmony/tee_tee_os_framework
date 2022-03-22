/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu event
 */

#include "npu_event.h"

#include <errno.h>

#include "drv_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "npu_common.h"
#include "npu_custom_info_share.h"
#include "npu_spec_share.h"

static u32 npu_get_available_event_num(struct npu_dev_ctx *dev_ctx)
{
	u32 event_num;

	if (dev_ctx == NULL) {
		NPU_ERR("invalid param dev_ctx is null\n");
		return 0;
	}
	event_num = dev_ctx->event_num;
	return event_num;
}

static struct npu_event_info *npu_get_one_event(struct npu_dev_ctx *dev_ctx)
{
	struct npu_event_info *event_info = NULL;

	if (dev_ctx == NULL) {
		NPU_ERR("invalid param dev_ctx is null\n");
		return NULL;
	}
	if (list_empty_careful(&dev_ctx->event_available_list)) {
		return NULL;
	}

	event_info = list_first_entry(&dev_ctx->event_available_list, struct npu_event_info, list);
	list_del(&event_info->list);
	if (dev_ctx->event_num <= 0) {
		NPU_ERR("dev_ctx->event_num is error\n");
		return NULL;
	}
	dev_ctx->event_num--;
	return event_info;
}

static struct npu_event_info *npu_find_one_event(struct npu_dev_ctx *dev_ctx,
                                                 u32 event_id)
{
	struct npu_event_info *event_info = NULL;

	if (dev_ctx == NULL) {
		NPU_ERR("invalid param dev_ctx is null\n");
		return NULL;
	}
	event_info = (struct npu_event_info *)(dev_ctx->event_addr +
		(long)sizeof(struct npu_event_info) * event_id);

	return event_info->id != (int)event_id ? NULL : event_info;
}


int npu_event_list_init(u8 dev_id)
{
	u32 i;
	u32 event_num = DEVDRV_MAX_EVENT_ID;
	unsigned long size;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_event_info *event_info = NULL;

	if (dev_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	INIT_LIST_HEAD(&dev_ctx->event_available_list);
	if (!list_empty_careful(&dev_ctx->event_available_list)) {
		NPU_ERR("available list not empty\n");
		return -EEXIST;
	}

	size = (long)(unsigned)sizeof(*event_info) * event_num;
	event_info = TEE_Malloc(size, 0);
	if (event_info == NULL) {
		return -ENOMEM;
	}

	dev_ctx->event_num = 0;
	for (i = 0; i < event_num; i++) {
		event_info[i].id = i;
		event_info[i].devid = dev_ctx->devid;
		list_add_tail(&event_info[i].list, &dev_ctx->event_available_list);
		dev_ctx->event_num++;
	}
	dev_ctx->event_addr = (void *)event_info;
	return 0;
}


struct npu_event_info *npu_alloc_event(u8 dev_id)
{
	u32 event_num;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_event_info *event_info = NULL;

	if (dev_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return NULL;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return NULL;
	}

	event_num = npu_get_available_event_num(dev_ctx);
	if (event_num == 0) {
		NPU_ERR("no available event\n");
		return NULL;
	}

	event_info = npu_get_one_event(dev_ctx);
	if (event_info == NULL) {
		NPU_ERR("get one event info by dev_ctx failed\n");
		return NULL;
	}

	return event_info;
}

int npu_free_event_id(u8 dev_id, u32 event_id)
{
	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_event_info *event_info = NULL;

	if ((dev_id >= NPU_DEV_NUM) || (event_id >= DEVDRV_MAX_EVENT_ID)) {
		NPU_ERR("invalid input argument\n");
		return -EINVAL;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	event_info = npu_find_one_event(dev_ctx, event_id);
	if (event_info == NULL) {
		NPU_ERR("can not find event by device context and event id\n");
		return -ENODATA;
	}

	list_del(&event_info->list);
	list_add(&event_info->list, &dev_ctx->event_available_list);
	dev_ctx->event_num++;

	return 0;
}

int npu_event_list_destroy(u8 dev_id)
{
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	struct npu_dev_ctx *dev_ctx = NULL;

	if (dev_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}
	if (!list_empty_careful(&dev_ctx->event_available_list)) {
		list_for_each_safe(pos, n, &dev_ctx->event_available_list) {
			list_del(pos);
		}
	}
	TEE_Free(dev_ctx->event_addr);
	dev_ctx->event_addr = NULL;
	dev_ctx->event_num = 0;
	return 0;
}
