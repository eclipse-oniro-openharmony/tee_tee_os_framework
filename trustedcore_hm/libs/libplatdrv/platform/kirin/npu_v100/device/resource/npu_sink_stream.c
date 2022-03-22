/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about sink stream
 */

#include "npu_sink_stream.h"
#include <errno.h>

#include "drv_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */

#include "npu_custom_info_share.h"
#include "npu_spec_share.h"
#include "npu_stream.h"
#include "npu_shm.h"

int npu_sink_stream_list_init(u8 dev_id)
{
	u32 i;
	unsigned long size;
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	struct npu_stream_sub_info *stream_sub_tmp = NULL;
	struct npu_stream_info *sink_stream_tmp = NULL;
	u32 sink_stream_num = DEVDRV_MAX_SINK_STREAM_ID;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	INIT_LIST_HEAD(&cur_dev_ctx->sink_stream_available_list);
	cur_dev_ctx->sink_stream_num = 0;
	if (!list_empty_careful(&cur_dev_ctx->sink_stream_available_list)) {
		NPU_ERR("available sink stream list not empty\n");
		return -1;
	}

	size = (unsigned long)sizeof(*stream_sub_tmp) * sink_stream_num;
	stream_sub_tmp = TEE_Malloc(size, 0);;
	if (stream_sub_tmp == NULL) {
		NPU_ERR("no sys mem to alloc sink stream list \n");
		return -ENOMEM;
	}
	cur_dev_ctx->sink_stream_sub_addr = (void *)stream_sub_tmp;

	for (i = 0; i < sink_stream_num; i++) {
		sink_stream_tmp = npu_calc_stream_info(dev_id, i + DEVDRV_MAX_NON_SINK_STREAM_ID);
		sink_stream_tmp->id = i + DEVDRV_MAX_NON_SINK_STREAM_ID;
		sink_stream_tmp->devid = cur_dev_ctx->devid;
		sink_stream_tmp->cq_index = (u32) DEVDRV_CQSQ_INVALID_INDEX;
		sink_stream_tmp->sq_index = (u32) DEVDRV_CQSQ_INVALID_INDEX;
		sink_stream_tmp->stream_sub = (void *)(stream_sub_tmp + i);
		stream_sub_tmp[i].proc_ctx = NULL;
		stream_sub_tmp[i].id = sink_stream_tmp->id;
		list_add_tail(&stream_sub_tmp[i].list, &cur_dev_ctx->sink_stream_available_list);
		cur_dev_ctx->sink_stream_num++;
	}
	NPU_DEBUG("cur dev %d own %d sink streams\n", dev_id, cur_dev_ctx->sink_stream_num);
	return 0;
}

int npu_alloc_sink_stream_id(u8 dev_id)
{
	struct npu_stream_sub_info *sub_stream = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	if (list_empty_careful(&cur_dev_ctx->sink_stream_available_list)) {
		NPU_ERR("cur dev %d available sink stream list empty,"
			"left stream_num = %d !!!\n", dev_id, cur_dev_ctx->sink_stream_num);
		return -1;
	}

	sub_stream = list_first_entry(&cur_dev_ctx->sink_stream_available_list, struct npu_stream_sub_info, list);
	list_del(&sub_stream->list);
	if (cur_dev_ctx->sink_stream_num <= 0) {
		NPU_ERR("cur_dev_ctx->sink_stream_num is error\n");
		return -1;
	}
	cur_dev_ctx->sink_stream_num--;
	NPU_DEBUG("cur dev %d left %d sink stream\n", dev_id, cur_dev_ctx->sink_stream_num);

	return sub_stream->id;
}

int npu_free_sink_stream_id(u8 dev_id, u32 stream_id)
{
	struct npu_stream_sub_info *stream_sub_info = NULL;
	struct npu_stream_info *stream_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (stream_id >= DEVDRV_MAX_STREAM_ID ||
		stream_id < DEVDRV_MAX_NON_SINK_STREAM_ID) {
		NPU_ERR("illegal npu stream id %d\n", stream_id);
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}
	stream_info = npu_calc_stream_info(dev_id, stream_id);
	if (stream_info == NULL) {
		NPU_ERR("stream_info %d is null\n", dev_id);
		return -1;
	}
	stream_sub_info = (struct npu_stream_sub_info *)stream_info->stream_sub;
	stream_sub_info->proc_ctx = NULL;

	list_add(&stream_sub_info->list, &cur_dev_ctx->sink_stream_available_list);
	cur_dev_ctx->sink_stream_num++;
	NPU_DEBUG("cur dev %d own %d sink stream\n", dev_id, cur_dev_ctx->sink_stream_num);

	return 0;
}

int npu_sink_stream_list_destroy(u8 dev_id)
{
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	if (!list_empty_careful(&cur_dev_ctx->sink_stream_available_list)) {
		list_for_each_safe(pos, n, &cur_dev_ctx->sink_stream_available_list) {
			list_del(pos);
		}
	}

	TEE_Free(cur_dev_ctx->sink_stream_sub_addr);
	cur_dev_ctx->sink_stream_sub_addr = NULL;
	cur_dev_ctx->sink_stream_num = 0;
	return 0;
}
