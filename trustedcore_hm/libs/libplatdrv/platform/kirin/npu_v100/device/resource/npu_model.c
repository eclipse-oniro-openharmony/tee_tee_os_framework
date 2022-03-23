/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu model
 */

#include "npu_model.h"
#include <errno.h>

#include "drv_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "npu_common.h"
#include "npu_custom_info_share.h"
#include "npu_spec_share.h"

static u32 npu_get_available_model_num(struct npu_dev_ctx *dev_ctx)
{
	u32 model_id_num;

	if (dev_ctx == NULL) {
		NPU_ERR("invalid param dev_ctx is null\n");
		return 0;
	}
	model_id_num = dev_ctx->model_id_num;

	return model_id_num;
}

static struct npu_model_info *npu_get_one_model_id(struct npu_dev_ctx *dev_ctx)
{
	struct npu_model_info *model_info = NULL;

	if (dev_ctx == NULL) {
		NPU_ERR("invalid param dev_ctx is null\n");
		return NULL;
	}

	if (list_empty_careful(&dev_ctx->model_available_list)) {
		return NULL;
	}

	model_info = list_first_entry(&dev_ctx->model_available_list, struct npu_model_info, list);
	list_del(&model_info->list);
	if (dev_ctx->model_id_num <= 0) {
		NPU_ERR("dev_ctx->model_id_num is error\n");
		return NULL;
	}
	dev_ctx->model_id_num--;
	return model_info;
}

static struct npu_model_info *npu_find_one_model(struct npu_dev_ctx *dev_ctx, u32 model_id)
{
	if (dev_ctx == NULL) {
		NPU_ERR("invalid param dev_ctx is null\n");
		return NULL;
	}
	struct npu_model_info *model_info = NULL;
	model_info = (struct npu_model_info *)(dev_ctx->model_addr +
		(long)sizeof(struct npu_model_info) * model_id);

	return model_info->id != (int)model_id ? NULL : model_info;
}

int npu_model_list_init(u8 dev_ctx_id)
{
	u32 i;
	u32 model_num = DEVDRV_MAX_MODEL_ID;
	unsigned long size;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_model_info *model_info = NULL;

	if (dev_ctx_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	INIT_LIST_HEAD(&dev_ctx->model_available_list);
	if (!list_empty_careful(&dev_ctx->model_available_list)) {
		NPU_ERR("available model list is not empty\n");
		return -EEXIST;
	}

	size = (long)(unsigned)sizeof(struct npu_model_info) * model_num;
	model_info = TEE_Malloc(size, 0);
	if (model_info == NULL) {
		NPU_ERR("model_info vmalloc failed\n");
		return -ENOMEM;
	}

	dev_ctx->model_id_num = 0;
	for (i = 0; i < model_num; i++) {
		model_info[i].id = i;
		model_info[i].devid = dev_ctx->devid;
		list_add_tail(&model_info[i].list, &dev_ctx->model_available_list);
		dev_ctx->model_id_num++;
	}
	dev_ctx->model_addr = model_info;

	return 0;
}

struct npu_model_info *npu_alloc_model(u8 dev_ctx_id)
{
	u32 model_num;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_model_info *model_info = NULL;

	if (dev_ctx_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return NULL;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return NULL;
	}

	model_num = npu_get_available_model_num(dev_ctx);
	if (model_num == 0) {
		NPU_ERR("no available model\n");
		return NULL;
	}

	model_info = npu_get_one_model_id(dev_ctx);
	if (model_info == NULL) {
		NPU_ERR("get one model info by dev_ctx failed\n");
		return NULL;
	}

	return model_info;
}

int npu_free_model_id(u8 dev_ctx_id, u32 model_id)
{
	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_model_info *model_info = NULL;

	if ((dev_ctx_id >= NPU_DEV_NUM) || (model_id >= DEVDRV_MAX_MODEL_ID)) {
		NPU_ERR("invalid input argument\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	model_info = npu_find_one_model(dev_ctx, model_id);
	if (model_info == NULL) {
		NPU_ERR("can not find model by device context\n");
		return -ENODATA;
	}

	list_del(&model_info->list);
	list_add(&model_info->list, &dev_ctx->model_available_list);
	dev_ctx->model_id_num++;

	return 0;
}

int npu_model_list_destroy(u8 dev_ctx_id)
{
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	struct npu_dev_ctx *dev_ctx = NULL;

	if (dev_ctx_id > NPU_DEV_NUM) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL || dev_ctx->model_id_num == 0) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	if (!list_empty_careful(&dev_ctx->model_available_list)) {
		list_for_each_safe(pos, n, &dev_ctx->model_available_list) {
			dev_ctx->model_id_num--;
			list_del(pos);
		}
	}
	TEE_Free(dev_ctx->model_addr);
	dev_ctx->model_addr = NULL;

	return 0;
}
