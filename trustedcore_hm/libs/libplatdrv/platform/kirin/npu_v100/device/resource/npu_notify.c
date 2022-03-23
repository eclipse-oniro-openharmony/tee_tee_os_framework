/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu notify
 */

#include "npu_notify.h"
#include <errno.h>

#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "drv_log.h"
#include "npu_common.h"
#include "npu_pm.h"
#include "npu_custom_info_share.h"
#include "npu_spec_share.h"

static struct npu_notify_info *npu_find_one_notify_id(struct npu_dev_ctx *dev_ctx, int id)
{
	int ret;
	struct npu_notify_info *notify_info = NULL;

	notify_info = (struct npu_notify_info *)(dev_ctx->notify_addr +
		(long)sizeof(struct npu_notify_info) * id);
	return notify_info;
}

static u32 npu_get_available_notify_num(struct npu_dev_ctx *dev_ctx)
{
	u32 notify_num;

	notify_num = dev_ctx->notify_id_num;

	return notify_num;
}

static struct npu_notify_info *npu_get_one_notify_id(struct npu_dev_ctx *dev_ctx)
{
	struct npu_notify_info *notify_info = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	if (!list_empty_careful(&dev_ctx->notify_available_list)) {
		if (dev_ctx->notify_id_num <= 0) {
			NPU_ERR("dev_ctx->notify_id_num is error\n");
			return NULL;
		}
		list_for_each_safe(pos, n, &dev_ctx->notify_available_list) {
			notify_info = list_entry(pos, struct npu_notify_info, list);
			list_del(&notify_info->list);
			dev_ctx->notify_id_num--;
			return notify_info;
		}
	}

	return NULL;
}

int npu_notify_ts_msg(struct npu_dev_ctx *dev_ctx, int notify_Id)
{
	struct npu_ts_notify_msg msg;
	int result;
	int ret;

	msg.header.valid = DEVDRV_MAILBOX_MESSAGE_VALID;
	msg.header.cmd_type = DEVDRV_MAILBOX_RESET_NOTIFY_ID;
	msg.header.result = 0;
	msg.notifyId = notify_Id;

	ret = npu_mailbox_message_send_for_res(&dev_ctx->mailbox, (u8 *) &msg, sizeof(msg), &result);
	if (ret != 0 || result != 0) {
		NPU_ERR("notify alloc inform ts failed\n");
		return -EFAULT;
	};
	return 0;
}

int npu_free_one_notify_id(struct npu_dev_ctx *dev_ctx,
                           int id, int inform_type)
{
	int ret;
	struct npu_notify_info *notify_info = NULL;

	if (id < 0 || id > DEVDRV_MAX_NOTIFY_ID || dev_ctx == NULL) {
		NPU_ERR("invalid inpu argument\n");
		return -1;
	}

	notify_info = npu_find_one_notify_id(dev_ctx, id);
	if (notify_info == NULL) {
		NPU_ERR("find notify id failed\n");
		return -1;
	}

	list_del(&notify_info->list);
	list_add(&notify_info->list, &dev_ctx->notify_available_list);
	dev_ctx->notify_id_num++;

	if (inform_type == DEVDRV_NOTIFY_INFORM_TS) {
		ret = npu_notify_ts_msg(dev_ctx, notify_info->id);
		if (ret != 0) {
			NPU_ERR("send ts notify alloc msg failed, notify id = %d\n", notify_info->id);
			goto notify_ts_msg_failed;
		}
	}

	return 0;

notify_ts_msg_failed:
	list_del(&notify_info->list);
	dev_ctx->notify_id_num--;

	return ret;
}

int npu_notify_software_register(int dev_ctx_id)
{
	struct npu_dev_ctx *dev_ctx = NULL;

	if ((dev_ctx_id < 0) || (dev_ctx_id > NPU_DEV_NUM)) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	return npu_dev_software_register(dev_ctx,
		npu_notify_list_init, npu_notify_list_init, npu_notify_list_init, npu_notify_list_init);
}

int npu_notify_list_init(int dev_ctx_id)
{
	u32 i;
	u32 notify_num = DEVDRV_MAX_NOTIFY_ID;
	unsigned long size;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_notify_info *notify_info = NULL;

	if ((dev_ctx_id < 0) || (dev_ctx_id > NPU_DEV_NUM)) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n");
		return -ENODATA;
	}

	if (!list_empty_careful(&dev_ctx->notify_available_list)) {
		NPU_ERR("available notify list is not empty\n");
		return -EEXIST;
	}

	size = (long)(unsigned)sizeof(struct npu_notify_info) * notify_num;
	notify_info = TEE_Malloc(size, 0);
	if (notify_info == NULL) {
		NPU_ERR("notify_info vmalloc failed\n");
		return -ENOMEM;
	}

	dev_ctx->notify_id_num = 0;
	for (i = 0; i < notify_num; i++) {
		notify_info[i].id = i;
		notify_info[i].devid = dev_ctx->devid;
		list_add_tail(&notify_info[i].list, &dev_ctx->notify_available_list);
		dev_ctx->notify_id_num++;
	}
	dev_ctx->notify_addr = notify_info;

	return 0;
}

int copy_to_TA_safe(void  *to, const void *from, unsigned long n)
{
	if (to == NULL || n == 0) {
		NPU_ERR("user pointer is NULL\n");
		return -1;
	}

	if (copy_to_user(to, (void *)from, n)) {
		return -ENODEV;
	}

	return 0;
}

int npu_alloc_notify_id(int dev_ctx_id, unsigned long arg)
{
	u32 notify_num;
	int ret;

	struct npu_dev_ctx *dev_ctx = NULL;
	struct npu_notify_info *notify_info = NULL;

	COND_RETURN_ERROR((dev_ctx_id < 0) || (dev_ctx_id > NPU_DEV_NUM), -1, "device id is illegal\n");

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	COND_RETURN_ERROR(dev_ctx == NULL, -ENODATA, "get device context by device id failed\n");

	mutex_lock(&dev_ctx->notify_mutex_t);
	notify_num = npu_get_available_notify_num(dev_ctx);
	if (notify_num == 0) {
		NPU_ERR("no available model\n");
		mutex_unlock(&dev_ctx->notify_mutex_t);
		return -ENODATA;
	}
	mutex_unlock(&dev_ctx->notify_mutex_t);

	notify_info = npu_get_one_notify_id(dev_ctx);
	COND_RETURN_ERROR(notify_info == NULL, -1, "get one notify info by dev_ctx failed\n");

	ret = npu_notify_ts_msg(dev_ctx, notify_info->id);
	if (ret != 0) {
		NPU_ERR("send ts notify alloc msg failed, notify id = %d\n", notify_info->id);
		goto notify_ts_msg_failed;
	}

	if (copy_to_TA_safe((void *)arg, &notify_info->id, sizeof(int))) {
		NPU_ERR("copy_to_TA_safe failed\n");
		goto copy_to_TA_safe_failed;
	}

	return 0;

notify_ts_msg_failed:
	if (npu_free_one_notify_id(dev_ctx, notify_info->id, DEVDRV_NOTIFY_NOT_INFORM_TS)) {
		NPU_ERR("free one notify id failed, id = %d\n", notify_info->id);
		return -1;
	}
	return -EFAULT;

copy_to_TA_safe_failed:
	if (npu_free_one_notify_id(dev_ctx, notify_info->id, DEVDRV_NOTIFY_INFORM_TS)) {
		NPU_ERR("free one notify id failed, id = %d\n", notify_info->id);
		return -1;
	}
	return -EFAULT;
}

int npu_free_notify_id(int dev_ctx_id, unsigned long arg)
{
	int ret;
	int id;
	struct npu_dev_ctx *dev_ctx = NULL;

	if ((dev_ctx_id < 0) || (dev_ctx_id > NPU_DEV_NUM)) {
		NPU_ERR("device id is illegal\n");
		return -1;
	}

	dev_ctx = get_dev_ctx_by_id(dev_ctx_id);
	if (dev_ctx == NULL) {
		NPU_ERR("get device context by device id failed\n", __func__);
		return -ENODATA;
	}

	if (copy_to_TA_safe(&id, (void *)arg, sizeof(int))) {
		NPU_ERR("copy_to_user_saft error\n");
		return -EFAULT;
	}

	ret = npu_free_one_notify_id(dev_ctx, id, DEVDRV_NOTIFY_INFORM_TS);
	if (ret != 0) {
		NPU_ERR("invalid input argument\n");
		return ret;
	}

	return 0;
}
