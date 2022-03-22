/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu recycle
 */

#include "npu_recycle.h"
#include <string.h>

#include <errno.h>

#include "drv_log.h"
#include "npu_event.h"
#include "npu_model.h"
#include "npu_task.h"
#include "npu_mailbox_msg.h"
#include "npu_proc_ctx.h"
#include "npu_custom_info_share.h"
#include "npu_common.h"
#include "npu_calc_cq.h"
#include "npu_calc_sq.h"
#include "npu_stream.h"
#include "npu_shm.h"
#include "npu_pm.h"
#include "npu_platform.h"

static int npu_inform_recycle_event_id(struct npu_proc_ctx *proc_ctx)
{
	int ret;
	int result = 0;
	struct npu_event_info *event_info = NULL;
	struct npu_recycle_event_msg recycle_event;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	COND_RETURN_ERROR(list_empty_careful(&proc_ctx->event_list), 0);

	if (memset_s(&recycle_event, sizeof(struct npu_recycle_event_msg),
	             0xFF, sizeof(struct npu_recycle_event_msg)) != EOK) {
		NPU_ERR("memset_s recycle_event failed\n");
	}

	recycle_event.count = 0;
	list_for_each_safe(pos, n, &proc_ctx->event_list) {
		event_info = list_entry(pos, struct npu_event_info, list);

		recycle_event.count++;
		ret = npu_create_recycle_event_msg(event_info, &recycle_event);
		COND_RETURN_ERROR(ret != 0, -1, "create recycle event msg failed\n");

		if (recycle_event.count >= DEVDRV_RECYCLE_MAX_EVENT_NUM) {
			ret = npu_mailbox_message_send_for_res(proc_ctx->devid, (u8 *)&recycle_event,
				sizeof(struct npu_recycle_event_msg), &result);
			COND_RETURN_ERROR((ret != 0) || (result != 0), -1, "send recycle event id message failed\n");
			if (memset_s(&recycle_event, sizeof(struct npu_recycle_event_msg), 0xFF,
				sizeof(struct npu_recycle_event_msg)) != EOK) {
				NPU_ERR("memset_s recycle_event fail");
			}
			recycle_event.count = 0;
		}
	}
	if (recycle_event.count == 0) {
		return 0;
	}

	ret = npu_create_recycle_event_msg(event_info, &recycle_event);
	if (ret != 0) {
		NPU_ERR("create recycle event msg failed\n");
		return -1;
	}

	ret = npu_mailbox_message_send_for_res(proc_ctx->devid, (u8 *)&recycle_event,
		sizeof(struct npu_recycle_event_msg), &result);
	if ((ret != 0) || (result != 0)) {
		NPU_ERR("send recycle less 25 event id message failed\n");
		return -1;
	}

	NPU_DEBUG("recycle event id inform ts succeed\n");
	return 0;
}

int npu_recycle_event_id(struct npu_proc_ctx *proc_ctx)
{
	struct npu_event_info *event_info = NULL;
	struct npu_dev_ctx* cur_dev_ctx = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	int inform_ts = DEVDRV_NO_NEED_TO_INFORM;
	int ret;

	if (list_empty_careful(&proc_ctx->event_list)) {
		NPU_ERR("proc context event list is empty\n");
		return 0;
	}

	cur_dev_ctx = get_dev_ctx_by_id(proc_ctx->devid);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", proc_ctx->devid);
		return -EINVAL;
	}

	MUTEX_LOCK(pm);
	if (cur_dev_ctx->power_stage != DEVDRV_PM_UP) {
		NPU_WARN("recyle event no need to inform ts\n");
		inform_ts = DEVDRV_NO_NEED_TO_INFORM;
	} else {
		NPU_WARN("recyle event inform ts\n");
		inform_ts = DEVDRV_HAVE_TO_INFORM;
	}

	if (inform_ts == DEVDRV_HAVE_TO_INFORM) {
		ret = npu_inform_recycle_event_id(proc_ctx);
		if (ret != 0) {
			MUTEX_UNLOCK(pm);
			NPU_ERR("inform recycle event id failed\n");
			return -1;
		}
	}
	MUTEX_UNLOCK(pm);

	list_for_each_safe(pos, n, &proc_ctx->event_list) {
		event_info = list_entry(pos, struct npu_event_info, list);
		if (event_info != NULL) {
			(void)npu_proc_free_event(proc_ctx, event_info->id);
		}
	}

	NPU_DEBUG("recycle %d event resource success,inform_ts = %d \n", proc_ctx->event_num, inform_ts);
	return 0;
}

void npu_recycle_model_id(struct npu_proc_ctx *proc_ctx)
{
	struct npu_model_info *model_info = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	if (list_empty_careful(&proc_ctx->model_list)) {
		NPU_ERR("proc context model list is empty\n");
		return;
	}

	list_for_each_safe(pos, n, &proc_ctx->model_list) {
		model_info = list_entry(pos, struct npu_model_info, list);
		if (model_info != NULL) {
			(void)npu_proc_free_model(proc_ctx, model_info->id);
		}
	}
}

void npu_recycle_task_id(struct npu_proc_ctx *proc_ctx)
{
	struct npu_task_info *task_info = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	if (list_empty_careful(&proc_ctx->task_list)) {
		NPU_ERR("proc context task list is empty\n");
		return;
	}

	list_for_each_safe(pos, n, &proc_ctx->task_list) {
		task_info = list_entry(pos, struct npu_task_info, list);
		if (task_info != NULL) {
			(void)npu_proc_free_task(proc_ctx, task_info->id);
		}
	}
}

bool npu_is_proc_resource_leaks(struct npu_proc_ctx *proc_ctx)
{
	bool result = false;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return false;
	}

	if (!list_empty_careful(&proc_ctx->message_list_header) ||
		atomic_read(&proc_ctx->mailbox_message_count) ||
		!list_empty_careful(&proc_ctx->stream_list) ||
		!list_empty_careful(&proc_ctx->event_list) ||
		!list_empty_careful(&proc_ctx->model_list) ||
		!list_empty_careful(&proc_ctx->task_list)) {
		result = true;
	}

	return result;
}

void npu_resource_leak_print(struct npu_proc_ctx *proc_ctx)
{
	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return;
	}

	if (!list_empty_careful(&proc_ctx->message_list_header)) {
		NPU_ERR("message_list_header is not empty\n");
	}

	if (atomic_read(&proc_ctx->mailbox_message_count)) {
		NPU_ERR("leak mailbox_message_count is %d \n", proc_ctx->mailbox_message_count.counter);
	}

	if (!list_empty_careful(&proc_ctx->stream_list)) {
		NPU_ERR("some stream id are not released, stream num = %d\n", proc_ctx->stream_num);
	}

	if (!list_empty_careful(&proc_ctx->event_list)) {
		NPU_ERR("some event id are not released, event num = %d\n", proc_ctx->event_num);
	}

	if (!list_empty_careful(&proc_ctx->model_list)) {
		NPU_ERR("some model id are not released, model num = %d\n", proc_ctx->model_num);
	}

	if (!list_empty_careful(&proc_ctx->task_list)) {
		NPU_ERR("some task id are not released, task num = %d\n", proc_ctx->task_num);
	}
}

static int npu_recycle_stream(struct npu_proc_ctx *proc_ctx)
{
	struct npu_stream_sub_info *stream_sub = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	int error = 0;
	int ret;

	if (list_empty_careful(&proc_ctx->stream_list)) {
		NPU_DEBUG("no stream leaks, no need to recycle\n");
		return 0;
	}

	// traverse all streams of current process
	list_for_each_safe(pos, n, &proc_ctx->stream_list) {
		stream_sub = list_entry(pos, struct npu_stream_sub_info, list);
		ret = npu_proc_free_stream(proc_ctx, stream_sub->id);
		if (ret != 0) {
			error++;
		}
	}

	if (error != 0) {
		error = -error;
		NPU_ERR("recycle %d stream resource error happened, error times = %d\n",
		        proc_ctx->stream_num, error);
		return -1;
	}

	NPU_DEBUG("recycle %d stream resource success \n", proc_ctx->stream_num);
	return 0;
}

static void npu_recycle_cq(struct npu_proc_ctx *proc_ctx)
{
	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return;
	}

	npu_unbind_proc_ctx_with_cq_int_ctx(proc_ctx);
	(void)npu_remove_proc_ctx(&proc_ctx->dev_ctx_list, proc_ctx->devid);
	(void)npu_proc_free_cq(proc_ctx);
}

void npu_recycle_npu_resources(struct npu_proc_ctx *proc_ctx)
{
	struct npu_dev_ctx* cur_dev_ctx = NULL;
	int ret;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return;
	}

	cur_dev_ctx = get_dev_ctx_by_id(proc_ctx->devid);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx is null,no leak resource get recycled\n");
		return;
	}

	/* recycle proc_ctx mailbox message */
	if (!list_empty_careful(&proc_ctx->message_list_header)) {
	}

	if (atomic_read(&proc_ctx->mailbox_message_count)) {
	}

	/* recycle stream */
	ret = npu_recycle_stream(proc_ctx);
	if (ret != 0) {
		NPU_ERR("npu_recycle_stream failed\n");
		goto recycle_error;
	}

	/* recycle event */
	ret = npu_recycle_event_id(proc_ctx);
	if (ret != 0) {
		NPU_ERR("npu_recycle_event failed\n");
		goto recycle_error;
	}

	/* recycle model */
	npu_recycle_model_id(proc_ctx);
	npu_recycle_task_id(proc_ctx);

	/* recycle cq */
	npu_recycle_cq(proc_ctx);

	// unbind
	npu_unbind_proc_ctx_with_cq_int_ctx(proc_ctx);
	(void)npu_remove_proc_ctx(&proc_ctx->dev_ctx_list, proc_ctx->devid);
	NPU_WARN("recycle all sources success\n");

	goto recycle_out;

recycle_error:
	NPU_WARN("failed to recycle sources, some sources are unavailable\n");
	npu_add_proc_ctx_to_rubbish_ctx_list(&proc_ctx->dev_ctx_list, proc_ctx->devid);
recycle_out:
	return;
}
