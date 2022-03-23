/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu proc ctx
 */

#include "npu_proc_ctx.h"

#include <errno.h>
#include <hm_unistd.h>
#include "sre_task.h"
#include "drv_pal.h"
#include "drv_log.h"
#include "npu_shm.h"
#include "npu_calc_channel.h"
#include "npu_calc_cq.h"
#include "npu_stream.h"
#include "npu_event.h"
#include "npu_model.h"
#include "npu_task.h"
#include "npu_platform.h"
#include "npu_semaphore.h"
#include "npu_calc_sq.h"

static struct npu_cq_report_int_ctx g_cq_int_ctx;
static u64 g_recv_cq_int_num = 0; // use for debug
static u64 g_find_cq_index_called_num = 0; // use for debug

struct npu_proc_ctx *g_proc_ctx[NPU_MAX_PROC_NUM];


static void npu_ids_status_init(struct npu_proc_ctx *proc_ctx)
{
	if (memset_s(proc_ctx->stream_bitmap, sizeof(proc_ctx->stream_bitmap),
	             0, sizeof(proc_ctx->stream_bitmap)) != EOK) {
		NPU_ERR("memset_s proc_ctx stream_bitmap fail");
	}
	if (memset_s(proc_ctx->event_bitmap, sizeof(proc_ctx->event_bitmap),
	             0, sizeof(proc_ctx->event_bitmap)) != EOK) {
		NPU_ERR("memset_s proc_ctx event_bitmap fail");
	}
	if (memset_s(proc_ctx->model_bitmap, sizeof(proc_ctx->model_bitmap),
	             0, sizeof(proc_ctx->model_bitmap)) != EOK) {
		NPU_ERR("memset_s proc_ctx model_bitmap fail");
	}
	if (memset_s(proc_ctx->task_bitmap, sizeof(proc_ctx->task_bitmap),
	             0, sizeof(proc_ctx->task_bitmap)) != EOK) {
		NPU_ERR("memset_s proc_ctx task_bitmap fail");
	}
}

// only support one process at the same time
void npu_set_proc_ctx(struct npu_proc_ctx *proc_ctx)
{
	if (g_proc_ctx[0] != NULL) {
		NPU_ERR("g_proc_ctx is not null \n");
		return;
	}

	g_proc_ctx[0] = proc_ctx;
}

void npu_clear_proc_ctx(void)
{
	if (g_proc_ctx[0] != NULL) {
		g_proc_ctx[0] = NULL;
		return;
	}
}

struct npu_proc_ctx* npu_get_proc_ctx(int fd)
{
	(void)fd;
	return g_proc_ctx[0];
}

void npu_proc_ctx_init(struct npu_proc_ctx *proc_ctx)
{
	int ret;
	uint32_t ta_pid = 0;

	npu_ids_status_init(proc_ctx);

	INIT_LIST_HEAD(&proc_ctx->cq_list);
	INIT_LIST_HEAD(&proc_ctx->sink_stream_list);
	INIT_LIST_HEAD(&proc_ctx->stream_list);
	INIT_LIST_HEAD(&proc_ctx->event_list);
	INIT_LIST_HEAD(&proc_ctx->model_list);
	INIT_LIST_HEAD(&proc_ctx->task_list);
	INIT_LIST_HEAD(&proc_ctx->dev_ctx_list);
	INIT_LIST_HEAD(&proc_ctx->message_list_header);
	INIT_LIST_HEAD(&proc_ctx->ipc_msg_send_head);
	INIT_LIST_HEAD(&proc_ctx->ipc_msg_return_head);

	proc_ctx->stream_num = 0;
	proc_ctx->event_num = 0;
	proc_ctx->cq_num = 0;
	proc_ctx->model_num = 0;
	proc_ctx->task_num = 0;
	proc_ctx->send_count = 0;
	proc_ctx->receive_count = 0;
	proc_ctx->ipc_port = -1;
	proc_ctx->should_stop_thread = 0;
	proc_ctx->mailbox_message_count.counter = 0;

	ret = SRE_TaskSelf(&ta_pid);
	if (ret < 0) {
		NPU_ERR("get ta pid failed");
	}
	NPU_INFO("current hiai ta pid = %d", ta_pid);
	proc_ctx->pid = ta_pid;
}

struct npu_ts_cq_info *npu_proc_alloc_cq(struct npu_proc_ctx *proc_ctx)
{
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_cq_sub_info *cq_sub_info = NULL;

	u8 dev_id;;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return NULL;
	}
	dev_id = proc_ctx->devid;
	cq_info = npu_alloc_cq(dev_id);
	if (cq_info == NULL) {
		NPU_ERR("npu dev %d cq_info is null\n", dev_id);
		return NULL;
	}
	cq_sub_info = (struct npu_cq_sub_info *)cq_info->cq_sub;
	list_add(&cq_sub_info->list, &proc_ctx->cq_list);
	cq_sub_info->proc_ctx = proc_ctx;
	proc_ctx->cq_num++;

	return cq_info;
}

static int npu_proc_get_cq_id(struct npu_proc_ctx *proc_ctx, u32* cq_id)
{
	struct npu_cq_sub_info *cq_sub = NULL;

	if (list_empty_careful(&proc_ctx->cq_list)) {
		NPU_ERR("cur proc_ctx cq_list null\n");
		return -1;
	}

	cq_sub = list_first_entry(&proc_ctx->cq_list, struct npu_cq_sub_info, list);

	*cq_id = cq_sub->index;

	return 0;
}

// protect by stream_mutex when called
int npu_proc_alloc_stream(struct npu_proc_ctx *proc_ctx, u32 *stream_id, u32 strategy)
{
	struct npu_stream_info* stream_info = NULL;
	struct npu_stream_sub_info *stream_sub_info = NULL;
	int ret;
	u32 cq_id;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx ptr is null \n");
		return -1;
	}

	if (stream_id == NULL) {
		NPU_ERR("stream_id ptr is null \n");
		return -1;
	}

	ret = npu_proc_get_cq_id(proc_ctx, &cq_id);
	if (ret != 0) {
		NPU_ERR("get cq_id from proc_ctx cq_list failed \n");
		return -1;
	}
	NPU_DEBUG("get cq_id = %d from proc_ctx cq_list \n", cq_id);

	stream_info = npu_alloc_stream(cq_id, strategy);
	if (stream_info == NULL) {
		NPU_ERR("get stream_info through cq %d failed \n", cq_id);
		return -1;
	}

	NPU_DEBUG("alloc stream success stream_id = %d ,sq_id = %d \n"
	"cq_id = %d", stream_info->id, stream_info->sq_index, stream_info->cq_index);

	stream_info->pid = proc_ctx->pid;
	stream_sub_info = (struct npu_stream_sub_info *)stream_info->stream_sub;
	stream_sub_info->proc_ctx = (void *)proc_ctx;
	if (strategy == STREAM_STRATEGY_SINK) {
		list_add(&stream_sub_info->list, &proc_ctx->sink_stream_list);
		proc_ctx->sink_stream_num++;
	} else {
		list_add(&stream_sub_info->list, &proc_ctx->stream_list);
		proc_ctx->stream_num++;
	}

	NPU_INFO("npu ta_pid = %d plat_drv_pid %d own sink_stream num = %d"
	         " non sink stream num = %d now", proc_ctx->pid, hm_getpid(),
	         proc_ctx->sink_stream_num, proc_ctx->stream_num);
	*stream_id = stream_info->id;

	return 0;
}

int npu_proc_alloc_event(struct npu_proc_ctx *proc_ctx, u32* event_id_ptr)
{
	struct npu_event_info *event_info = NULL;

	if (proc_ctx == NULL || event_id_ptr == NULL) {
		NPU_ERR("proc_ctx ptr or event id ptr is null \n");
		return -EINVAL;
	}

	event_info = npu_alloc_event(proc_ctx->devid);
	if (event_info == NULL) {
		NPU_ERR("event info is null\n");
		*event_id_ptr = DEVDRV_MAX_EVENT_ID;
		return -ENODATA;
	}
	list_add(&event_info->list, &proc_ctx->event_list);
	proc_ctx->event_num++;
	NPU_DEBUG("npu process %d own event num = %d now \n", hm_getpid(), proc_ctx->stream_num);

	*event_id_ptr = event_info->id;
	return 0;
}

int npu_proc_free_event(struct npu_proc_ctx *proc_ctx, u32 event_id)
{
	int ret;

	if (proc_ctx == NULL || event_id >= DEVDRV_MAX_EVENT_ID) {
		NPU_ERR("proc_ctx ptr is null or event id %d is invalid \n", event_id);
		return -1;
	}

	if (proc_ctx->event_num == 0) {
		NPU_ERR("event_num is 0 invalid \n");
		return -EINVAL;
	}

	ret = npu_free_event_id(proc_ctx->devid, event_id);
	if (ret != 0) {
		NPU_ERR("free event id failed\n");
		return -ENODATA;
	}
	proc_ctx->event_num--;
	BITMAP_CLEAR(proc_ctx->event_bitmap, event_id);
	NPU_DEBUG("npu process %d left event num = %d\n", proc_ctx->pid, proc_ctx->event_num);
	return 0;
}

int npu_proc_alloc_model(struct npu_proc_ctx *proc_ctx, u32* model_id_ptr)
{
	struct npu_model_info *model_info = NULL;

	if (proc_ctx == NULL || model_id_ptr == NULL) {
		NPU_ERR("proc_ctx ptr or model id ptr is null \n");
		return -EINVAL;
	}

	model_info = npu_alloc_model(proc_ctx->devid);
	if (model_info == NULL) {
		NPU_ERR("model info is null\n");
		*model_id_ptr = DEVDRV_MAX_MODEL_ID;
		return -ENODATA;
	}

	list_add(&model_info->list, &proc_ctx->model_list);
	proc_ctx->model_num++;
	NPU_DEBUG("npu process %d own model num = %d now \n", hm_getpid(), proc_ctx->model_num);

	*model_id_ptr = model_info->id;
	return 0;
}

int npu_proc_free_model(struct npu_proc_ctx *proc_ctx, u32 model_id)
{
	int ret;

	if (proc_ctx == NULL || model_id >= DEVDRV_MAX_MODEL_ID) {
		NPU_ERR("proc_ctx ptr or model id ptr is null \n");
		return -EINVAL;
	}

	if (proc_ctx->model_num == 0) {
		NPU_ERR("model_num is 0 \n");
		return -EINVAL;
	}

	ret = npu_free_model_id(proc_ctx->devid, model_id);
	if (ret != 0) {
		NPU_ERR("free model id failed\n");
		return -ENODATA;
	}
	proc_ctx->model_num--;
	BITMAP_CLEAR(proc_ctx->model_bitmap, model_id);
	NPU_DEBUG("npu process %d left model num = %d", hm_getpid(), proc_ctx->model_num);

	return 0;
}

int npu_proc_alloc_task(struct npu_proc_ctx *proc_ctx, u32* task_id_ptr)
{
	struct npu_task_info *task_info = NULL;

	if (proc_ctx == NULL || task_id_ptr == NULL) {
		NPU_ERR("proc_ctx ptr or task id ptr is null \n");
		return -EINVAL;
	}

	task_info = npu_alloc_task(proc_ctx->devid);
	if (task_info == NULL) {
		NPU_ERR("task info is null\n");
		*task_id_ptr = DEVDRV_MAX_TASK_ID;
		return -ENODATA;
	}

	list_add(&task_info->list, &proc_ctx->task_list);
	proc_ctx->task_num++;
	NPU_DEBUG("npu process %d own task num = %d now \n", hm_getpid(), proc_ctx->task_num);

	*task_id_ptr = task_info->id;
	return 0;
}

int npu_proc_free_task(struct npu_proc_ctx *proc_ctx, u32 task_id)
{
	int ret;

	if (proc_ctx == NULL || task_id >= DEVDRV_MAX_TASK_ID) {
		NPU_ERR("proc_ctx ptr or task id ptr is null \n");
		return -EINVAL;
	}

	if (proc_ctx->task_num == 0) {
		NPU_ERR("task_num id 0\n");
		return -ENODATA;
	}

	ret = npu_free_task_id(proc_ctx->devid, task_id);
	if (ret != 0) {
		NPU_ERR("free task id failed\n");
		return -ENODATA;
	}
	proc_ctx->task_num--;
	BITMAP_CLEAR(proc_ctx->task_bitmap, task_id);
	NPU_DEBUG("npu process %d left task num = %d", hm_getpid(), proc_ctx->task_num);

	return 0;
}

int npu_proc_free_stream(struct npu_proc_ctx* proc_ctx, u32 stream_id)
{
	struct npu_stream_info* stream_info = NULL;
	struct npu_stream_sub_info *stream_sub_info = NULL;
	u32 sq_send_count = 0;
	u8 dev_id;
	int ret;

	if (proc_ctx == NULL || stream_id >= DEVDRV_MAX_STREAM_ID) {
		NPU_ERR("proc_ctx ptr is null or illegal npu stream id. stream_id=%d\n", stream_id);
		return -1;
	}

	if (stream_id < DEVDRV_MAX_NON_SINK_STREAM_ID && proc_ctx->stream_num == 0) {
			NPU_ERR("stream_num is 0. stream_id=%d \n", stream_id);
			return -1;
	}

	if (stream_id >= DEVDRV_MAX_NON_SINK_STREAM_ID &&
		proc_ctx->sink_stream_num == 0) {
		NPU_ERR("sink stream_num is 0 stream_id=%d \n", stream_id);
		return -1;
	}

	dev_id = proc_ctx->devid;
	stream_info = npu_calc_stream_info(dev_id, stream_id);
	if (stream_info == NULL) {
		NPU_ERR("stream_info is NULL. stream_id=%d\n", stream_id);
		return -1;
	}
	stream_sub_info = (struct npu_stream_sub_info*)stream_info->stream_sub;
	list_del(&stream_sub_info->list);

	ret = npu_free_stream(proc_ctx->devid, stream_id, &sq_send_count);
	if (ret != 0) {
		NPU_ERR("npu process free stream_id %d failed \n", stream_id);
		return -1;
	}
	proc_ctx->send_count += sq_send_count;

	BITMAP_CLEAR(proc_ctx->stream_bitmap, stream_id);
	if (stream_id < DEVDRV_MAX_NON_SINK_STREAM_ID) {
		proc_ctx->stream_num--;
	} else {
		proc_ctx->sink_stream_num--;
	}

	NPU_DEBUG("npu process left stream num = %d sq_send_count = %d (if stream'sq has been released) now\n",
		proc_ctx->stream_num, sq_send_count);
	return 0;
}

int npu_proc_send_alloc_stream_mailbox(struct npu_proc_ctx *proc_ctx)
{
	struct npu_stream_sub_info *stream_sub = NULL;
	struct npu_stream_info *stream_info = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	u8 cur_dev_id = 0;	// get from platform
	int ret;

	if (list_empty_careful(&proc_ctx->stream_list)) {
		NPU_ERR("proc context stream list is empty\n");
		return -1;
	}

	list_for_each_safe(pos, n, &proc_ctx->stream_list) {
		stream_sub = list_entry(pos, struct npu_stream_sub_info, list);
		if (stream_sub == NULL) {
			NPU_ERR("stream sub is null\n");
			return -1;
		}
		stream_info = npu_calc_stream_info(cur_dev_id, stream_sub->id);
		if (stream_info->strategy == STREAM_STRATEGY_SINK) {
			NPU_DEBUG("send no mailbox for sink stream\n");
			continue;
		}

		ret = npu_send_alloc_stream_mailbox(cur_dev_id, stream_sub->id, stream_info->cq_index);
		if (ret) {
			NPU_ERR("send alloc stream %d mailbox failed\n", stream_info->id);
			return ret;
		}
	}

	return 0;
}

static int npu_proc_free_single_cq(struct npu_proc_ctx *proc_ctx, u32 cq_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_cq_sub_info *cq_sub_info = NULL;
	u8 dev_id;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return -1;
	}

	if (cq_id >= DEVDRV_MAX_CQ_NUM) {
		NPU_ERR("illegal npu cq id = %d\n", cq_id);
		return -1;
	}
	dev_id = proc_ctx->devid;
	cq_info = npu_calc_cq_info(dev_id, cq_id);
	cq_sub_info = (struct npu_cq_sub_info *)cq_info->cq_sub;
	proc_ctx->receive_count += cq_info->receive_count;

	// del from proc_ctx->cq_list
	list_del(&cq_sub_info->list);
	proc_ctx->cq_num--;
	// add to dev_ctx->cq_available_list
	(void)npu_free_cq_id(dev_id, cq_id);
	(void)npu_free_cq_mem(dev_id, cq_id);

	NPU_DEBUG("proc_ctx pid %d cq_id %d total receive report count = %d proc current left cq num = %d \n",
		proc_ctx->pid, cq_id, proc_ctx->receive_count, proc_ctx->cq_num);
	return 0;
}

int npu_proc_free_cq(struct npu_proc_ctx *proc_ctx)
{
	struct npu_cq_sub_info *cq_sub = NULL;
	u32 cq_id;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return -1;
	}

	if (list_empty_careful(&proc_ctx->cq_list)) {
		NPU_ERR("cur process %d available cq list empty, left cq_num = %d\n", proc_ctx->pid, proc_ctx->cq_num);
		return -1;
	}

	cq_sub = list_first_entry(&proc_ctx->cq_list, struct npu_cq_sub_info, list);
	cq_id = cq_sub->index;

	return npu_proc_free_single_cq(proc_ctx, cq_id);
}

int npu_proc_clr_sqcq_info(struct npu_proc_ctx *proc_ctx)
{
	struct npu_stream_sub_info *stream_sub = NULL;
	struct npu_stream_info *stream_info = NULL;
	struct npu_cq_sub_info *cq_sub = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	u8 cur_dev_id = 0;	// get from platform

	if (list_empty_careful(&proc_ctx->cq_list)) {
		NPU_DEBUG("proc context cq list is empty, no need clear\n");
		return 0;
	}

	list_for_each_safe(pos, n, &proc_ctx->cq_list) {
		cq_sub = list_entry(pos, struct npu_cq_sub_info, list);
		if (cq_sub != NULL) {
			(void)npu_clr_cq_info(cur_dev_id, cq_sub->index);
		}
	}

	if (list_empty_careful(&proc_ctx->stream_list)) {
		NPU_DEBUG("proc context sq list is empty, no need clear\n");
		return 0;
	}

	list_for_each_safe(pos, n, &proc_ctx->stream_list) {
		stream_sub = list_entry(pos, struct npu_stream_sub_info, list);
		if (stream_sub != NULL) {
			stream_info = npu_calc_stream_info(cur_dev_id, stream_sub->id);
			if (stream_info->strategy == STREAM_STRATEGY_SINK) {
				NPU_DEBUG("send no mailbox for sink stream\n");
				continue;
			}
			(void)npu_clr_sq_info(cur_dev_id, stream_info->sq_index);
		}
	}

	return 0;
}

static irqreturn_t npu_irq_handler(int irq, void *data)
{
	UNUSED(irq);
	UNUSED(data);
	g_recv_cq_int_num++; // user for debug,compare with ts side
	NPU_INFO("cq_irq_cnt = %d ", g_recv_cq_int_num);
	npu_sem_post(CALC_CQ_SEM);

	return IRQ_HANDLED;
}

// just use for debug when exception happened
void show_cq_report_int_info(void)
{
	NPU_ERR("g_recv_cq_int_num = %llu ,g_find_cq_index_called_num: %llu\n",
		g_recv_cq_int_num, g_find_cq_index_called_num);
}

static int __npu_request_cq_report_irq_bh(struct npu_cq_report_int_ctx *cq_int_ctx)
{
	int ret;
	unsigned int cq_irq;
	struct npu_platform_info* plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_info\n");
		return -EINVAL;
	}

	if (cq_int_ctx == NULL) {
		NPU_ERR("cq report int_context is null ");
		return -1;
	}

	cq_irq = DEVDRV_PLAT_GET_CQ_UPDATE_IRQ(plat_info);
	ret = request_irq(cq_irq, (irq_handler_t)npu_irq_handler,
	                  IRQF_TRIGGER_NONE, "npu_cq_report_handler", cq_int_ctx);
	if (ret != 0) {
		NPU_ERR("request cq report irq failed\n");
		goto request_failed;
	}

	NPU_DEBUG("request cq report irq %d success\n", cq_irq);
	return ret;

request_failed:
	free_irq(DEVDRV_PLAT_GET_CQ_UPDATE_IRQ(plat_info), cq_int_ctx);
	return ret;
}


int npu_request_cq_report_irq_bh(void)
{
	NPU_INFO("npu_request_cq_report_irq_bh");
	return __npu_request_cq_report_irq_bh(&g_cq_int_ctx);
}

static int __npu_free_cq_report_irq_bh(struct npu_cq_report_int_ctx *cq_int_ctx)
{
	unsigned int cq_irq;
	struct npu_platform_info* plat_info = npu_plat_get_info();
	if (plat_info == NULL) {
		NPU_ERR("npu_plat_get_info\n");
		return -1;
	}

	if (cq_int_ctx == NULL) {
		NPU_ERR("cq report int_context is null ");
		return -1;
	}

	cq_irq = DEVDRV_PLAT_GET_CQ_UPDATE_IRQ(plat_info);
	free_irq(cq_irq, cq_int_ctx);
	return 0;
}

int npu_free_cq_report_irq_bh(void)
{
	return __npu_free_cq_report_irq_bh(&g_cq_int_ctx);
}

void npu_bind_proc_ctx_with_cq_int_ctx(struct npu_proc_ctx *proc_ctx)
{
	g_cq_int_ctx.proc_ctx = proc_ctx;
}

void npu_unbind_proc_ctx_with_cq_int_ctx(struct npu_proc_ctx *proc_ctx)
{
	if (proc_ctx != NULL) {
		g_cq_int_ctx.proc_ctx = NULL;
	}
}
