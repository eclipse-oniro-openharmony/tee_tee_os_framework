#include "npu_proc_ctx_mngr.h"
#include "tee_mem_mgmt_api.h"
#include "npu_log.h"

static inline int npu_init_proc_ctx(npu_proc_ctx_t *proc_ctx, npu_dev_ctx_t *dev_ctx)
{
	INIT_LIST_HEAD(&(proc_ctx->list_node));
	proc_ctx->dev_ctx = dev_ctx;

	INIT_LIST_HEAD(&(proc_ctx->task_list));
	INIT_LIST_HEAD(&(proc_ctx->stream_list));
	INIT_LIST_HEAD(&(proc_ctx->model_list));
	INIT_LIST_HEAD(&(proc_ctx->event_list));
	INIT_LIST_HEAD(&(proc_ctx->sq_list));

	return 0;
}

static inline void npu_free_proc_ctx_sq(npu_proc_ctx_t *proc_ctx)
{
	npu_hwts_sq_t *sq = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	struct list_head *n = NULL;
	struct list_head *pos = NULL;
	list_for_each_safe(pos, n, &(proc_ctx->sq_list)) {
		sq = list_entry(pos, npu_hwts_sq_t, list_node);

		list_del(pos);
		npu_free_hwts_sq(&(dev_ctx->sq_mngr), sq->sq_id);
	}
}

static inline void npu_free_proc_ctx_task(npu_proc_ctx_t *proc_ctx)
{
	npu_task_info_t *task_info = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	struct list_head *n = NULL;
	struct list_head *pos = NULL;
	list_for_each_safe(pos, n, &(proc_ctx->task_list)) {
		task_info = list_entry(pos, npu_task_info_t, list_node);

		list_del(pos);
		npu_free_task_info(&(dev_ctx->task_mngr), task_info->task_id);
	}
}

static inline void npu_free_proc_ctx_event(npu_proc_ctx_t *proc_ctx)
{
	npu_event_info_t *event_info = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	struct list_head *n = NULL;
	struct list_head *pos = NULL;
	list_for_each_safe(pos, n, &(proc_ctx->event_list)) {
		event_info = list_entry(pos, npu_event_info_t, list_node);

		list_del(pos);
		npu_free_event_info(&(dev_ctx->event_mngr), event_info->event_id);
	}
}

static inline void npu_free_stream_to_dev(struct list_head *head, npu_dev_ctx_t *dev_ctx)
{
	struct list_head *n = NULL;
	struct list_head *pos = NULL;
	npu_stream_info_t *stream_info = NULL;

	list_for_each_safe(pos, n, head) {
		stream_info = list_entry(pos, npu_stream_info_t, list_node);

		list_del(pos);
		npu_free_stream_info(&(dev_ctx->stream_mngr), stream_info->stream_id);
	}
}

static inline void npu_free_proc_ctx_model(npu_proc_ctx_t *proc_ctx)
{
	npu_model_info_t *model_info = NULL;
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;

	struct list_head *n = NULL;
	struct list_head *pos = NULL;
	list_for_each_safe(pos, n, &(proc_ctx->model_list)) {
		model_info = list_entry(pos, npu_model_info_t, list_node);
		npu_free_stream_to_dev(&(model_info->stream_list), dev_ctx);

		list_del(pos);
		npu_free_model_info(&(dev_ctx->model_mngr), model_info->model_id);
	}
}

static inline void npu_free_proc_ctx_stream(npu_proc_ctx_t *proc_ctx)
{
	npu_dev_ctx_t *dev_ctx = proc_ctx->dev_ctx;
	npu_free_stream_to_dev(&(proc_ctx->stream_list), dev_ctx);
}

void npu_deinit_proc_ctx(npu_proc_ctx_t *proc_ctx)
{
	npu_free_proc_ctx_sq(proc_ctx);
	npu_free_proc_ctx_task(proc_ctx);
	npu_free_proc_ctx_event(proc_ctx);
	npu_free_proc_ctx_model(proc_ctx);
	npu_free_proc_ctx_stream(proc_ctx);
}

npu_proc_ctx_t *npu_create_proc_ctx(npu_dev_ctx_t *dev_ctx)
{
	int ret;
	npu_proc_ctx_t *proc_ctx = NULL;

	if (!list_empty(&dev_ctx->proc_ctx_list)) {
		NPU_DRV_ERR("dev_ctx->proc_ctx_list is not empty, clear it\n");
		proc_ctx = npu_get_proc_ctx(dev_ctx);
		if (proc_ctx == NULL) {
			NPU_DRV_ERR("get proc_ctx fail, fatal\n");
			return NULL;
		}

		npu_destroy_proc_ctx(proc_ctx);
	}

	proc_ctx = TEE_Malloc(sizeof(npu_proc_ctx_t), 0);
	if (proc_ctx == NULL) {
		NPU_DRV_ERR("TEE_Malloc nullptr, no memory\n");
		return NULL;
	}

	ret = npu_init_proc_ctx(proc_ctx, dev_ctx);
	if (ret != 0) {
		NPU_DRV_ERR("npu_init_proc_ctx fail, ret=%d\n", ret);
		TEE_Free(proc_ctx);
		return NULL;
	}

	list_add(&proc_ctx->list_node, &dev_ctx->proc_ctx_list);

	return proc_ctx;
}

npu_proc_ctx_t *npu_get_proc_ctx(npu_dev_ctx_t *dev_ctx)
{
	npu_proc_ctx_t *proc_ctx = NULL;
	if (!list_empty(&dev_ctx->proc_ctx_list)) {
		proc_ctx = list_first_entry(&dev_ctx->proc_ctx_list, npu_proc_ctx_t, list_node);
	}

	return proc_ctx;
}

void npu_destroy_proc_ctx(npu_proc_ctx_t *proc_ctx)
{
	list_del(&proc_ctx->list_node);

	npu_deinit_proc_ctx(proc_ctx);

	TEE_Free(proc_ctx);
}

