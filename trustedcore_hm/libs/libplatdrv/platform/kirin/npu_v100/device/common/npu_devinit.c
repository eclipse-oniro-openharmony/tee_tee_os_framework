/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about devinit and destroy
 */

#include "npu_devinit.h"
#include <errno.h>
#include "drv_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "npu_shm.h"
#include "npu_sink_stream.h"
#include "npu_stream.h"
#include "npu_mailbox.h"
#include "npu_calc_sq.h"
#include "npu_calc_cq.h"
#include "npu_pm.h"
#include "npu_event.h"
#include "npu_model.h"
#include "npu_task.h"
#include "npu_doorbell.h"
#include "npu_common.h"

#define COND_GOTO_ERROR(COND, LABEL, ERROR, ERRCODE, ...) \
	COND_GOTO_WITH_ERRCODE_((COND), LABEL, ERROR, ERRCODE, ##__VA_ARGS__)

// Do NOT use this Marco directly
#define COND_GOTO_WITH_ERRCODE_(COND, LABEL, ERROR, ERRCODE, ...) \
	if (COND) {                \
		NPU_ERR(__VA_ARGS__); \
		ERROR = (ERRCODE);                \
		goto LABEL;                     \
	}

static int npu_resource_list_init(u8 dev_id)
{
	int ret;
	ret = npu_stream_list_init(dev_id);
	if (ret != 0) {
		NPU_ERR("npu dev id = %u non sink stream list init failed\n", dev_id);
		return -1;
	}

	ret = npu_sink_stream_list_init(dev_id);
	COND_GOTO_ERROR(ret != 0, sink_stream_list_init_failed, ret, -1,
	                "npu dev id = %u sink stream list init failed\n",dev_id);
	ret = npu_sq_list_init(dev_id);
	COND_GOTO_ERROR(ret != 0, sq_list_init_failed, ret, -1, "npu dev id = %d sq list init failed\n", dev_id);

	ret = npu_cq_list_init(dev_id);
	COND_GOTO_ERROR(ret != 0, cq_list_init_failed, ret, -1, "npu dev id = %d cq list init failed\n", dev_id);

	ret = npu_event_list_init(dev_id);
	COND_GOTO_ERROR(ret != 0, event_list_init_failed, ret, -1, "npu dev id = %d event list init failed\n",
	                dev_id);

	ret = npu_model_list_init(dev_id);
	COND_GOTO_ERROR(ret != 0, model_list_init_failed, ret, -1, "npu dev id = %d model list init failed\n",
	                dev_id);

	ret = npu_task_list_init(dev_id);
	if (ret != 0) {
		NPU_ERR("npu dev id = %d task list init failed\n", dev_id);
		ret = -1;
		goto task_list_init_failed;
	}

	ret = npu_mailbox_init(dev_id);
	if (ret != 0) {
		NPU_ERR("npu dev id = %d mailbox init failed\n", dev_id);
		ret = -1;
		goto mailbox_init_failed;
	}

	return ret;
mailbox_init_failed:
	npu_task_list_destroy(dev_id);
task_list_init_failed:
	npu_model_list_destroy(dev_id);
model_list_init_failed:
	npu_event_list_destroy(dev_id);
event_list_init_failed:
	npu_cq_list_destroy(dev_id);
cq_list_init_failed:
	npu_sq_list_destroy(dev_id);
sq_list_init_failed:
	npu_sink_stream_list_destroy(dev_id);
sink_stream_list_init_failed:
	npu_stream_list_destroy(dev_id);
	return ret;
}

static void npu_resource_list_destroy(u8 dev_id)
{
	npu_model_list_destroy(dev_id);
	npu_task_list_destroy(dev_id);
	npu_event_list_destroy(dev_id);
	npu_cq_list_destroy(dev_id);
	npu_sq_list_destroy(dev_id);
	npu_stream_list_destroy(dev_id);
}

static void npu_syn_res_init(struct npu_dev_ctx *dev_ctx)
{
	(void)pthread_mutex_init(&dev_ctx->open_close_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->pm_mutex, NULL); // power management
	(void)pthread_mutex_init(&dev_ctx->calc_cq_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->mailbox_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->stream_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->event_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->model_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->task_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->notify_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->cma_mutex, NULL);
	(void)pthread_mutex_init(&dev_ctx->mbx_send_mutex, NULL);

	atomic_set(&dev_ctx->accessible, 1);
	atomic_set(&dev_ctx->poweron_access, 1);
	atomic_set(&dev_ctx->poweron_success, 1);
}

static void npu_syn_res_deinit(struct npu_dev_ctx *dev_ctx)
{
	pthread_mutex_destroy(&dev_ctx->open_close_mutex);
	pthread_mutex_destroy(&dev_ctx->pm_mutex); // power management
	pthread_mutex_destroy(&dev_ctx->calc_cq_mutex);
	pthread_mutex_destroy(&dev_ctx->mailbox_mutex);
	pthread_mutex_destroy(&dev_ctx->stream_mutex);
	pthread_mutex_destroy(&dev_ctx->event_mutex);
	pthread_mutex_destroy(&dev_ctx->model_mutex);
	pthread_mutex_destroy(&dev_ctx->task_mutex);
	pthread_mutex_destroy(&dev_ctx->notify_mutex);
	pthread_mutex_destroy(&dev_ctx->cma_mutex);
	pthread_mutex_destroy(&dev_ctx->mbx_send_mutex);

	atomic_set(&dev_ctx->accessible, 0);
	atomic_set(&dev_ctx->poweron_access, 0);
	atomic_set(&dev_ctx->poweron_success, 0);
}

/*
 * npu_register - register a new npu device
 * @NPU_INFO: npu device info
 *
 * returns zero n success
 */
static int npu_register(u8 dev_id)
{
	struct npu_dev_ctx *dev_ctx = NULL;
	int ret;

	NPU_DEBUG("dev %u npu_register started\n", dev_id);

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id = %u\n", dev_id);
		return -1;
	}

	dev_ctx = (struct npu_dev_ctx *)TEE_Malloc(sizeof(struct npu_dev_ctx), 0);
	if (dev_ctx == NULL) {
		NPU_ERR("kmalloc devid = %u dev_ctx failed\n", dev_id);
		return -ENOMEM;
	}

	set_dev_ctx_with_dev_id(dev_ctx, dev_id);
	dev_ctx->devid = dev_id;
	dev_ctx->power_stage = DEVDRV_PM_DOWN;

	ret = npu_shm_init(dev_id);
	if (ret != 0) {
		NPU_ERR("dev %d shm init failed\n", dev_id);
		ret = -ENODEV;
		goto shm_init_fail;
	}

	ret = npu_resource_list_init(dev_id);
	if (ret != 0) {
		NPU_ERR("npu dev id = %u resource list init failed\n", dev_id);
		ret = -ENODEV;
		goto resource_list_init;
	}

	INIT_LIST_HEAD(&dev_ctx->proc_ctx_list); // init proc_ctx list
	npu_syn_res_init(dev_ctx);

	NPU_DEBUG("npu_register succeed\n");

	return 0;

resource_list_init:
	npu_shm_destroy(dev_id);
shm_init_fail:
	TEE_Free(dev_ctx);
	dev_ctx = NULL;
	set_dev_ctx_with_dev_id(NULL, dev_id);
	return ret;
}

/*
 * npu_unregister - unregister a npu device
 * @NPU_INFO: npu device info
 *
 * returns zero on success
 */
void npu_unregister(u8 dev_id)
{
	struct npu_dev_ctx *dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id = %d\n", dev_id);
		return;
	}

	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return;
	};

	npu_resource_list_destroy(dev_id);
	npu_syn_res_deinit(dev_ctx);
	npu_shm_destroy(dev_id);

	TEE_Free(dev_ctx);
	dev_ctx = NULL;
}

int npu_devinit(u8 dev_id)
{
	int ret;

	NPU_DEBUG("npu dev %u init start\n", dev_id);

	dev_ctx_array_init();

	ret = npu_register(dev_id);
	if (ret != 0) {
		NPU_ERR("npu %d npu_register failed \n", dev_id);
		ret = -1;
		goto npu_register_fail;
	}

	NPU_DEBUG("npu dev %d init succeed \n", dev_id);
	return ret;

npu_register_fail:
	return ret;
}

void npu_devexit(u8 dev_id)
{
	npu_unregister(dev_id);
}
