/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu calc channel
 */

#include "npu_calc_channel.h"

#include <errno.h>

#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "drv_log.h"
#include "npu_stream.h"
#include "npu_calc_sq.h"
#include "npu_calc_cq.h"
#include "npu_mailbox_msg.h"
#include "npu_mailbox.h"
#include "npu_shm.h"
#include "npu_pm.h"
#include "npu_sink_stream.h"

struct npu_ts_cq_info *npu_alloc_cq(u8 dev_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
	int cq_id;
	int ret;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return NULL;
	}

	cq_id = npu_alloc_cq_id(dev_id);
	if (cq_id < 0) {
		NPU_ERR("alloc cq_id from dev %d failed\n", dev_id);
		return NULL;
	}

	// alloc cq mem (do it through user mmap at the stage of open device currently)
	ret = npu_alloc_cq_mem(dev_id, cq_id);
	if (ret != 0) {
		NPU_ERR("alloc cq mem from dev %d cq %d failed\n", dev_id, cq_id);
		return NULL;
	}

	cq_info = npu_calc_cq_info(dev_id, cq_id);

	return cq_info;
}

int npu_send_alloc_stream_mailbox(u8 cur_dev_id, int stream_id, int cq_id)
{
	struct npu_stream_msg *alloc_stream_msg = NULL;
	int mbx_send_result = -1;
	u32 msg_len;
	int ret;
	int cq_stream_num;

	cq_stream_num = npu_get_cq_ref_by_stream(cur_dev_id, cq_id);
	if (cq_stream_num == 0) {
		NPU_INFO("cq ref by steram add from zero. devid = %d, cq_id = %d\n", cur_dev_id, cq_id);
		(void)npu_clr_cq_info(cur_dev_id, cq_id);
	}

	// for mailbox create stream msg to ts
	(void)npu_inc_cq_ref_by_stream(cur_dev_id, cq_id);

	// call mailbox to info ts to create stream
	alloc_stream_msg = (struct npu_stream_msg *)TEE_Malloc(sizeof(struct npu_stream_msg), 0);
	if (alloc_stream_msg == NULL) {
		ret = -ENOMEM;
		NPU_ERR("kzalloc alloc_stream_msg failed, ret = %d\n", ret);
		goto alloc_stream_msg_failed;
	}

	(void)npu_create_alloc_stream_msg(cur_dev_id, stream_id, alloc_stream_msg);
	msg_len = sizeof(struct npu_stream_msg);

	ret = npu_mailbox_message_send_for_res(cur_dev_id, (u8 *) alloc_stream_msg, msg_len, &mbx_send_result);
	if (ret != 0) {
		NPU_ERR("alloc stream mailbox_message_send failed mbx_send_result = %d ret = %d\n",
		        mbx_send_result, ret);
		goto message_send_for_res_failed;
	}

	NPU_DEBUG("alloc stream mailbox_message_send success"
		" mbx_send_result = %d ret = %d\n", mbx_send_result, ret);
	TEE_Free(alloc_stream_msg);
	alloc_stream_msg = NULL;
	return 0;

message_send_for_res_failed:
	TEE_Free(alloc_stream_msg);
	alloc_stream_msg = NULL;
alloc_stream_msg_failed:
	(void)npu_dec_cq_ref_by_stream(cur_dev_id, cq_id);
	return -1;
}

struct npu_stream_info* npu_alloc_sink_stream(u8 cur_dev_id)
{
	int stream_id;
	struct npu_stream_info *stream_info = NULL;

	stream_id = npu_alloc_sink_stream_id(cur_dev_id);
	if (stream_id < DEVDRV_MAX_NON_SINK_STREAM_ID) {
		NPU_ERR("alloc sink stream_id from dev %d failed\n", cur_dev_id);
		return NULL;
	}

	stream_info = npu_calc_stream_info(cur_dev_id, stream_id);
	if (stream_info == NULL) {
		NPU_ERR("sink stream info is null\n");
		npu_free_sink_stream_id(cur_dev_id, stream_id);
		return NULL;
	}

	return stream_info;
}

struct npu_stream_info* npu_alloc_non_sink_stream(u8 cur_dev_id, u32 cq_id)
{
	int ret = 0;
	int sq_id;
	int stream_id;
	struct npu_stream_info *stream_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	int inform_ts;

	stream_id = npu_alloc_stream_id(cur_dev_id);
	NPU_DEBUG("non sink stream=%d\n", stream_id);

	static int entry_cnt = 0;
	NPU_INFO("entry cnt=%d\n", entry_cnt);
	entry_cnt++;
	COND_RETURN_ERROR(stream_id < 0 || stream_id >= DEVDRV_MAX_NON_SINK_STREAM_ID, NULL,
		"alloc stream_id from dev %d stream_id = %d failed\n", cur_dev_id, stream_id);

	stream_info = npu_calc_stream_info(cur_dev_id, stream_id);
	COND_GOTO_ERROR(stream_info == NULL, calc_stream_info_failed, ret, ret, "sink stream info is null\n");

	// alloc sq id
	sq_id = npu_alloc_sq_id(cur_dev_id);
	COND_GOTO_ERROR(sq_id < 0, sq_id_alloc_failed, ret, ret, "alloc sq_id from dev %d failed\n", cur_dev_id);

	// alloc sq physical mem (do it through user mmap at the stage of open device currently)
	ret = npu_alloc_sq_mem(cur_dev_id, sq_id);
	COND_GOTO_ERROR(ret != 0, sq_mem_alloc_failed, ret, ret, "alloc sq mem from dev %d failed\n", cur_dev_id);

	// bind stream with sq_id
	COND_GOTO_ERROR(npu_bind_stream_with_sq(cur_dev_id, stream_id, sq_id), bind_stream_with_sq_failed, ret, ret,
		"bind stream = %d with sq_id = %d from dev %d failed\n", stream_id, sq_id, cur_dev_id);

	// increment sq ref by current stream
	(void)npu_inc_sq_ref_by_stream(cur_dev_id, sq_id);

	// bind stream with cq_id
	COND_GOTO_ERROR(npu_bind_stream_with_cq(cur_dev_id, stream_id, cq_id), bind_stream_with_cq_failed, ret, ret,
		"bind stream = %d with cq_id = %d from dev %d failed\n", stream_id, cq_id, cur_dev_id);

	cur_dev_ctx = get_dev_ctx_by_id(cur_dev_id);
	COND_RETURN_ERROR(cur_dev_ctx == NULL, NULL, "cur_dev_ctx %d is null\n", cur_dev_id);

	MUTEX_LOCK(pm);
	if (cur_dev_ctx->power_stage != DEVDRV_PM_UP) {
		NPU_INFO("no need to inform ts as ts is powerdown");
		inform_ts = DEVDRV_NO_NEED_TO_INFORM;
	} else {
		NPU_INFO("inform ts as npu is poweron");
		inform_ts = DEVDRV_HAVE_TO_INFORM;
	}

	// TS must have been powered up n teeos
	if (inform_ts == DEVDRV_HAVE_TO_INFORM) {
		ret = npu_send_alloc_stream_mailbox(cur_dev_id, stream_id, cq_id);
		if (ret != 0) {
			MUTEX_UNLOCK(pm);
			NPU_ERR("send alloc stream %d mailbox failed\n", stream_id);
			goto send_alloc_stream_mailbox;
		}
	}
	MUTEX_UNLOCK(pm);

	return stream_info;

send_alloc_stream_mailbox:
bind_stream_with_cq_failed:
	npu_dec_sq_ref_by_stream(cur_dev_id, sq_id);
bind_stream_with_sq_failed:
	npu_free_sq_id(cur_dev_id, sq_id);
sq_mem_alloc_failed:
sq_id_alloc_failed:
calc_stream_info_failed:
	npu_free_stream_id(cur_dev_id,stream_id);
	return NULL;
}

struct npu_stream_info* npu_alloc_stream(u32 cq_id, u32 strategy)
{
	const u8 cur_dev_id = 0;
	struct npu_stream_info *stream_info = NULL;

	if (cq_id >= DEVDRV_MAX_CQ_NUM) {
		NPU_ERR("illegal npu cq id %d\n", cq_id);
		return NULL;
	}

	if (strategy == STREAM_STRATEGY_SINK) {
		stream_info = npu_alloc_sink_stream(cur_dev_id);
		if (stream_info != NULL) {
			stream_info->strategy = strategy;
		}
		return stream_info;
	}

	stream_info = npu_alloc_non_sink_stream(cur_dev_id, cq_id);
	if (stream_info != NULL) {
		stream_info->strategy = strategy;
	}

	return stream_info;
}

int npu_free_stream(u8 dev_id, u32 stream_id, u32 *sq_send_count)
{
	const u8 cur_dev_id = 0;	// get from platform
	int mbx_send_result = -1;
	int inform_ts = DEVDRV_NO_NEED_TO_INFORM;

	COND_RETURN_ERROR(dev_id >= NPU_DEV_NUM, -1, "illegal npu dev id\n");

	struct npu_dev_ctx *cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	COND_RETURN_ERROR(cur_dev_ctx == NULL, -EINVAL, "cur_dev_ctx %d is null\n", dev_id);
	COND_RETURN_ERROR(stream_id >= DEVDRV_MAX_STREAM_ID, -1, "illegal npu dev id\n");
	COND_RETURN_ERROR(sq_send_count == NULL, -1, "sq_send_count ptr is null\n");

	struct npu_stream_info *stream_info = npu_calc_stream_info(dev_id, stream_id);
	COND_RETURN_ERROR(stream_info->strategy == STREAM_STRATEGY_SINK, npu_free_sink_stream_id(dev_id, stream_id),
		"free sink stream success\n");

	u32 sq_id = stream_info->sq_index;
	u32 cq_id = stream_info->cq_index;

	MUTEX_LOCK(pm);
	if (cur_dev_ctx->power_stage != DEVDRV_PM_UP) {
		NPU_INFO("no need to inform ts\n");
		inform_ts = DEVDRV_NO_NEED_TO_INFORM;
	} else {
		NPU_INFO("need to inform ts\n");
		inform_ts = DEVDRV_HAVE_TO_INFORM;
	}

	// call mailbox to info ts to free stream
	if (inform_ts == DEVDRV_HAVE_TO_INFORM) {
		struct npu_stream_msg *free_stream_msg = (struct npu_stream_msg *)TEE_Malloc(sizeof(struct npu_stream_msg), 0);

		COND_GOTO_ERROR(free_stream_msg == NULL, fail, inform_ts, inform_ts,
			"kzalloc free_stream_msg failed, will cause resource leak\n");

		(void)npu_create_free_stream_msg(cur_dev_id, stream_id, free_stream_msg);
		u32 msg_len = sizeof(struct npu_stream_msg);
		int ret = npu_mailbox_message_send_for_res(cur_dev_id, (u8 *)free_stream_msg, msg_len, &mbx_send_result);
		TEE_Free(free_stream_msg);
		free_stream_msg = NULL;

		COND_GOTO_ERROR(ret != 0, fail, ret, ret, "free stream mailbox_message_send failed "
			"will cause resource leak mbx_send_result = %d ret = %d\n", mbx_send_result, ret);

		NPU_DEBUG("free stream mailbox_message_send success mbx_send_result = %d ret = %d\n", mbx_send_result, ret);
	}
	MUTEX_UNLOCK(pm);

	// dec ref of cq used by cur stream
	npu_dec_cq_ref_by_stream(dev_id, cq_id);

	// dec ref of sq used by cur stream
	npu_dec_sq_ref_by_stream(dev_id, sq_id);

	*sq_send_count = 0;  // to make sure upper layer get right data when no free sq
	if (npu_is_sq_ref_by_no_stream(dev_id, sq_id)) {
		npu_get_sq_send_count(dev_id, sq_id, sq_send_count);
		NPU_DEBUG("prepare free dev %d sq %d total sq_send_count = %d\n", dev_id, sq_id, *sq_send_count);
		npu_free_sq_id(dev_id, sq_id);
		npu_free_sq_mem(dev_id, sq_id);
	}
	// add stream_info to dev_ctx ->stream_available_list
	return npu_free_stream_id(dev_id, stream_id);
fail:
	MUTEX_UNLOCK(pm);
	return -1;
}
