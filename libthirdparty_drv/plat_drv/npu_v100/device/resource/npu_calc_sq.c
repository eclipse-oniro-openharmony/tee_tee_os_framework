/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu calc sq
 */

#include "npu_calc_sq.h"

#include <errno.h>
#include <mem_mode.h> /* secure_mode_type */

#include "drv_log.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "drv_mem.h" /* sre_mmap */
#include "mem_page_ops.h"
#include "npu_custom_info_share.h"
#include "npu_spec_share.h"
#include "npu_common.h"
#include "npu_shm.h"

static u64 s_drv_sq_virt_addrs[DEVDRV_MAX_SQ_NUM] = {0};

int npu_sq_list_init(u8 dev_id)
{
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	struct npu_sq_sub_info *sq_sub_info = NULL;
	struct npu_ts_sq_info *sq_info = NULL;
	unsigned long size;
	u32 num_sq = DEVDRV_MAX_SQ_NUM;	// need get from platform
	u32 i;

	COND_RETURN_ERROR(dev_id >= NPU_DEV_NUM, -1, "illegal npu dev id\n");

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	COND_RETURN_ERROR(cur_dev_ctx == NULL, -1, "cur_dev_ctx %d is null\n", dev_id);

	INIT_LIST_HEAD(&cur_dev_ctx->sq_available_list);
	COND_RETURN_ERROR(!list_empty_careful(&cur_dev_ctx->sq_available_list), -1, "sq_available_list is not empty\n");

	cur_dev_ctx->sq_num = 0;
	size = (long)(unsigned)sizeof(struct npu_sq_sub_info) * num_sq;
	sq_sub_info = TEE_Malloc(size, 0);
	COND_RETURN_ERROR(sq_sub_info == NULL, -ENOMEM, "no mem to alloc sq sub info list\n");

	cur_dev_ctx->sq_sub_addr = (void *)sq_sub_info;

	for (i = 0; i < num_sq; i++) {
		sq_info = npu_calc_sq_info(dev_id, i);
		sq_info->head = 0;
		sq_info->tail = 0;
		sq_info->credit = DEVDRV_MAX_SQ_DEPTH - 1;
		sq_info->index = i;
		sq_info->uio_addr = NULL;
		sq_info->uio_fd = DEVDRV_INVALID_FD_OR_NUM;
		sq_info->uio_size = DEVDRV_MAX_SQ_DEPTH * DEVDRV_SQ_SLOT_SIZE;
		sq_info->stream_num = 0;
		sq_info->send_count = 0;

		sq_info->sq_sub = (void *)(sq_sub_info + i);
		sq_sub_info[i].index = sq_info->index;
		sq_sub_info[i].ref_by_streams = 0;

		list_add_tail(&sq_sub_info[i].list, &cur_dev_ctx->sq_available_list);
		cur_dev_ctx->sq_num++;
	}
	NPU_DEBUG("cur dev %d own %d calc sq\n", dev_id, cur_dev_ctx->sq_num);

	return 0;
}

int npu_alloc_sq_id(u8 dev_id)
{
	struct npu_sq_sub_info *sq_sub = NULL;
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

	if (list_empty_careful(&cur_dev_ctx->sq_available_list)) {
		NPU_ERR("cur dev %d available sq list empty, left sq_num = %d !!!\n", dev_id, cur_dev_ctx->sq_num);
		return -1;
	}
	sq_sub = list_first_entry(&cur_dev_ctx->sq_available_list, struct npu_sq_sub_info, list);
	list_del(&sq_sub->list);
	cur_dev_ctx->sq_num--;
	NPU_DEBUG("cur dev %d left %d sq\n", dev_id, cur_dev_ctx->sq_num);

	return sq_sub->index;
}

int npu_get_sq_send_count(u8 dev_id, u32 sq_id, u32 *send_count)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}

	if (send_count == NULL) {
		NPU_ERR("send_count is null ptr\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	*send_count = sq_info->send_count;

	return 0;
}

int npu_is_sq_ref_by_no_stream(u8 dev_id, u32 sq_id)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_sq_sub_info *sq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	sq_sub = (struct npu_sq_sub_info *)sq_info->sq_sub;
	if (sq_sub->ref_by_streams != 0) {
		NPU_DEBUG("can't release cur_dev_ctx %d sq calc channel %d for ref_by_streams = %d\n",
			dev_id, sq_id, sq_sub->ref_by_streams);
		return 0;
	}

	return -1;
}

// sq_sub->ref_by_streams-- excute by service layer
int npu_free_sq_id(u8 dev_id, u32 sq_id)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_sq_sub_info *sq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	sq_sub = (struct npu_sq_sub_info *)sq_info->sq_sub;
	if (sq_sub->ref_by_streams != 0) {
		NPU_DEBUG("can't release cur_dev_ctx %d sq calc channel %d for ref_by_streams = %d\n",
			dev_id, sq_id, sq_sub->ref_by_streams);
		return -1;
	}
	list_add(&sq_sub->list, &cur_dev_ctx->sq_available_list);
	// no stream use it
	sq_sub->ref_by_streams = 0;
	cur_dev_ctx->sq_num++;
	sq_info->head = 0;
	sq_info->tail = 0;
	sq_info->credit = DEVDRV_MAX_SQ_DEPTH - 1;
	sq_info->stream_num = 0;
	sq_info->send_count = 0;
	NPU_DEBUG("cur dev %d own %d sq\n", dev_id, cur_dev_ctx->sq_num);

	return 0;
}

int npu_alloc_sq_mem(u8 dev_id, u32 sq_id)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_sq_sub_info *sq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	vir_addr_t drv_sq_virt_addr = 0;
	u64 phy_addr;
	u64 sq_size;
	int err;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}
	static int entry_cnt = 0;
	NPU_INFO("entry cnt=%d\n", entry_cnt);
	entry_cnt++;

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	phy_addr = (unsigned long long)(g_sq_desc.base +
		(sq_id * DEVDRV_MAX_SQ_DEPTH * DEVDRV_SQ_SLOT_SIZE));
	sq_size = DEVDRV_MAX_SQ_DEPTH * DEVDRV_SQ_SLOT_SIZE;
	err = sre_mmap(phy_addr, sq_size, (uint32_t *)(uintptr_t) &drv_sq_virt_addr,
		(secure_mode_type)secure, (cache_mode_type)non_cache);
	if (err) {
		NPU_ERR("calc sq sre_map failed err=0x%x \n", err);
		return -1;
	}

	if (drv_sq_virt_addr == 0) {
		NPU_ERR("cur_dev_ctx %d calc cq sre_map failed \n", dev_id);
		return -1;
	}

	s_drv_sq_virt_addrs[sq_id] = drv_sq_virt_addr;
	sq_info = npu_calc_sq_info(dev_id, sq_id);
	sq_sub = (struct npu_sq_sub_info *)sq_info->sq_sub;
	sq_sub->phy_addr = phy_addr;

	// make sq mem clean
	npu_clear_mem_data((void *)(uintptr_t) drv_sq_virt_addr, sq_size);

	NPU_DEBUG("dev %d cur sq %d phy_addr = %p \n", dev_id, sq_id, (void *)(uintptr_t) phy_addr);

	return 0;
}

// get sq_id sq`s sq_addr from dev_id(must called after alloc_sq_mem)
int npu_get_sq_phy_addr(u8 dev_id, u32 sq_id, u64 *phy_addr)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_sq_sub_info *sq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}

	if (phy_addr == NULL) {
		NPU_ERR("phy_addr is null\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	sq_sub = (struct npu_sq_sub_info *)sq_info->sq_sub;
	*phy_addr = sq_sub->phy_addr;

	NPU_DEBUG("dev %d cur sq %d phy_addr = %p\n", dev_id, sq_id, (void *)(*phy_addr));

	return 0;
}

int npu_free_sq_mem(u8 dev_id, u32 sq_id)
{
	struct npu_sq_sub_info *sq_sub = NULL;
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	u64 sq_size;
	int err = -1;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_size = DEVDRV_MAX_SQ_DEPTH * DEVDRV_SQ_SLOT_SIZE;
	if (s_drv_sq_virt_addrs[sq_id] != 0) {
		err = sre_unmap(s_drv_sq_virt_addrs[sq_id], sq_size);
		if (err) {
			NPU_ERR("calc sq sre_unmap failed n %s\n", __func__);
			return -1;
		}
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	sq_info->uio_addr = NULL;
	sq_info->uio_fd = DEVDRV_INVALID_FD_OR_NUM;
	sq_sub = (struct npu_sq_sub_info *)sq_info->sq_sub;
	sq_sub->phy_addr = 0;

	return 0;
}

int npu_clr_sq_info(u8 dev_id, u32 sq_id)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}
	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	if (sq_info == NULL) {
		NPU_ERR("sq_info %d is null\n", dev_id);
		return -1;
	}
	sq_info->head = 0;
	sq_info->tail = 0;
	sq_info->credit = DEVDRV_MAX_SQ_DEPTH - 1;

	return 0;
}


// called by alloc stream n service layer
int npu_inc_sq_ref_by_stream(u8 dev_id, u32 sq_id)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_sq_sub_info *sq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	sq_sub = (struct npu_sq_sub_info *)sq_info->sq_sub;
	sq_info->stream_num++;	// should do it here or user driver
	sq_sub->ref_by_streams++;

	return 0;
}

// called by free stream in service layer
int npu_dec_sq_ref_by_stream(u8 dev_id, u32 sq_id)
{
	struct npu_ts_sq_info *sq_info = NULL;
	struct npu_sq_sub_info *sq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	if (sq_id >= DEVDRV_MAX_SQ_NUM) {
		NPU_ERR("illegal npu sq id\n");
		return -1;
	}
	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	sq_info = npu_calc_sq_info(dev_id, sq_id);
	sq_sub = (struct npu_sq_sub_info *)sq_info->sq_sub;
	if (sq_info->stream_num <= 0 || sq_sub->ref_by_streams <= 0) {
		NPU_ERR("sq_info->stream_num or sq_sub->ref_by_streams is error\n");
		return -1;
	}
	sq_info->stream_num--;	// should do it here or user driver
	sq_sub->ref_by_streams--;

	return 0;
}

int npu_sq_list_destroy(u8 dev_id)
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

	if (!list_empty_careful(&cur_dev_ctx->sq_available_list)) {
		list_for_each_safe(pos, n, &cur_dev_ctx->sq_available_list) {
			cur_dev_ctx->sq_num--;
			list_entry(pos, struct npu_sq_sub_info, list);
			list_del(pos);
		}
	}

	TEE_Free(cur_dev_ctx->sq_sub_addr);

	return 0;
}
