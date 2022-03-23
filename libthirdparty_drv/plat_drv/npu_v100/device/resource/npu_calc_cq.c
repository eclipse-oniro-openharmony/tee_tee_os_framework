/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu calc cq
 */

#include "npu_calc_cq.h"
#include <errno.h>

#include "drv_log.h"
#include "drv_mem.h" /* sre_mmap */
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */
#include "mem_page_ops.h"
#include "npu_custom_info_share.h"
#include "npu_spec_share.h"
#include "npu_doorbell.h"
#include "npu_common.h"
#include "npu_shm.h"

int npu_cq_list_init(u8 dev_id)
{
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	struct npu_cq_sub_info *cq_sub_info = NULL;
	struct npu_ts_cq_info *cq_info = NULL;
	unsigned long size;
	u32 num_cq = DEVDRV_MAX_CQ_NUM;	// need get from platform
	u32 i;

	COND_RETURN_ERROR(dev_id >= NPU_DEV_NUM, -1, "illegal npu dev id\n");

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	COND_RETURN_ERROR(cur_dev_ctx == NULL, -1, "cur_dev_ctx %d is null\n", dev_id);

	INIT_LIST_HEAD(&cur_dev_ctx->cq_available_list);

	COND_RETURN_ERROR(!list_empty_careful(&cur_dev_ctx->cq_available_list), -1, "cq_available_list is not empty\n");

	cur_dev_ctx->cq_num = 0;
	size = (long)(unsigned)sizeof(struct npu_cq_sub_info) * num_cq;
	cq_sub_info = TEE_Malloc(size, 0);
	if (cq_sub_info == NULL) {
		NPU_ERR("no mem to alloc cq sub info list\n");
		return -ENOMEM;
	}

	cur_dev_ctx->cq_sub_addr = (void *)cq_sub_info;

	for (i = 0; i < num_cq; i++) {
		cq_info = npu_calc_cq_info(dev_id, i);
		cq_info->head = 0;
		cq_info->tail = 0;
		cq_info->index = i;
		cq_info->count_report = 0;
		cq_info->uio_addr = NULL;
		cq_info->uio_fd = DEVDRV_INVALID_FD_OR_NUM;
		cq_info->uio_size = DEVDRV_MAX_CQ_DEPTH * DEVDRV_CQ_SLOT_SIZE;
		cq_info->stream_num = 0;
		cq_info->receive_count = 0;
		cq_info->phase = 1;
		cq_info->slot_size = DEVDRV_CQ_SLOT_SIZE;
		cq_info->cq_sub = (void *)(cq_sub_info + i);
		cq_sub_info[i].proc_ctx = NULL;
		cq_sub_info[i].index = cq_info->index;
		cq_sub_info[i].virt_addr = (u64)(uintptr_t)NULL;
		cq_sub_info[i].phy_addr = (u64)(uintptr_t)NULL;
		list_add_tail(&cq_sub_info[i].list, &cur_dev_ctx->cq_available_list);
		cur_dev_ctx->cq_num++;
	}
	NPU_DEBUG("cur dev %d own %d calc cq \n", dev_id, cur_dev_ctx->cq_num);

	return 0;
}

int npu_inc_cq_ref_by_stream(u8 dev_id, u32 cq_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d \n", dev_id);
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	if (cq_info->stream_num == DEVDRV_MAX_STREAM_ID) {
		NPU_ERR("cq_info->stream_num is DEVDRV_MAX_STREAM_ID\n");
		return -1;
	}
	cq_info->stream_num++;	// should do it here or user driver

	return 0;
}

int npu_dec_cq_ref_by_stream(u8 dev_id, u32 cq_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
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

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	if (cq_info->stream_num == 0) {
		NPU_ERR("cq_info->stream_num is 0\n");
		return -1;
	}
	cq_info->stream_num--;	// should do it here or user driver

	return 0;
}

int npu_clr_cq_info(u8 dev_id, u32 cq_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
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

	(void)npu_write_doorbell_val(DOORBELL_RES_CAL_CQ, cq_id, 0);

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	cq_info->count_report = 0;
	cq_info->stream_num = 0;

	NPU_WARN("end. head = 0, tail = 0, phase = 1\n");

	return 0;
}

int npu_get_cq_ref_by_stream(u8 dev_id, u32 cq_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	u32 cq_stream_num;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id\n");
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	cq_stream_num = cq_info->stream_num;

	return cq_stream_num;
}


int npu_alloc_cq_id(u8 dev_id)
{
	struct npu_cq_sub_info *cq_sub = NULL;
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

	if (list_empty_careful(&cur_dev_ctx->cq_available_list)) {
		NPU_ERR("cur dev %d available cq list empty, left cq_num = %d !!!\n", dev_id,
			cur_dev_ctx->cq_num);
		return -1;
	}
	cq_sub = list_first_entry(&cur_dev_ctx->cq_available_list, struct npu_cq_sub_info, list);
	list_del(&cq_sub->list);

	if (cur_dev_ctx->cq_num <= 0) {
		NPU_ERR("cur_dev_ctx->cq_num is error\n");
		return -1;
	}
	cur_dev_ctx->cq_num--;
	NPU_DEBUG("cur dev %d left %d cq\n", dev_id, cur_dev_ctx->cq_num);

	return cq_sub->index;
}

int npu_free_cq_id(u8 dev_id, u32 cq_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_cq_sub_info *cq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (cq_id >= DEVDRV_MAX_CQ_NUM) {
		NPU_ERR("illegal npu cq id %d\n", cq_id);
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	cq_sub = (struct npu_cq_sub_info *)cq_info->cq_sub;
	list_add(&cq_sub->list, &cur_dev_ctx->cq_available_list);
	// no stream use it
	cur_dev_ctx->cq_num++;

	cq_sub->proc_ctx = NULL;
	cq_info->head = 0;
	cq_info->tail = 0;
	cq_info->count_report = 0;
	cq_info->stream_num = 0;
	cq_info->receive_count = 0;
	cq_info->slot_size = DEVDRV_CQ_SLOT_SIZE;
	NPU_DEBUG("cur dev %d own %d cq\n", dev_id, cur_dev_ctx->cq_num);

	return 0;
}

// make sure the cq_mem data all been zero when alloced success,or bug happens
// because TS will write from cq head 0,but user driver will not when we reuse the
// dirty cq mem
int npu_alloc_cq_mem(u8 dev_id, u32 cq_id)
{
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_cq_sub_info *cq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	u64 phy_addr;
	vir_addr_t drv_cq_virt_addr = 0;
	u64 cq_size;
	int err;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (cq_id >= DEVDRV_MAX_CQ_NUM) {
		NPU_ERR("illegal npu cq id %d\n", cq_id);
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	cq_size = DEVDRV_MAX_CQ_DEPTH * cq_info->slot_size;

	phy_addr = (unsigned long long)(g_sq_desc.base +
		DEVDRV_MAX_SQ_DEPTH * DEVDRV_SQ_SLOT_SIZE * DEVDRV_MAX_SQ_NUM +
		(cq_id * DEVDRV_MAX_CQ_DEPTH * DEVDRV_CQ_SLOT_SIZE));
	err = sre_mmap(phy_addr, cq_size, (uint32_t *)(uintptr_t) &drv_cq_virt_addr,
	               (secure_mode_type)secure, (cache_mode_type)non_cache);
	if (err) {
		NPU_ERR("calc cq sre_map failed err = %d\n", err);
		return -1;
	}

	if (drv_cq_virt_addr == 0) {
		NPU_ERR("cur_dev_ctx %d calc cq sre_map failed \n", dev_id);
		return -1;
	}

	cq_sub = (struct npu_cq_sub_info *)cq_info->cq_sub;
	cq_sub->virt_addr = drv_cq_virt_addr;
	cq_sub->phy_addr = phy_addr;

	// make cq mem clean
	npu_clear_mem_data((void *)(uintptr_t) drv_cq_virt_addr, cq_size);

	NPU_DEBUG("dev %d cur cq %d phy_addr = %p drv_cq_virt_addr = %p cq_size = 0x%llx\n",
	          dev_id, cq_id, (void *)(uintptr_t) phy_addr,
	          (void *)(uintptr_t) drv_cq_virt_addr, cq_size);

	return 0;
}

int npu_free_cq_mem(u8 dev_id, u32 cq_id)
{
	struct npu_cq_sub_info *cq_sub = NULL;
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	vir_addr_t drv_cq_virt_addr;
	u64 cq_size;
	int err;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (cq_id >= DEVDRV_MAX_CQ_NUM) {
		NPU_ERR("illegal npu cq id %d\n", cq_id);
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	cq_size = DEVDRV_MAX_CQ_DEPTH * cq_info->slot_size;

	cq_sub = (struct npu_cq_sub_info *)cq_info->cq_sub;
	drv_cq_virt_addr = cq_sub->virt_addr;
	if (drv_cq_virt_addr != 0) {
		err = sre_unmap(drv_cq_virt_addr, cq_size);
		if (err) {
			NPU_ERR("calc cq sre_unmap failed in %s\n", __func__);
			return -1;
		}
	}

	cq_info->uio_addr = NULL;
	cq_info->uio_fd = DEVDRV_INVALID_FD_OR_NUM;
	cq_sub->virt_addr = 0;
	cq_sub->phy_addr = 0;
	NPU_DEBUG("free dev %d cur cq %d memory success\n", dev_id, cq_id);

	return 0;
}

// get cq_id cq`s cq_addr from dev_id(must called after alloc_cq_mem)
int npu_get_cq_phy_addr(u8 dev_id, u32 cq_id, u64 *phy_addr)
{
	struct npu_ts_cq_info *cq_info = NULL;
	struct npu_cq_sub_info *cq_sub = NULL;
	struct npu_dev_ctx *cur_dev_ctx = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	if (cq_id >= DEVDRV_MAX_CQ_NUM) {
		NPU_ERR("illegal npu cq id %d\n", cq_id);
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	if (phy_addr == NULL) {
		NPU_ERR("phy_addr is null\n");
		return -1;
	}

	cq_info = npu_calc_cq_info(dev_id, cq_id);
	cq_sub = (struct npu_cq_sub_info *)cq_info->cq_sub;
	*phy_addr = cq_sub->phy_addr;

	NPU_DEBUG("dev %d cur cq %d phy_addr = %p \n", dev_id, cq_id, (void *)(uintptr_t) (*phy_addr));

	return 0;
}

int npu_cq_list_destroy(u8 dev_id)
{
	struct npu_dev_ctx *cur_dev_ctx = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d\n", dev_id);
		return -1;
	}

	cur_dev_ctx = get_dev_ctx_by_id(dev_id);
	if (cur_dev_ctx == NULL) {
		NPU_ERR("cur_dev_ctx %d is null\n", dev_id);
		return -1;
	}

	if (!list_empty_careful(&cur_dev_ctx->cq_available_list)) {
		if (cur_dev_ctx->cq_num <= 0) {
			NPU_ERR("cur_dev_ctx->cq_num is error!\n");
			return -1;
		}
		list_for_each_safe(pos, n, &cur_dev_ctx->cq_available_list) {
			cur_dev_ctx->cq_num--;
			list_entry(pos, struct npu_cq_sub_info, list);
			list_del(pos);
		}
	}

	TEE_Free(cur_dev_ctx->cq_sub_addr);
	cur_dev_ctx->cq_sub_addr = NULL;
	return 0;
}
