/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu cal
 */
#ifndef _NPU_CALC_CQ_H
#define _NPU_CALC_CQ_H
#include <list.h>
struct npu_cq_sub_info {
	u32 index;
	struct list_head list;
	void *proc_ctx; // struct npu_proc_ctx
	/*
	 * use for avoid the problem:
	 * tasklet(npu_find_cq_index) may access cq's uio mem,
	 * there is a delay time, between set cq's uio invalid and accessing cq's uio mem by tasklet.
	 */
	u64 virt_addr;
	u64 phy_addr;
};

int npu_cq_list_init(u8 dev_id);

int npu_inc_cq_ref_by_stream(u8 dev_id, u32 cq_id);

int npu_dec_cq_ref_by_stream(u8 dev_id, u32 cq_id);

int npu_get_cq_ref_by_stream(u8 dev_id, u32 cq_id);

int npu_clr_cq_info(u8 dev_id, u32 cq_id);

int npu_alloc_cq_id(u8 dev_id);

int npu_free_cq_id(u8 dev_id, u32 cq_id);

int npu_alloc_cq_mem(u8 dev_id, u32 cq_id);

int npu_get_cq_phy_addr(u8 dev_id, u32 cq_id, u64 *phy_addr);

int npu_free_cq_mem(u8 dev_id, u32 cq_id);

int npu_cq_list_destroy(u8 dev_id);

#endif