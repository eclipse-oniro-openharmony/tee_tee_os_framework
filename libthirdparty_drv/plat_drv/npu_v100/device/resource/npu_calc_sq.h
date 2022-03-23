/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu calc sq
 */
#ifndef _NPU_CALC_SQ_H
#define _NPU_CALC_SQ_H
#include <list.h>
#include "npu_shm.h"

struct npu_sq_sub_info {
	u32 index;
	struct list_head list;
	u32 ref_by_streams;
	u64 phy_addr;
};

int npu_sq_list_init(u8 dev_id);

int npu_alloc_sq_id(u8 dev_id);

int npu_free_sq_id(u8 dev_id, u32 sq_id);

int npu_alloc_sq_mem(u8 dev_id, u32 sq_id);

int npu_get_sq_phy_addr(u8 dev_id, u32 sq_id, u64 *phy_addr);

int npu_clr_sq_info(u8 dev_id, u32 sq_id);

int npu_free_sq_mem(u8 dev_id, u32 sq_id);

int npu_is_sq_ref_by_no_stream(u8 dev_id, u32 sq_id);

int npu_inc_sq_ref_by_stream(u8 dev_id, u32 sq_id);

int npu_dec_sq_ref_by_stream(u8 dev_id, u32 sq_id);

int npu_get_sq_send_count(u8 dev_id, u32 sq_id, u32 *send_count);

int npu_sq_list_destroy(u8 dev_id);

#endif