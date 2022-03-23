/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu stream
 */

#ifndef __NPU_STREAM_H
#define __NPU_STREAM_H
#include <list.h>

struct npu_stream_sub_info {
	int id;
	struct list_head list;
	void *proc_ctx; // struct npu_proc_ctx
};

int npu_stream_list_init(u8 dev_id);

int npu_alloc_stream_id(u8 dev_id);

int npu_free_stream_id(u8 dev_id, u32 stream_id);

int npu_bind_stream_with_sq(u8 dev_id, u32 stream_id, u32 sq_id);

int npu_bind_stream_with_cq(u8 dev_id, u32 stream_id, u32 cq_id);

int npu_stream_list_destroy(u8 dev_id);

#endif
