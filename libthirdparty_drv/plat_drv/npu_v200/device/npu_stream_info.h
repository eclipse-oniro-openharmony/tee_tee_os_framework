/*
 * npu_stream_info.h
 *
 * Copyright (c) 2012-2020 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __NPU_STREAM_INFO_H__
#define __NPU_STREAM_INFO_H__
#include <stdint.h>
#include <list.h>
#include "npu_custom_info_share.h"

#define DEVDRV_MAX_STREAM_PRIORITY	7

typedef struct npu_sink_stream_sub {
	int model_id;

	u32 sqe_count;
	uintptr_t phy_addr;
	uintptr_t virt_addr;

	u16 smmu_substream_id;
	u16 hwts_sq_id;
} npu_sink_stream_sub_t;

typedef struct npu_stream_info {
	struct list_head list_node;

	int stream_id;
	u32 strategy;
	u8 priority;

	void *proc_ctx;
	npu_sink_stream_sub_t *sink_sub;
} npu_stream_info_t;

#endif /* __NPU_STREAM_INFO_H__ */
