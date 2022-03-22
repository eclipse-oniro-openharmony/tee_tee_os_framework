/*
 * npu_stream_info_mngr.h
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

#ifndef __NPU_STREAM_INFO_MNGR_H__
#define __NPU_STREAM_INFO_MNGR_H__
#include "npu_stream_info.h"

#define NPU_MAX_SINK_STREAM_ID		24
#define NPU_MAX_NON_SINK_STREAM_ID	24
#define NPU_MAX_STREAM_ID			48

typedef struct npu_stream_info_mngr {
	npu_stream_info_t streams[NPU_MAX_STREAM_ID];
	npu_sink_stream_sub_t sink_subs[NPU_MAX_SINK_STREAM_ID];
	struct list_head non_sink_stream_list;
	struct list_head sink_stream_list;
} npu_stream_info_mngr_t;

void npu_init_stream_info_mngr(npu_stream_info_mngr_t *mngr);
npu_stream_info_t *npu_alloc_stream_info(npu_stream_info_mngr_t *mngr, u32 strategy);
void npu_free_stream_info(npu_stream_info_mngr_t *mngr, int stream_id);
npu_stream_info_t *npu_get_stream_info(npu_stream_info_mngr_t *mngr, int stream_id);

#endif /* __NPU_STREAM_INFO_MNGR_H__ */
