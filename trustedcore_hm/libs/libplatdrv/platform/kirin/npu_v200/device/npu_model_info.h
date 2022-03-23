/*
 * npu_model_info.h
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

#ifndef __NPU_MODEL_INFO_H__
#define __NPU_MODEL_INFO_H__
#include <list.h>

#define NPU_MAX_MODEL_ID	12

typedef struct npu_model_info {
	struct list_head list_node;

	int model_id;
	void *proc_ctx;
	struct list_head stream_list;
} npu_model_info_t;

#endif /* __NPU_MODEL_INFO_H__ */

