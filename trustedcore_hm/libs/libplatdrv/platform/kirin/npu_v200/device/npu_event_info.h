/*
 * npu_event_info.h
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

#ifndef __NPU_EVENT_INFO_H__
#define __NPU_EVENT_INFO_H__
#include <list.h>

#define NPU_MAX_EVENT_ID	16

typedef struct npu_event_info {
	struct list_head list_node;

	int event_id;
	void *proc_ctx;
} npu_event_info_t;

#endif /* __NPU_EVENT_INFO_H__ */
