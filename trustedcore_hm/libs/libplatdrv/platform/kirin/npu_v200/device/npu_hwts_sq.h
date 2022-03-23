/*
 * npu_hwts_sq.h
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

#ifndef __NPU_HWTS_SQ_H__
#define __NPU_HWTS_SQ_H__
#include <list.h>

#define DEVDRV_SEC_SQ_NUM		8
#define DEVDRV_SEC_SQ_ID_BEGIN	56

typedef struct npu_hwts_sq {
	struct list_head list_node;

	int sq_id;
	int stream_id;
	void *proc_ctx;
} npu_hwts_sq_t;

#endif /* __NPU_HWTS_SQ_H__ */
