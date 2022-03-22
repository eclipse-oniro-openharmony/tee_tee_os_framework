/*
 * npu_task_info_mngr.h
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

#ifndef __NPU_TASK_INFO_MNGR_H__
#define __NPU_TASK_INFO_MNGR_H__
#include "npu_task_info.h"

typedef struct npu_task_info_mngr {
	npu_task_info_t tasks[DEVDRV_MAX_TASK_ID];
	struct list_head task_list;
} npu_task_info_mngr_t;

void npu_init_task_info_mngr(npu_task_info_mngr_t *mngr);
npu_task_info_t *npu_alloc_task_info(npu_task_info_mngr_t *mngr);
void npu_free_task_info(npu_task_info_mngr_t *mngr, int task_id);
npu_task_info_t *npu_get_task_info(npu_task_info_mngr_t *mngr, int task_id);

#endif /* __NPU_TASK_INFO_MNGR_H__ */
