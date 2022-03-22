/*
 * npu_hwts_sq_mngr.h
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

#ifndef __NPU_HWTS_SQ_MNGR_H__
#define __NPU_HWTS_SQ_MNGR_H__
#include <list.h>

#include "npu_hwts_sq.h"

typedef struct npu_hwts_sq_mngr {
	npu_hwts_sq_t sqs[DEVDRV_SEC_SQ_NUM];
	struct list_head sq_list;
} npu_hwts_sq_mngr_t;

void npu_init_hwts_sq_mngr(npu_hwts_sq_mngr_t *mngr);
npu_hwts_sq_t *npu_alloc_hwts_sq(npu_hwts_sq_mngr_t *mngr);
void npu_free_hwts_sq(npu_hwts_sq_mngr_t *mngr, int sq_id);
npu_hwts_sq_t *npu_get_hwts_sq(npu_hwts_sq_mngr_t *mngr, int sq_id);

#endif /* __NPU_HWTS_SQ_MNGR_H__ */
