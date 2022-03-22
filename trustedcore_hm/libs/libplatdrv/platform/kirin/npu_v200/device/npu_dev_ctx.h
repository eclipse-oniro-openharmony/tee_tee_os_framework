/*
 * npu_dev_ctx.h
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

#ifndef __NPU_DEV_CTX_H__
#define __NPU_DEV_CTX_H__
#include <list.h>

#include "secmem.h"
#include "sec_smmu_com.h"
#include "npu_shm_info.h"
#include "npu_task_info_mngr.h"
#include "npu_stream_info_mngr.h"
#include "npu_model_info_mngr.h"
#include "npu_event_info_mngr.h"
#include "npu_hwts_sq_mngr.h"

typedef struct npu_dev_ctx {
	u8 dev_id;
	u8 power_stage;

	struct list_head proc_ctx_list;
	struct sec_smmu_para smmu_para;

	npu_task_info_mngr_t task_mngr;
	npu_stream_info_mngr_t stream_mngr;
	npu_model_info_mngr_t model_mngr;
	npu_event_info_mngr_t event_mngr;
	npu_hwts_sq_mngr_t sq_mngr;

	npu_mem_info_t shm_mem[NPU_SHM_TYPES];
} npu_dev_ctx_t;

#endif /* __NPU_DEV_CTX_H__ */
