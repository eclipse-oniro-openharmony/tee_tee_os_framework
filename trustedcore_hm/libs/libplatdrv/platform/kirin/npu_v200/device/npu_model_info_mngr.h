/*
 * npu_model_info_mngr.h
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

#ifndef __NPU_MODEL_INFO_MNGR_H__
#define __NPU_MODEL_INFO_MNGR_H__
#include "npu_model_info.h"

typedef struct npu_model_info_mngr {
	npu_model_info_t models[NPU_MAX_MODEL_ID];
	struct list_head model_list;
} npu_model_info_mngr_t;

void npu_init_model_info_mngr(npu_model_info_mngr_t *mngr);
npu_model_info_t *npu_alloc_model_info(npu_model_info_mngr_t *mngr);
void npu_free_model_info(npu_model_info_mngr_t *mngr, int model_id);
npu_model_info_t *npu_get_model_info(npu_model_info_mngr_t *mngr, int model_id);

#endif /* __NPU_MODEL_INFO_MNGR_H__ */
