/*
 * npu_proc_ctx_mngr.h
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

#ifndef __NPU_PROC_CTX_MNGR_H__
#define __NPU_PROC_CTX_MNGR_H__
#include "npu_dev_ctx.h"
#include "npu_proc_ctx.h"

npu_proc_ctx_t *npu_create_proc_ctx(npu_dev_ctx_t *dev_ctx);
npu_proc_ctx_t *npu_get_proc_ctx(npu_dev_ctx_t *dev_ctx);
void npu_deinit_proc_ctx(npu_proc_ctx_t *proc_ctx);
void npu_destroy_proc_ctx(npu_proc_ctx_t *proc_ctx);

#endif /* __NPU_PROC_CTX_MNGR_H__ */
