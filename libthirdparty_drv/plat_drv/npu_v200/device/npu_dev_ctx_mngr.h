/*
 * npu_dev_ctx_mngr.h
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

#ifndef __NPU_DEV_CTX_MNGR_H__
#define __NPU_DEV_CTX_MNGR_H__
#include "npu_base_define.h"
#include "npu_dev_ctx.h"

int npu_init_dev_ctx(u8 dev_id);
void npu_deinit_dev_ctx(u8 dev_id);

uint32_t npu_sec_enable();

npu_dev_ctx_t *npu_get_dev_ctx(u8 dev_id);
int npu_get_res_mem_of_smmu(uintptr_t *phy_addr_ptr, uintptr_t *virt_addr_ptr, u32 *len_ptr);
int npu_get_res_mem_of_chip_cfg(uintptr_t *virt_addr_ptr);
#endif /* __NPU_DEV_CTX_MNGR_H__ */
