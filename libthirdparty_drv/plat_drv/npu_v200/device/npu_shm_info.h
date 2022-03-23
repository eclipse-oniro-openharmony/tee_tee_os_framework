/*
 * npu_shm_info.h
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

#ifndef __NPU_SHM_INFO_H__
#define __NPU_SHM_INFO_H__
#include "npu_base_define.h"

enum npu_shm_type {
	NPU_SHM_CONFIG,
	NPU_SHM_SQ,
	NPU_SHM_CQ,
	NPU_SHM_SMMU_QUEUE, /* memory to store "ste" and "cd" table */
	NPU_CHIP_CFG,
	NPU_SHM_TYPES
};

typedef struct npu_mem_info {
	uintptr_t phy_base;
	uintptr_t virt_base;
	size_t size;
} npu_mem_info_t;

#endif /* __NPU_SHM_INFO_H__ */
