/*
 * npu_adapter.h
 *
 * about npu adapter
 *
 * Copyright (c) 2012-2019 Huawei Technologies Co., Ltd.
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
#ifndef __NPU_ADAPTER_H__
#define __NPU_ADAPTER_H__

#include "npu_base_define.h"

int npu_plat_power_up(void *svm_dev);

int npu_plat_power_down(void *svm_dev);

__attribute__((weak))int npu_plat_aicore_get_disable_status(int core_id)
{
	UNUSED(core_id);
	return 0;
}

int npu_plat_aicore_get_disable_status(int core_id);

#endif /* __NPU_ADAPTER_H__ */
