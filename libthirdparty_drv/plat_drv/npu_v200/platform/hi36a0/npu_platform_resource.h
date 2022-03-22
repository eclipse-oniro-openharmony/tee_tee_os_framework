/*
 * npu_platform_resource.h
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

#ifndef NPU_PLATFORM_RESOURCE_H
#define NPU_PLATFORM_RESOURCE_H
#include <stdint.h>
#include "npu_ddr_map.h"

#define DEVDRV_PLAT_STREAM_MAX     16
#define DEVDRV_PLAT_EVENT_MAX      16
#define DEVDRV_PLAT_NOTIFY_MAX     1024
#define DEVDRV_PLAT_MODEL_MAX      (DEVDRV_PLAT_STREAM_MAX)
#define DEVDRV_PLAT_AICORE_MAX     2
#define DEVDRV_PLAT_AICPU_MAX      0
#define DEVDRV_PLAT_CALC_SQ_MAX    16
#define DEVDRV_PLAT_CALC_SQ_DEPTH  256
#define DEVDRV_PLAT_CALC_CQ_MAX    1
#define DEVDRV_PLAT_CALC_CQ_DEPTH  1024
#define DEVDRV_PLAT_DFX_SQ_MAX     4
#define DEVDRV_PLAT_DFX_CQ_MAX     10
#define DEVDRV_PLAT_DFX_SQCQ_DEPTH 1024
#define DEVDRV_PLAT_DOORBELL_STRIDE 4096  /* stride 4KB */

#endif
