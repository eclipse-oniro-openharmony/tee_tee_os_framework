/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu platform resource
 */
#ifndef __NPU_PLATFORM_RESOURCE_H
#define __NPU_PLATFORM_RESOURCE_H
#include <stdint.h>
#include "npu_ddr_map.h"

#define DEVDRV_PLAT_STREAM_MAX     16
#define DEVDRV_PLAT_EVENT_MAX      16
#define DEVDRV_PLAT_NOTIFY_MAX     1024
#define DEVDRV_PLAT_MODEL_MAX      (DEVDRV_PLAT_STREAM_MAX)
#define DEVDRV_PLAT_AICORE_MAX     1
#define DEVDRV_PLAT_AICPU_MAX      1
#define DEVDRV_PLAT_CALC_SQ_MAX    16
#define DEVDRV_PLAT_CALC_SQ_DEPTH  256
#define DEVDRV_PLAT_CALC_CQ_MAX    1
#define DEVDRV_PLAT_CALC_CQ_DEPTH  1024
#define DEVDRV_PLAT_DFX_SQ_MAX     4
#define DEVDRV_PLAT_DFX_CQ_MAX     10
#define DEVDRV_PLAT_DFX_SQCQ_DEPTH 1024
#define DEVDRV_PLAT_DOORBELL_STRIDE 4096 /* stride 4KB */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
static uint32_t reserv_mem_lens[] = {
	NPU_NS_AICPU_FW_SIZE, // 1
	NPU_NS_TSCPU_FW_SIZE, // 2
	NPU_NS_SQCQ_SIZE, // 3
	NPU_NS_TASKPOOL_SIZE, // 4
	NPU_NS_LOG_SIZE, // 5
	NPU_NS_PROF_SIZE, // 6
	NPU_NS_BBOX_SIZE, // 7
	NPU_NS_DUMP_SIZE, // 8
	NPU_NS_CHIP_CFG_SIZE
};
#pragma GCC diagnostic pop

#define SQ_CQ_BUF_IDX	3
#define PERSISTENT_TASK_BUF_IDX	4

// interrupt number info
#define IRQ_CALC_CQ_UPDATE0		691
#define IRQ_DFX_CQ_UPDATE		690
#define IRQ_MAILBOX_ACK			689

#endif
