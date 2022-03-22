/*
 * npu_schedule_task.h
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

#ifndef _NPU_SCHEDULE_TASK_H_
#define _NPU_SCHEDULE_TASK_H_
#include "npu_base_define.h"
#include "npu_dev_ctx.h"

typedef enum npu_schedule_task_type {
	NPU_SCH_KERNEL_AICORE = 0,	    /* AI core task */
	NPU_SCH_KERNEL_AICPU = 1,	   /* AI cpu task */
	NPU_SCH_EVENT_RECORD = 2,	   /* event record task */
	NPU_SCH_STREAM_WAIT_EVENT = 3,	  /* stream wait event task */
	NPU_SCH_FUSION_ISSUE = 4,	     /* fusion issue task */
	NPU_SCH_MEMCPY = 5,	          /* memory copy task */
	NPU_SCH_MAINTENANCE = 6,	      /* such as destroy the event or stream */
	NPU_SCH_CREATE_STREAM = 7,	   /* create stream task */
	NPU_SCH_REMOTE_EVENT_WAIT = 9,	  /* wait for event on another device */
	NPU_SCH_PCTRACE_ENABLE = 10,
	NPU_SCH_CREATE_L2_ADDR = 11,	  /* create L2 addr info for aicpu kernel */
	NPU_SCH_MODEL_MAINTAINCE = 12,
	NPU_SCH_MODEL_EXECUTE = 13,
	NPU_SCH_RDMA_SEND = 16,	     /* hccl rdma send task */
	NPU_SCH_L2_SDMA_TASK_MEMCPY = 17,	 /* test l2 task memory copy task */
	NPU_SCH_STREAM_SWITCH = 18,
	NPU_SCH_STREAM_ACTIVE = 19,
	NPU_SCH_LABEL_SET = 20,	  /* set label for control flow ops */
	NPU_SCH_LABEL_SWITCH = 21,	  /* switch label for control flow ops */
	NPU_SCH_LABEL_GOTO = 22,	  /* goto label for control flow ops */
	NPU_SCH_PROFILING_ENABLE = 0x40,
	NPU_SCH_PROFILING_DISABLE = 0x41,
	NPU_SCH_RESERVED = 0x42,
} npu_schedule_task_type_t;

typedef struct npu_schedule_event_sqe {
	u16 event_id;
	u8 reserved[46];
} npu_schedule_event_sqe_t;

typedef struct npu_schedule_model_execute_sqe {
	u16 model_id;
	u16 first_task_id;
	u8  res0[4];
	u64 asid_baddr;
	u64 tcr;
	u16 asid;
	u16 smmu_svm_ssid; /* sub_stream_id */
	u8  res1[20];
} npu_schedule_model_execute_sqe_t;

/**
* @brief TS SQE 64B (same to Runtime non_sink Task 64B)
*/
typedef struct npu_schedule_comm_sqe {
	/* 16 bytes */
	u16 stream_id;
	u16 task_id;
	u16 next_task_id;
	u16 type;
	u16 next_stream_id;
	u16 task_state;
	u8  task_prof_en;
	u8  reserved[3];
	/* 48 bytes */
	union {
		npu_schedule_event_sqe_t event_sqe; // type 2,3
		npu_schedule_model_execute_sqe_t model_execute_sqe; // type 13
	} u;
} npu_schedule_comm_sqe_t;


typedef enum npu_hwts_irq_type {
	NPU_HWTS_IRQ_TYPE_NORMAL = 0,
	NPU_HWTS_IRQ_TYPE_ERROR = 1,
	NPU_HWTS_IRQ_TYPE_DEBUG = 2,
	NPU_HWTS_IRQ_TYPE_RESERVED,
} npu_hwts_irq_type_t;

typedef struct npu_hwts_irq_rlt {
    npu_hwts_irq_type_t hwts_irq_type;
    u16 stream_id;
    u16 sq_id;
} npu_hwts_irq_rlt_t;

int npu_hwts_irq_init(void);
int npu_schedule_task(npu_dev_ctx_t *dev_ctx, npu_schedule_comm_sqe_t *sch_task);
int npu_hwts_get_sch_result(void);
void npu_hwts_irq_reset(void);

#endif