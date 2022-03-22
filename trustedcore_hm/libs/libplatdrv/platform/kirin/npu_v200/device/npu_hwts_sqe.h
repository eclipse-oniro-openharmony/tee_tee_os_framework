/*
 * npu_hwts_sqe.h
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

#ifndef __NPU_HWTS_SQE_H__
#define __NPU_HWTS_SQE_H__
#include "npu_base_define.h"

typedef enum npu_hwts_sqe_type {
	NPU_HWTS_SQE_AICORE = 0, /* rt 0 */
	NPU_HWTS_SQE_AICPU = 1,
	NPU_HWTS_SQE_VECTOR_CORE = 2,
	NPU_HWTS_SQE_PLACE_HOLDER = 3, /* rt 20 21 22 */
	NPU_HWTS_SQE_EVENT_RECORD = 4, /* rt 2 */
	NPU_HWTS_SQE_EVENT_WAIT = 5, /* rt 3 */
	NPU_HWTS_SQE_NOTIFY_RECORD = 6, /* rt 15 */
	NPU_HWTS_SQE_NOTIFY_WAIT = 7, /* rt 14 */
	NPU_HWTS_SQE_WRITE_VALUE = 8,
	NPU_HWTS_SQE_MEMCPY = 9, /* rt 5 */
	NPU_HWTS_SQE_TYPE_RESV,
} npu_hwts_sqe_type_t;

typedef struct npu_hwts_sqe_head {
	u8  type;
	u8  ie : 1;
	u8  pre_p : 1;
	u8  post_p : 1;
	u8  wr_cqe : 1;
	u8  rd_cond : 1;
	u8  res0 : 1;
	u8  l2_lock : 1;
	u8  l2_unlock : 1;
	u16 block_dim;
	u16 stream_id;
	u16 task_id;
} npu_hwts_sqe_head_t;

// HWTS_SQE 128B
typedef struct npu_hwts_kernel_sqe {
	u32 type:8;
	u32 ie:1;
	u32 pre_p:1;
	u32 post_p:1;
	u32 wr_cqe:1;
	u32 rd_cond:1;
	u32 res0:1;
	u32 l2_lock:1;
	u32 l2_unlock:1;
	u32 block_dim:16;
	u32 stream_id:16;
	u32 task_id:16;
	// 8 Bytes
	u32 pc_addr_low;
	u32 pc_addr_high:16;
	u32 kernel_credit:8;
	u32 res1:2;
	u32 icache_prefetch_cnt:6;
	u32 param_addr_low;
	u32 param_addr_high:16;
	u32 l2_in_main:8;
	u32 res2:8;
	u32 literal_addr_low;
	u32 literal_addr_high:16;
	u32 res3:16;
	u32 literal_base_ub;
	u32 res4;
	u32 literal_buff_len;
	u32 res5;
	u32 l2_ctrl_addr_low;
	u32 l2_ctrl_addr_high:16;
	u32 res6:16;
	u32 l2_remap[16];
	u32 l2_vaddr_base_low;
	u32 l2_vaddr_base_high:16;
	u32 res7:16;
} npu_hwts_kernel_sqe_t;

/* HWTS_SQE 16B */
typedef struct npu_hwts_cqe {
	volatile u16 p : 1;
	volatile u16 w : 1;
	volatile u16 evt : 1;
	volatile u16 res0 : 1;
	volatile u16 sq_id : 10;
	volatile u16 res1 : 2;
	volatile u16 sq_head;
	volatile u16 stream_id;
	volatile u16 task_id;
	volatile u32 syscnt_low; // status
	volatile u32 syscnt_high; // res0
} npu_hwts_cqe_t;

/* ----------------------  Runtime sink Task  ---------------------- */
typedef struct npu_rt_hwts_kernel_task {
	u64 pc_start;
	u64 param_base;
	u64 l2_preload_ctrl;
	u64 literal_src_addr;
	u32 literal_dst_base;
	u32 literal_size;
	u16 block_dim;
	u8  l2_size;
	u8  priority;
	u8  ai_core_alloc_hint_bw;
	u8  ai_core_alloc_hint_l2bw;
	u8  l2_in_main;
	u8  reserved[1];
} npu_rt_hwts_kernel_task_t;

typedef struct npu_rt_hwts_event_task {
	u16 event_id;
	u8  reserved[46];
} npu_rt_hwts_event_task_t;

typedef struct npu_rt_hwts_notify_task {
	u16 notify_id;
	u8 reserved[46];
} npu_rt_hwts_notify_task_t;

typedef struct npu_rt_hwts_memcpy_task {
	u64 src_addr;
	u64 dst_addr;
	u64 length;
	u16 memcpy_type;
	u8  dir;
	u8  reserved[21];
} npu_rt_hwts_memcpy_task_t;

/*
 * @brief Runtime sink Task 64B (9 kinds of hwts task)
 */
typedef struct npu_rt_hwts_task {
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
		npu_rt_hwts_kernel_task_t kernel_task;
		/* Place holder task */
		npu_rt_hwts_event_task_t event_task;
		npu_rt_hwts_notify_task_t notify_task;
		/* write value task */
		npu_rt_hwts_memcpy_task_t memcpy_task;
	} u;
} npu_rt_hwts_task_t;

int npu_format_hwts_sqe(void *sq_addr, void *task_addr, u16 count);

#endif /* __NPU_HWTS_SQE_H__ */
