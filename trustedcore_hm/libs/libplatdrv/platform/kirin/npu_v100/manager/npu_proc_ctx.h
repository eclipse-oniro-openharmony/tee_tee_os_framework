/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu proc ctx
 */
#ifndef __NPU_PROC_CTX_H
#define __NPU_PROC_CTX_H
#include <list.h>
#include "tee_defines.h"

#include "npu_spec_share.h"
#include "npu_common.h"

#define NPU_MAX_PROC_NUM			1

struct npu_para {
	struct list_head list;
	pid_t pid;
	u32 cq_slot_size;

	u16 group_id; /* docker */
	u16 tflops;
	u16 disable_wakelock;
};

struct npu_proc_ctx {
	pid_t pid; // stores ta pid, not plat drv pid
	u8 devid;
	u32 stream_num;
	u32 sink_stream_num;
	u32 event_num;
	u32 cq_num;
	u32 model_num;
	u32 task_num;
	u32 send_count;
	u32 receive_count;
	u32 last_ts_status;

	/* ipc receive process will check this and find proc_context */
	int ipc_port;
	struct list_head stream_list;
	struct list_head sink_stream_list;
	struct list_head event_list;
	struct list_head model_list;
	struct list_head task_list;
	struct list_head dev_ctx_list;
	struct list_head cq_list;
	atomic_t mailbox_message_count;
	u32 should_stop_thread;
	struct list_head message_list_header;
	struct list_head ipc_msg_send_head;
	struct list_head ipc_msg_return_head;
	struct npu_para para;

	DECLARE_BITMAP(stream_bitmap, DEVDRV_MAX_STREAM_ID);
	DECLARE_BITMAP(event_bitmap, DEVDRV_MAX_EVENT_ID);
	DECLARE_BITMAP(model_bitmap, DEVDRV_MAX_MODEL_ID);
	DECLARE_BITMAP(task_bitmap, DEVDRV_MAX_TASK_ID);
};

/* for get report phase byte */
struct npu_report {
	u32 a;
	u32 b;
	u64 c;
};

// update in cq report interrupt
#define CQ_HEAD_UPDATED_FLAG	0x1
#define CQ_HEAD_INITIAL_UPDATE_FLAG	0x0

#define DEVDRV_REPORT_PHASE	0x8000

#define npu_get_phase_from_report(report)	(((report)->b & DEVDRV_REPORT_PHASE) >> 15)


#define DEVDRV_CQ_PER_IRQ          1
#define DEVDRV_CQ_UPDATE_IRQ_SUM   1

struct npu_cq_report_int_ctx {
		struct npu_proc_ctx *proc_ctx;
		int first_cq_index;
		void* find_cq_task;
};

typedef enum {
	RREPORT_FROM_CQ_HEAD = 0x0,
	RREPORT_FROM_CQ_TAIL,
} cq_report_pos_t;

void npu_proc_ctx_init(struct npu_proc_ctx *proc_ctx);

int npu_request_cq_report_irq_bh(void);

int npu_free_cq_report_irq_bh(void);

void npu_bind_proc_ctx_with_cq_int_ctx(struct npu_proc_ctx *proc_ctx);

void npu_unbind_proc_ctx_with_cq_int_ctx(struct npu_proc_ctx *proc_ctx);

struct npu_ts_cq_info *npu_proc_alloc_cq(struct npu_proc_ctx *proc_ctx);

int npu_proc_free_cq(struct npu_proc_ctx *proc_ctx);

int npu_proc_alloc_stream(struct npu_proc_ctx *proc_ctx, u32 *stream_id, u32 strategy);

int npu_proc_free_stream(struct npu_proc_ctx* proc_ctx, u32 stream_id);

int npu_proc_alloc_event(struct npu_proc_ctx *proc_ctx, u32* event_id_ptr);

int npu_proc_free_event(struct npu_proc_ctx *proc_ctx, u32 event_id);

int npu_proc_alloc_model(struct npu_proc_ctx *proc_ctx, u32* model_id_ptr);

int npu_proc_free_model(struct npu_proc_ctx *proc_ctx, u32 model_id);

int npu_proc_alloc_task(struct npu_proc_ctx *proc_ctx, u32* task_id_ptr);

int npu_proc_free_task(struct npu_proc_ctx *proc_ctx, u32 task_id);

void npu_set_proc_ctx(struct npu_proc_ctx *proc_ctx);

void npu_clear_proc_ctx(void);

struct npu_proc_ctx* npu_get_proc_ctx(int fd);

int npu_proc_clr_sqcq_info(struct npu_proc_ctx *proc_ctx);

#endif /* __DEVDRV_MANAGER_H */
