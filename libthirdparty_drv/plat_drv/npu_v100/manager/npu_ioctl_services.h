/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu ioctl services
 */
#ifndef __NPU_IOCTL_SERVICE_H
#define __NPU_IOCTL_SERVICE_H

#include "npu_proc_ctx.h"

// consistent with devdrv_runtime_api.h
typedef struct npu_contig_mem{
	u64 out_addr; // output param of cma alloc
	u32 req_size; // input param of cma alloc
} npu_contig_mem_t;

typedef struct tag_free_cm_para {
	void* ptr; // cma vaddr prepare to free
} devdrv_free_cm_para_t;

int npu_dev_ioctl(npu_ops_ioctl_info *command_info);

int npu_ioctl_alloc_stream(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_get_occupy_stream_id(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_alloc_event(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_alloc_model(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_alloc_task(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_free_stream(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_free_event(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_free_model(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_free_task(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_mailbox_send(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_flush_smmu_tlb(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_mmap_db_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_unmap_db_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_custom(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_get_ts_timeout(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

extern int npu_proc_dev_ioctl_call(struct npu_proc_ctx *proc_ctx, npu_ops_ioctl_info *command_info);

int npu_ioctl_set_secure_flag(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_get_secure_flag(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_exit_share_mem(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_mmap_power_status_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

int npu_ioctl_unmap_power_status_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size);

#endif /*__DEVDRV_MANAGER_H*/
