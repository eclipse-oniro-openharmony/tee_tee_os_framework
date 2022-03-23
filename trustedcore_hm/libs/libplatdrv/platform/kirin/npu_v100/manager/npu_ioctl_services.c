/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu ioctl services
 */

#include "npu_ioctl_services.h"

#include <errno.h>
#include <string.h>
#include <stdint.h>

// get smmu config interface
#include "svm.h"
#include "tee_defines.h"
#include "drv_log.h"
#include "sre_syscalls_ext.h"
#include "tee_mem_mgmt_api.h" /* TEE_Malloc */

#include "npu_io_cmd_share.h"
#include "npu_spec_share.h"
#include "npu_manager_common.h"
#include "npu_proc_ctx.h"
#include "npu_calc_channel.h"
#include "npu_calc_cq.h"
#include "npu_stream.h"
#include "npu_shm.h"
#include "npu_mailbox.h"
#include "npu_event.h"
#include "npu_model.h"
#include "npu_task.h"
#include "npu_cma.h"
#include "npu_pm.h"
#include "npu_common.h"

#define npu_ioctl_para_check(arg, arg_size, info) do { \
	if (arg == 0 || arg_size != sizeof(info)) { \
		NPU_ERR("input arg fault, arg:%llu arg:%llu infosize:%llu", arg, arg_size, sizeof(info)); \
		return -1; \
	} \
} while(0)

extern uint64_t __virt_to_phys(uintptr_t vaddr);
static int s_secure_flag = 0;
extern int npu_proc_send_alloc_stream_mailbox(struct npu_proc_ctx *proc_ctx);
int get_secure_flag_tmp(void)
{
	return s_secure_flag;
}

int npu_ioctl_set_secure_flag(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	(void)proc_ctx;
	npu_ioctl_para_check(arg, arg_size, int);
	if (copy_from_TA_safe(&s_secure_flag, (void *)(uintptr_t)arg, sizeof(int))) {
		NPU_ERR("npu_ioctl_set_secure_flag error\n");
		return -EFAULT;
	}
	NPU_DEBUG("HIAI TA set secure flag = %d\n", s_secure_flag);
	return 0;
}

int npu_ioctl_get_secure_flag(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	(void)proc_ctx;
	NPU_DEBUG("HIAI TA get secure flag = %d\n", s_secure_flag);

	npu_ioctl_para_check(arg, arg_size, int);
	if (copy_to_TA_safe((void *)(uintptr_t)arg, &s_secure_flag, sizeof(int))) {
		NPU_ERR("copy to user safe s_secure_flag = %d error\n", s_secure_flag);
		return -EFAULT;
	}

	return 0;
}

// unmp sq、cq、info、db
int npu_ioctl_exit_share_mem(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	(void)proc_ctx;
	(void)arg;
	(void)arg_size;
	u8 dev_id = 0; // default
	int ret;

	ret = npu_shm_unmap(dev_id);
	NPU_INFO("npu_ioctl_exit_share_mem devid = %d ret = %d\n", dev_id, ret);

	return ret;
}

void acpu_gic_set_spi_pending(uint32_t irq)
{
	uint32_t val;
	uint32_t base_addr = 0xfe400200;
	uint32_t reg_addr = base_addr + ((irq >> 5) << 2);
	uint32_t *reg_ptr = (uint32_t *)(uintptr_t)reg_addr;

	val = 0x1 << (irq % 32);
	NPU_ERR("before write reg_addr = 0x%x val = 0x%x ", reg_ptr, *reg_ptr);
	*reg_ptr = val;

	NPU_ERR("after write reg_addr = 0x%x val  = 0x%x ", reg_ptr, *reg_ptr);
}


int npu_ioctl_alloc_stream(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int stream_id = 0;
	int ret;
	uint32_t strategy;
	struct npu_stream_strategy_ioctl_info *para =
		(struct npu_stream_strategy_ioctl_info*)((uintptr_t)arg);

	npu_ioctl_para_check(arg, arg_size, struct npu_stream_strategy_ioctl_info);
	strategy = para->strategy;

	NPU_DEBUG("strategy = %d", strategy);

	MUTEX_LOCK(stream);
	ret = npu_proc_alloc_stream(proc_ctx, (u32*)(uintptr_t)(&stream_id), strategy);
	if (ret != 0) {
		NPU_ERR("npu_alloc_stream failed\n");
		MUTEX_UNLOCK(stream);
		return -ENOKEY;
	}
	para->stream_id = stream_id;
	BITMAP_SET(proc_ctx->stream_bitmap, stream_id);
	MUTEX_UNLOCK(stream);

	NPU_INFO("alloc strategy = %d stream_id = %d success\n", strategy, stream_id);

	return 0;
}

int npu_ioctl_get_occupy_stream_id(struct npu_proc_ctx *proc_ctx,
                                   unsigned long arg, unsigned long arg_size)
{
	struct npu_occupy_stream_id *stream_id = NULL;
	struct npu_stream_sub_info *stream_sub_info = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;

	npu_ioctl_para_check(arg, arg_size, struct npu_occupy_stream_id);

	stream_id = (struct npu_occupy_stream_id *)(uintptr_t)arg;
	if (stream_id == NULL) {
		NPU_ERR("npu_occupy_stream_id param illegal\n");
		return -1;
	}

	stream_id->count = 0;

	list_for_each_safe(pos, n, &proc_ctx->sink_stream_list) {
		if (stream_id->count >= DEVDRV_MAX_SINK_STREAM_ID) {
			NPU_ERR("illegal sink stream_id->count = %u", stream_id->count);
			return -1;
		}
		stream_sub_info = list_entry(pos, struct npu_stream_sub_info, list);
		stream_id->id[stream_id->count] = stream_sub_info->id;
		stream_id->count++;
	}

	list_for_each_safe(pos, n, &proc_ctx->stream_list) {
		if (stream_id->count >= DEVDRV_MAX_STREAM_ID) {
			NPU_ERR("illegal non sink stream_id->count = %u", stream_id->count);
			return -1;
		}
		stream_sub_info = list_entry(pos, struct npu_stream_sub_info, list);
		stream_id->id[stream_id->count] = stream_sub_info->id;
		stream_id->count++;
	}

	NPU_WARN("stream_id->count = %u", stream_id->count);
	return 0;
}

int npu_ioctl_alloc_event(struct npu_proc_ctx *proc_ctx,
                          unsigned long arg, unsigned long arg_size)
{
	int event_id = 0;
	int ret;

	npu_ioctl_para_check(arg, arg_size, int);

	MUTEX_LOCK(event);
	ret = npu_proc_alloc_event(proc_ctx, (u32*)(uintptr_t)(&event_id));
	if (ret != 0) {
		NPU_ERR("proc alloc event failed, event id: %d\n", event_id);
		MUTEX_UNLOCK(event);
		return -EFAULT;
	}

	if (copy_to_TA_safe((void *)(uintptr_t)arg, &event_id, sizeof(int))) {
		NPU_ERR("copy to user safe event_id = %d error\n", event_id);
		if (event_id != DEVDRV_MAX_EVENT_ID) {
			ret = npu_proc_free_event(proc_ctx, event_id);
			if (ret != 0) {
				NPU_ERR("proc free event id failed, event id: %d\n", event_id);
				MUTEX_UNLOCK(event);
				return -EFAULT;
			}
			MUTEX_UNLOCK(event);
			return -EFAULT;
		}
	}
	BITMAP_SET(proc_ctx->event_bitmap, event_id);
	MUTEX_UNLOCK(event);
	return 0;
}

int npu_ioctl_alloc_model(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int model_id = 0;
	int ret;

	npu_ioctl_para_check(arg, arg_size, int);

	MUTEX_LOCK(model);
	ret = npu_proc_alloc_model(proc_ctx, (u32*)(uintptr_t)(&model_id));
	if (ret != 0) {
		NPU_ERR("proc alloc model failed, model id: %d\n", model_id);
		MUTEX_UNLOCK(model);
		return -EFAULT;
	}

	if (copy_to_TA_safe((void *)(uintptr_t)arg, &model_id, sizeof(int))) {
		NPU_ERR("copy to user safe model_id = %d error\n", model_id);
		if (model_id != DEVDRV_MAX_EVENT_ID) {
			ret = npu_proc_free_model(proc_ctx, model_id);
			if (ret != 0) {
				NPU_ERR("proc free model id failed, model id: %d\n", model_id);
				MUTEX_UNLOCK(model);
				return -EFAULT;
			}
			MUTEX_UNLOCK(model);
			return -EFAULT;
		}
	}

	BITMAP_SET(proc_ctx->model_bitmap, model_id);
	MUTEX_UNLOCK(model);
	return 0;
}

int npu_ioctl_alloc_task(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int task_id = 0;
	int ret;

	npu_ioctl_para_check(arg, arg_size, int);

	MUTEX_LOCK(task);
	ret = npu_proc_alloc_task(proc_ctx, (u32*)(uintptr_t)(&task_id));
	if (ret != 0) {
		NPU_ERR("proc alloc task failed, task id: %d\n", task_id);
		MUTEX_UNLOCK(task);
		return -EFAULT;
	}

	if (copy_to_TA_safe((void *)(uintptr_t)arg, &task_id, sizeof(int))) {
		NPU_ERR("copy to user safe task_id = %d error\n", task_id);
		if (task_id != DEVDRV_MAX_TASK_ID) {
			ret = npu_proc_free_task(proc_ctx, task_id);
			if (ret != 0) {
				NPU_ERR("proc free task id failed, task id: %d\n", task_id);
				MUTEX_UNLOCK(task);
				return -EFAULT;
			}
			MUTEX_UNLOCK(task);
			return -EFAULT;
		}
	}

	BITMAP_SET(proc_ctx->task_bitmap, task_id);
	MUTEX_UNLOCK(task);
	return 0;
}

static int npu_check_ioctl_free_stream_para(struct npu_proc_ctx *proc_ctx,
                                            unsigned long arg, int* pstream_id)
{
	MUTEX_LOCK(stream);
	if (copy_from_TA_safe(pstream_id, (void *)(uintptr_t)arg, sizeof(int))) {
		MUTEX_UNLOCK(stream);
		NPU_ERR("npu_check_ioctl_free_stream_para error\n");
		return -EFAULT;
	}

	NPU_DEBUG("HIAI TA prepare free stream id = %d\n", *pstream_id);

	if (*pstream_id >= DEVDRV_MAX_STREAM_ID) {
		MUTEX_UNLOCK(stream);
		NPU_ERR("npu_check_ioctl_free_stream_para free_stream_id %d\n", *pstream_id);
		return -EFAULT;
	}

	if (!BITMAP_OCCUPIED(proc_ctx->stream_bitmap, *pstream_id)) {
		MUTEX_UNLOCK(stream);
		NPU_ERR("stream_id %d has been freed before", *pstream_id);
		return -EFAULT;
	}

	MUTEX_UNLOCK(stream);

	return 0;
}

static int npu_check_ioctl_free_event_para(struct npu_proc_ctx *proc_ctx,
                                           unsigned long arg, u32* event_id)
{
	MUTEX_LOCK(event);
	if (copy_from_TA_safe(event_id, (void *)(uintptr_t)arg, sizeof(int))) {
		MUTEX_UNLOCK(event);
		NPU_ERR("npu_check_ioctl_free_event_para error\n");
		return -EFAULT;
	}

	if (*event_id >= DEVDRV_MAX_EVENT_ID) {
		MUTEX_UNLOCK(event);
		NPU_ERR("npu_check_ioctl_free_event_para free_stream_id %d\n", *event_id);
		return -EFAULT;
	}

	if (!BITMAP_OCCUPIED(proc_ctx->event_bitmap, *event_id)) {
		MUTEX_UNLOCK(event);
		NPU_ERR("event_id  %d has been freed before", *event_id);
		return -EFAULT;
	}
	MUTEX_UNLOCK(event);

	return 0;
}

static int npu_check_ioctl_free_model_para(struct npu_proc_ctx *proc_ctx,
                                           unsigned long arg, u32* model_id)
{
	MUTEX_LOCK(model);
	if (copy_from_TA_safe(model_id, (void *)(uintptr_t)arg, sizeof(int))) {
		MUTEX_UNLOCK(model);
		NPU_ERR("npu_check_ioctl_free_model_para error\n");
		return -EFAULT;
	}

	NPU_DEBUG("HIAI TA prepare free model_id = %d\n", *model_id);

	if (*model_id >= DEVDRV_MAX_MODEL_ID) {
		MUTEX_UNLOCK(model);
		NPU_ERR("npu_check_ioctl_free_model_para free_stream_id %d\n", *model_id);
		return -EFAULT;
	}

	if (!BITMAP_OCCUPIED(proc_ctx->model_bitmap, *model_id)) {
		MUTEX_UNLOCK(model);
		NPU_ERR("model_id  %d has been freed before", *model_id);
		return -EFAULT;
	}

	MUTEX_UNLOCK(model);
	return 0;
}

static int npu_check_ioctl_free_task_para(struct npu_proc_ctx *proc_ctx,
                                          unsigned long arg, u32* task_id)
{
	MUTEX_LOCK(task);
	if (copy_from_TA_safe(task_id, (void *)(uintptr_t)arg, sizeof(int))) {
		MUTEX_UNLOCK(task);
		NPU_ERR("npu_check_ioctl_free_task_para error\n");
		return -EFAULT;
	}
	NPU_DEBUG("HIAI TA prepare free task_id = %d\n", *task_id);
	if (*task_id >= DEVDRV_MAX_TASK_ID) {
		MUTEX_UNLOCK(task);
		NPU_ERR("npu_check_ioctl_free_task_para free_task_id %d\n", *task_id);
		return -EFAULT;
	}

	if (!BITMAP_OCCUPIED(proc_ctx->task_bitmap, *task_id)) {
		MUTEX_UNLOCK(task);
		NPU_ERR("task_id  %d has been freed before", *task_id);
		return -EFAULT;
	}

	MUTEX_UNLOCK(task);
	return 0;
}

static int npu_proc_ioctl_free_stream(struct npu_proc_ctx *proc_ctx,
                                      u32 free_stream_id)
{
	int ret;

	MUTEX_LOCK(stream);
	ret = npu_proc_free_stream(proc_ctx, free_stream_id);
	MUTEX_UNLOCK(stream);

	if (ret != 0) {
		NPU_ERR("npu_ioctl_free_stream_id = %d error\n", free_stream_id);
		return -1;
	}

	return ret;
}

static int npu_proc_ioctl_free_event(struct npu_proc_ctx *proc_ctx,
                                     u32 free_event_id)
{
	int ret;

	MUTEX_LOCK(event);
	ret = npu_proc_free_event(proc_ctx, free_event_id);
	MUTEX_UNLOCK(event);
	if (ret != 0) {
		NPU_ERR("free event id = %d error\n", free_event_id);
		ret = -1;
	}

	return ret;
}

static int npu_proc_ioctl_free_model(struct npu_proc_ctx *proc_ctx,
                                     u32 free_model_id)
{
	int ret;

	MUTEX_LOCK(model);
	ret = npu_proc_free_model(proc_ctx, free_model_id);
	MUTEX_UNLOCK(model);
	if (ret != 0) {
		NPU_ERR("free model id = %d error\n", free_model_id);
		ret = -1;
	}

	return ret;
}

static int npu_proc_ioctl_free_task(struct npu_proc_ctx *proc_ctx,
                                    u32 free_task_id)
{
	int ret;

	MUTEX_LOCK(task);
	ret = npu_proc_free_task(proc_ctx, free_task_id);
	MUTEX_UNLOCK(task);

	if (ret != 0) {
		NPU_ERR("free task id = %d error\n", free_task_id);
		ret = -1;
	}

	return ret;
}

int npu_ioctl_free_stream(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int ret;
	int stream_id = 0;

	npu_ioctl_para_check(arg, arg_size, int);

	ret = npu_check_ioctl_free_stream_para(proc_ctx, arg, &stream_id);
	if (ret != 0) {
		NPU_ERR("npu_ioctl_free_stream check para fail\n");
		return -EFAULT;
	}

	return npu_proc_ioctl_free_stream(proc_ctx, stream_id);
}

int npu_ioctl_free_event(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int ret;
	int event_id = 0;
	npu_ioctl_para_check(arg, arg_size, int);
	ret = npu_check_ioctl_free_event_para(proc_ctx, arg, (u32*)(uintptr_t)(&event_id));
	if (ret != 0) {
		NPU_ERR("npu_ioctl_free_event check para fail\n");
		return -EFAULT;
	}

	return npu_proc_ioctl_free_event(proc_ctx, event_id);
}

int npu_ioctl_free_model(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int ret;
	int model_id = 0;
	npu_ioctl_para_check(arg, arg_size, int);
	ret = npu_check_ioctl_free_model_para(proc_ctx, arg, (u32*)(uintptr_t)(&model_id));
	if (ret != 0) {
		NPU_ERR("npu_ioctl_free_model check para fail\n");
		return -EFAULT;
	}

	return npu_proc_ioctl_free_model(proc_ctx, model_id);
}

int npu_ioctl_free_task(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int ret;
	int task_id = 0;
	npu_ioctl_para_check(arg, arg_size, int);
	ret = npu_check_ioctl_free_task_para(proc_ctx, arg, (u32*)(uintptr_t)(&task_id));
	if (ret != 0) {
		NPU_ERR("npu_ioctl_free_task check para fail\n");
		return -EFAULT;
	}

	return npu_proc_ioctl_free_task(proc_ctx, task_id);
}

int npu_ioctl_flush_smmu_tlb(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	UNUSED(arg);
	(void)arg_size;
	return npu_flush_smmu_tlb(proc_ctx->devid);
}

static int davinci_va_to_pa(struct davinci_area_info *params)
{
	unsigned long ta_vaddr = params->va;
	uint32_t phy_addr = 0;
	int err;
	err = npu_cma_ta_vaddr_to_paddr((void *)(uintptr_t)ta_vaddr, &phy_addr);
	params->pa = (unsigned long)phy_addr;

	return err;
}

static int npu_ioctl_davinci_va_to_pa(u64 arg, u64 arg_size)
{
	int ret;
	struct davinci_area_info params;

	params.va = 0;
	params.pa = 0;
	params.len = 0;

	npu_ioctl_para_check(arg, arg_size, struct davinci_area_info);

	ret = copy_from_TA_safe(&params, (void *)(uintptr_t)arg, sizeof(params));
	if (ret != 0) {
		NPU_ERR("fail to copy davinci_area_info params, ret = %d\n", ret);
		return -1;
	}
	ret = davinci_va_to_pa(&params);
	if (ret != 0) {
 		NPU_ERR("fail to change the virtual pte, ret = %d\n", ret);
		return ret;
	}
	ret = copy_to_TA_safe((void *)(uintptr_t)arg, &params, sizeof(params));
	if (ret != 0) {
		NPU_ERR("fail to copy phys params to user space, ret = %d\n", ret);
		return -1;
	}

	return ret;
}

static int npu_ioctl_get_chip_info(u64 arg, u64 arg_size)
{
	int ret;
	struct npu_chip_info info = {0};

	npu_ioctl_para_check(arg, arg_size, struct npu_chip_info);
	struct npu_mem_desc *l2_desc = npu_plat_get_reg_desc(DEVDRV_REG_L2BUF_BASE);

	if (l2_desc == NULL) {
		NPU_ERR("npu_plat_get_reg_desc failed\n");
		return -EFAULT;
	}

	info.l2_size = l2_desc->len;

	ret = copy_to_TA_safe((void *)(uintptr_t)arg, &info, sizeof(info));
	if (ret != 0) {
		NPU_ERR("fail to copy chip_info params to user space,ret = %d\n", ret);
		return -1;
	}

	return ret;
}

// https://patchwork.kernel.org/patch/10213969/
// At the moment, the SMMUv3 driver offers only one stage-1 or stage-2
// address space to each device. SMMUv3 allows to associate multiple address
// spaces per device. in addition to the Stream ID (SID), that identifies a
// device, we can now have Substream IDs (SSID) identifying an address space.
// In PCIe lingo, SID is called Requester ID (RID) and SSID is called Process
// Address-Space ID (PASID).
//
// Prepare the driver for SSID support, by adding context descriptor tables
// in STEs (previously a single static context descriptor). A complete
// stage-1 walk is now performed like this by the SMMU:
//
//      Stream tables          Ctx. tables          Page tables
//        +--------+   ,------->+-------+   ,------->+-------+
//        :        :   |        :       :   |        :       :
//        +--------+   |        +-------+   |        +-------+
//   SID->|  STE   |---'  SSID->|  CD   |---'  IOVA->|  PTE  |--> IPA
//        +--------+            +-------+            +-------+
//        :        :            :       :            :       :
//        +--------+            +-------+            +-------+
//
// We only implement one level of context descriptor table for now, but as
// with stream and page tables, an SSID can be split to target multiple
// levels of tables.
//
// In all stream table entries, we set S1DSS=SSID0 mode, making translations
// without an ssid use context descriptor 0.
static int npu_ioctl_get_svm_ssid(struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	int ret;
	struct tee_svm_para_list *svm_para_list = NULL;
	struct process_info *info_p = NULL;

	npu_ioctl_para_check(arg, arg_size, struct process_info);

	info_p = (struct process_info *)(uintptr_t)arg;

	svm_para_list = (struct tee_svm_para_list *)dev_ctx->hisi_svm;
	ret = __teesvm_ioctl(SVM_SEC_CMD_GET_SSID, svm_para_list);
	if (ret) {
		NPU_ERR("fail to get ssid through __teesvm_ioctl, ret = %d\n", ret);
		return ret;
	}

	info_p->ttbr = svm_para_list->ttbr;
	info_p->tcr = svm_para_list->tcr;
	info_p->pasid = svm_para_list->ssid;

	NPU_DEBUG("get ssid 0x%x ttbr %p tcr %p arg_size = %u \n",
	         info_p->pasid, (void *)(uintptr_t)info_p->ttbr,
	         (void *)(uintptr_t)info_p->tcr, sizeof(struct process_info));
	return ret;
}

int npu_ioctl_alloc_cm(struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	npu_contig_mem_t alloc_cma = {0};
	u32 ta_vaddr = 0;
	u64 size;
	int ret;

	if (dev_ctx == NULL) {
		NPU_ERR("dev_ctx is null\n");
		return -1;
	}
	npu_ioctl_para_check(arg, arg_size, npu_contig_mem_t);

	MUTEX_LOCK(cma);
	ret = copy_from_TA_safe(&alloc_cma, (void *)(uintptr_t)arg, sizeof(alloc_cma));
	if (ret) {
		MUTEX_UNLOCK(cma);
		NPU_ERR("fail to copy npu alloc_cma params, ret = %d\n", ret);
		return -1;
	}

	size = alloc_cma.req_size;
	ret = npu_cma_alloc(size, &ta_vaddr);
	if (ret) {
		MUTEX_UNLOCK(cma);
		NPU_ERR("fail to malloc cma mem size 0x%llx\n", size);
		return -ENOMEM;
	}

	alloc_cma.out_addr = ta_vaddr;
	ret = copy_to_TA_safe((void *)(uintptr_t)arg, &alloc_cma, sizeof(alloc_cma));
	if (ret) {
		npu_cma_free((void *)(uintptr_t)ta_vaddr);
		MUTEX_UNLOCK(cma);
		NPU_ERR("fail to copy npu cma params to hiai ta space, ret = %d\n", ret);
		return ret;
	}

	MUTEX_UNLOCK(cma);

	return 0;
}

int npu_ioctl_get_shm_ta_vaddr(struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	npu_shm_vaddr_t *ta_shm_vaddrs = NULL;
	int ret;

	if (dev_ctx == NULL) {
		NPU_ERR("dev_ctx is null\n");
		return -1;
	}
	npu_ioctl_para_check(arg, arg_size, npu_shm_vaddr_t);

	ta_shm_vaddrs = (npu_shm_vaddr_t *)(uintptr_t)arg; // already platdrv vaddr after "ACCESS_CHECK"
	ret = npu_shm_mmap(dev_ctx->devid, ta_shm_vaddrs);
	if (ret != 0) {
		NPU_ERR("fail to get shm to ta_vaddr ret = %d\n", ret);
		return -1;
	}
	return 0;
}

int npu_ioctl_mmap_db_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	uintptr_t *db_vaddrs = NULL;
	int ret;

	if (proc_ctx == NULL) {
		NPU_ERR("proc_ctx is null\n");
		return -1;
	}

	npu_ioctl_para_check(arg, arg_size, uintptr_t);

	db_vaddrs = (uintptr_t *)(uintptr_t)arg;
	ret = npu_doorbell_mmap(proc_ctx->devid, db_vaddrs);
	if (ret != 0) {
		NPU_ERR("fail to map db vaddr ret = %d\n", ret);
		return -1;
	}
	return 0;
}

int npu_ioctl_unmap_db_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	(void)arg;
	(void)arg_size;
	int ret;

	ret = npu_doorbell_unmap(proc_ctx->devid);

	NPU_INFO("npu_ioctl_exit_share_mem devid = %d ret = %d\n", proc_ctx->devid, ret);

	return ret;
}

int npu_ioctl_mmap_power_status_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	uintptr_t *vaddrs = NULL;
	int ret;

	COND_RETURN_ERROR(proc_ctx == NULL, -1, "proc_ctx is null\n");

	npu_ioctl_para_check(arg, arg_size, uintptr_t);

	vaddrs = (uintptr_t *)(uintptr_t)arg;
	ret = npu_power_status_mmap(proc_ctx->devid, vaddrs);
	COND_RETURN_ERROR(ret != 0, -1, "fail to map power status vaddr ret = %d\n", ret);

	return ret;
}

int npu_ioctl_unmap_power_status_vaddr(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	(void)arg;
	(void)arg_size;
	int ret;

	ret = npu_power_status_unmap(proc_ctx->devid);
	NPU_INFO("npu_ioctl_exit_share_mem devid = %d ret = %d\n", proc_ctx->devid, ret);

	return ret;
}

int npu_ioctl_mmap_ta_vaddr(struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	ta_vm_area_t *ta_vm_area = NULL;
	int ret;

	if (dev_ctx == NULL) {
		NPU_ERR("dev_ctx is null\n");
		return -1;
	}
	npu_ioctl_para_check(arg, arg_size, ta_vm_area_t);

	ta_vm_area = (ta_vm_area_t *)(uintptr_t)arg; // already platdrv vaddr after "ACCESS_CHECK"
	if (ta_vm_area == NULL) {
		NPU_ERR(" ta_vm_area from hiai ta is null\n");
		return -1;
	}

	ret = npu_dev_map(dev_ctx->devid, ta_vm_area);
	if (ret != 0) {
		NPU_ERR("fail to map phsical mem to ta_vaddr ret = %d\n", ret);
		return -1;
	}

	return 0;
}

int npu_ioctl_unmap_ta_vaddr(struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	npu_unmap_ta_vaddr_t *ta_vaddr_info = NULL;
	int ret;

	if (dev_ctx == NULL) {
		NPU_ERR("dev_ctx is null\n");
		return -1;
	}
	npu_ioctl_para_check(arg, arg_size, npu_unmap_ta_vaddr_t);

	ta_vaddr_info = (npu_unmap_ta_vaddr_t *)(uintptr_t)arg; // already platdrv vaddr after "ACCESS_CHECK"
	if (ta_vaddr_info == NULL) {
		NPU_ERR(" ta_vaddr_info from hiai ta is null\n");
		return -1;
	}

	NPU_DEBUG(" unmap ta_vaddr = %p size = 0x%x \n",
		(void *)ta_vaddr_info->ta_vaddr, ta_vaddr_info->size);

	ret = npu_dev_unmap(ta_vaddr_info->ta_vaddr, ta_vaddr_info->size);
	if (ret != 0) {
		NPU_ERR("fail to unmap ta_vaddr = %p size = 0x%x ret = %d\n",
			(void *)ta_vaddr_info->ta_vaddr, ta_vaddr_info->size, ret);
		return -1;
	}

	return 0;
}

int npu_ioctl_free_cm(struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	int ret;
	devdrv_free_cm_para_t free_cma = {0};

	if (dev_ctx == NULL) {
		NPU_ERR("dev_ctx is null\n");
		return -1;
	}
	npu_ioctl_para_check(arg, arg_size, devdrv_free_cm_para_t);

	MUTEX_LOCK(cma);

	ret = copy_from_TA_safe(&free_cma, (void *)(uintptr_t)arg, sizeof(free_cma));
	if (ret) {
		MUTEX_UNLOCK(cma);
		NPU_ERR("fail to copy free_cma params, ret = %d\n", ret);
		return -1;
	}

	NPU_DEBUG(" free_cma.ptr = %p from hiai ta \n", free_cma.ptr);

	ret = npu_cma_free(free_cma.ptr);
	if (ret) {
		MUTEX_UNLOCK(cma);
		NPU_ERR(" free_cma.ptr = %p from hiai ta failed\n", free_cma.ptr);
		return ret;
	}

	MUTEX_UNLOCK(cma);

	return 0;
}

int npu_check_ioctl_custom_para(struct npu_proc_ctx *proc_ctx,
                                unsigned long arg,
                                npu_custom_para_t* custom_para,
                                struct npu_dev_ctx** dev_ctx)
{
	int ret;

	ret = copy_from_TA_safe(custom_para, (void *)(uintptr_t)arg, sizeof(npu_custom_para_t));
	if (ret != 0) {
		NPU_ERR("npu_check_ioctl_custom_para,ret = %d\n", ret);
		return -1;
	}

	if (custom_para->arg == 0) {
		NPU_ERR("npu_check_ioctl_custom_para invalid arg\n");
		return -1;
	}

	*dev_ctx = get_dev_ctx_by_id(proc_ctx->devid);
	if ((*dev_ctx) == NULL) {
		NPU_ERR("npu_proc_ioctl_custom %d of npu process %d is null\n", proc_ctx->devid, proc_ctx->pid);
		return -1;
	}

	return ret;
}

int npu_ioctl_powerup(struct npu_proc_ctx *proc_ctx, struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	npu_secure_info_t *sec_mode_info = NULL;
	u32 secure_mode;
	int ret;
	npu_ioctl_para_check(arg, arg_size, npu_secure_info_t);

	sec_mode_info = (npu_secure_info_t *)(uintptr_t)arg;
	secure_mode = sec_mode_info->secure_mode;

	NPU_WARN("power up secure_mode = 0x%x \n", secure_mode);

	if (secure_mode == NPU_NONSEC) {
		NPU_ERR("illgal secure mode\n");
		return -1;
	}

	MUTEX_LOCK(pm);
	ret = npu_powerup(dev_ctx);
	if (ret) {
		MUTEX_UNLOCK(pm);
		NPU_ERR("npu powerup failed\n");
		return ret;
	}
	npu_set_sec_stat(dev_ctx->devid, secure_mode);

	ret = npu_proc_send_alloc_stream_mailbox(proc_ctx);
	if (ret) {
		MUTEX_UNLOCK(pm);
		NPU_ERR("npu send stream mailbox failed\n");
		return ret;
	}

	MUTEX_UNLOCK(pm);
	return ret;
}


int npu_ioctl_powerdown(struct npu_proc_ctx *proc_ctx, struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	(void)arg;
	(void)arg_size;
	int ret;

	NPU_WARN("power down start\n");

	MUTEX_LOCK(pm);
	(void)npu_proc_clr_sqcq_info(proc_ctx);

	ret = npu_powerdown(dev_ctx);
	if (ret != 0) {
		MUTEX_UNLOCK(pm);
		NPU_ERR("npu powerdown failed\n");
		return ret;
	}

	MUTEX_UNLOCK(pm);

	return ret;
}

int npu_ioctl_reboot(struct npu_proc_ctx *proc_ctx, struct npu_dev_ctx *dev_ctx, u64 arg, u64 arg_size)
{
	(void)proc_ctx;
	(void)dev_ctx;
	(void)arg;
	(void)arg_size;
	return 0;
}

static int npu_proc_ioctl_custom(struct npu_proc_ctx *proc_ctx,
                                 struct npu_dev_ctx *dev_ctx,
                                 const npu_custom_para_t* custom_para)
{
	int ret = 0;
	switch (custom_para->cmd) {
		case DEVDRV_IOC_VA_TO_PA:
			ret = npu_ioctl_davinci_va_to_pa(custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_GET_SVM_SSID:
			ret = npu_ioctl_get_svm_ssid(dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_GET_CHIP_INFO:
			ret = npu_ioctl_get_chip_info(custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_ALLOC_CONTIGUOUS_MEM:
			// need lock because cm_info global resoure
			ret = npu_ioctl_alloc_cm(dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_FREE_CONTIGUOUS_MEM:
			ret = npu_ioctl_free_cm(dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_GET_SHM_MEM_TA_VADDR:
			ret = npu_ioctl_get_shm_ta_vaddr(dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_MMAP_PHY_MEM_TA_VADDR:
			ret = npu_ioctl_mmap_ta_vaddr(dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_UNMAP_HIAI_TA_VADDR:
			ret = npu_ioctl_unmap_ta_vaddr(dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_POWERUP:
			ret = npu_ioctl_powerup(proc_ctx, dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_POWERDOWN:
			ret = npu_ioctl_powerdown(proc_ctx, dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		case DEVDRV_IOC_REBOOT:
			ret = npu_ioctl_reboot(proc_ctx, dev_ctx, custom_para->arg, custom_para->arg_size);
			break;
		default:
			NPU_ERR("invalid custom cmd 0x%x \n", custom_para->cmd);
			ret = -1;
			break;
	}

	return ret;
}


int npu_ioctl_custom(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	int ret;
	npu_custom_para_t custom_para = {0};
	struct npu_dev_ctx* dev_ctx = NULL;

	npu_ioctl_para_check(arg, arg_size, npu_custom_para_t);

	ret = npu_check_ioctl_custom_para(proc_ctx, arg, &custom_para, &dev_ctx);
	if (ret != 0) {
		NPU_ERR("npu_ioctl_custom,ret = %d\n", ret);
		return -1;
	}

	ret = npu_proc_ioctl_custom(proc_ctx, dev_ctx, &custom_para);
	if (ret != 0) {
		NPU_ERR("npu_ioctl_custom call npu_proc_ioctl_custom,ret = %d\n", ret);
		return -1;
	}

	return ret;
}

/*
 * new add for TS timeout function
 */
int npu_ioctl_get_ts_timeout(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	(void)proc_ctx;
	uint64_t exception_code = 0;

	npu_ioctl_para_check(arg, arg_size, uint64_t);

	if (copy_from_TA_safe(&exception_code, (void *)(uintptr_t)arg, sizeof(uint64_t))) {
		NPU_ERR("copy_from_TA_safe error\n");
		return -EFAULT;
	}

	return 0;
}

static int npu_ioctl_message_send_one(struct npu_dev_ctx *dev_ctx, struct npu_mailbox_message *message)
{
	(void)dev_ctx;
	(void)message;
	return 0;
}

int npu_ioctl_mailbox_send(struct npu_proc_ctx *proc_ctx, unsigned long arg, unsigned long arg_size)
{
	NPU_ERR("enter, arg: 0x%lx\n", arg);

	COND_RETURN_ERROR(proc_ctx->devid > NPU_DEV_NUM, -1, "device id is illegal\n");

	npu_ioctl_para_check(arg, arg_size, struct npu_mailbox_user_message);

	struct npu_dev_ctx *dev_ctx = get_dev_ctx_by_id(proc_ctx->devid);
	COND_RETURN_ERROR(dev_ctx == NULL, -ENODATA, "get device context by device id failed\n");

	struct npu_mailbox_user_message *user_message = TEE_Malloc(sizeof(struct npu_mailbox_user_message), 0);
	COND_RETURN_ERROR(user_message == NULL, -ENOMEM, "kmalloc failed\n");

	int ret = copy_from_TA_safe(user_message, (void *)(uintptr_t)arg, sizeof(struct npu_mailbox_user_message));
	NPU_ERR("copy_from_TA_safe, user_message: %pK, arg: %pK\n", (void *)user_message, (void *)(uintptr_t)arg);

	COND_GOTO_ERROR(ret != 0, fail, ret, -EFAULT, "copy_from_TA_safe error\n");

	NPU_ERR("user_message->message_length: %d\n", user_message->message_length);

	COND_GOTO_ERROR(user_message->message_length <= 0 || user_message->message_length > DEVDRV_MAILBOX_PAYLOAD_LENGTH,
		fail, ret, -1, "invalid input argument\n");

	struct npu_mailbox_message *message = TEE_Malloc(sizeof(struct npu_mailbox_message), 0);

	COND_GOTO_ERROR(message == NULL, fail, ret, -ENOMEM, "kmalloc failed\n");

	message->message_payload = TEE_Malloc(DEVDRV_MAILBOX_PAYLOAD_LENGTH, 0);
	if (message->message_payload == NULL) {
		TEE_Free(message);
		message = NULL;
		TEE_Free(user_message);
		user_message = NULL;
		NPU_ERR("kmalloc failed\n");
		return -ENOMEM;
	}

	COND_RETURN_ERROR(memcpy_s(message->message_payload, user_message->message_length,
		user_message->message_payload, user_message->message_length) != EOK, -ENOMEM, "message memcpy_s failed\n");

	message->message_length = user_message->message_length;

	message->process_result = 0;
	message->sync_type = user_message->sync_type;
	message->cmd_type= user_message->cmd_type;
	message->message_index = user_message->message_index;
	message->message_pid = user_message->message_pid;
	message->mailbox = &dev_ctx->mailbox;
	message->abandon = 0;

	TEE_Free(user_message);
	user_message = NULL;

	return npu_ioctl_message_send_one(dev_ctx, message);
fail:
	TEE_Free(user_message);
	user_message = NULL;
	return ret;
}

static int npu_iocmd_para_check(npu_ops_ioctl_info *command_info)
{
	if (command_info->fd != NPU_DEV_SEC_MODE_OPENFD) {
		NPU_ERR("invalid fd:0x%x\n", command_info->fd);
		return -1;
	}

	if (_IOC_NR(command_info->cmd) >= DEVDRV_MAX_CMD) {
		NPU_ERR("cmd is invalid! %d > DEVDRV_MAX_CMD:%d", _IOC_NR(command_info->cmd), DEVDRV_MAX_CMD);
		return -1;
	}

	if (command_info->param == 0) {
		NPU_ERR("invalid param arg, arg is 0\n");
		return -1;
	}

	return 0;
}

int npu_dev_ioctl(npu_ops_ioctl_info *command_info)
{
	struct npu_proc_ctx *proc_ctx = NULL;
	int ret;

	if (command_info == NULL) {
		NPU_ERR(" input command_info is NULL, FATAL arg and ignore\n");
		return -1;
	}

	if (npu_iocmd_para_check(command_info)) {
		NPU_ERR("invalid npu_npu_ioctl parameter,arg = 0x%lx,cmd = %d fd = %d\n",
			command_info->param, command_info->cmd, command_info->fd);
		return -1;
	}

	proc_ctx = npu_get_proc_ctx(command_info->fd);
	if (proc_ctx == NULL) {
		NPU_ERR("get proc_ctx fail. arg=%lu, cmd=%u\n", command_info->param, command_info->cmd);
		return -1;
	}

	ret = npu_proc_dev_ioctl_call(proc_ctx, command_info);
	if (ret != 0) {
		NPU_ERR("npu_npu_ioctl process failed,arg=%lu, cmd = %u\n", command_info->param, command_info->cmd);
		return -1;
	}

	return ret;
}

