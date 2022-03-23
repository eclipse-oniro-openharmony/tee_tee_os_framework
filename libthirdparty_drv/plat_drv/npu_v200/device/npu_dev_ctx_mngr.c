#include <drv_mem.h>

#include "npu_log.h"
#include "npu_dev_ctx_mngr.h"
#include "npu_proc_ctx_mngr.h"
#include "npu_platform_resource.h"

static npu_dev_ctx_t g_dev_ctxs[NPU_DEV_NUM];
static int npu_init_dev_chip_cfg_shm(npu_dev_ctx_t *dev_ctx)
{
	u32 chip_cfg_len = NPU_S_CHIP_CFG_SIZE;
	uintptr_t phy_base = dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].phy_base +
		dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].size;
	uintptr_t virt_base = 0;

	if (sre_mmap((paddr_t)phy_base, chip_cfg_len,
		(uint32_t *)&(virt_base), secure, non_cache)) {
		NPU_DRV_ERR("sre_mmap fail, fatal");
		return -EFAULT;
	}

	COND_RETURN_ERROR(virt_base == (uintptr_t)NULL, -EFAULT, "virt_base is null after sre_mmap");

	dev_ctx->shm_mem[NPU_CHIP_CFG].phy_base = phy_base;
	dev_ctx->shm_mem[NPU_CHIP_CFG].virt_base = virt_base;
	dev_ctx->shm_mem[NPU_CHIP_CFG].size = chip_cfg_len;
	NPU_DRV_DEBUG("npu chip cfg phy base addr 0x%x", phy_base);

	return 0;
}

uint32_t npu_sec_enable()
{
	uintptr_t phy_base = NPU_SEC_RESERVED_DDR_BASE_ADDR;
	npu_secmem_head *head = NULL;
	uint32_t ret;

	if (sre_mmap((paddr_t)phy_base, sizeof(npu_secmem_head), (uint32_t *)(&head), secure, non_cache)) {
		NPU_DRV_WARN("sre_mmap sec shared memory failed");
		return NPU_SEC_FEATURE_UNSUPPORTED;
	}
	ret = head->cfg.npu_sec_enable;
	if (sre_unmap((uintptr_t)head, sizeof(npu_secmem_head)) != 0)
		NPU_DRV_ERR("sre_unmap head fail");
	return ret;
}

static int npu_init_dev_ctx_shm(npu_dev_ctx_t *dev_ctx)
{
	u32 sq_len = (NPU_MAX_HWTS_SQ_DEPTH * NPU_HWTS_SQ_SLOT_SIZE) * NPU_MAX_SINK_STREAM_ID;
	u32 cq_len = NPU_MAX_HWTS_CQ_DEPTH * NPU_HWTS_CQ_SLOT_SIZE;
	u32 smmu_queue_len = NPU_S_SMMU_QUEUE_SIZE;
	u32 length;
	npu_secmem_head *head = NULL;
	u32 head_length = sizeof(npu_secmem_head);
	int ret;
	uintptr_t phy_base = NPU_SEC_RESERVED_DDR_BASE_ADDR;
	uintptr_t virt_base = 0;

	COND_RETURN_ERROR((sq_len + cq_len) > NPU_S_HWTS_SQCQ_SIZE, -EINVAL, "sq cq resev mem size(0x%x) exceed 0x%x",
		sq_len + cq_len, NPU_S_HWTS_SQCQ_SIZE);

	length = NPU_S_HWTS_SQCQ_SIZE + smmu_queue_len;

	if (sre_mmap((paddr_t)phy_base, head_length, (uint32_t *)(&head), secure, non_cache)) {
		NPU_DRV_WARN("sre_mmap sec shared memory failed");
		return -EINVAL;
	}

	COND_RETURN_ERROR(head == NULL, -ENODEV, "sec_config is null after sre_mmap");

	dev_ctx->shm_mem[NPU_SHM_CONFIG].phy_base = phy_base;
	dev_ctx->shm_mem[NPU_SHM_CONFIG].virt_base = (uintptr_t)head;
	dev_ctx->shm_mem[NPU_SHM_CONFIG].size = (size_t)head_length;

	if (head->cfg.npu_sec_enable != NPU_SEC_FEATURE_SUPPORTED) {
		NPU_DRV_WARN("this platform unsupport secure workmode");
		ret = -ENODEV;
		goto free_head;
	}

	phy_base += head_length;
	ret = sre_mmap((paddr_t)phy_base, length, (uint32_t *)&(virt_base), secure, non_cache);
	if ((ret != 0) || (virt_base == (uintptr_t)NULL)) {
		NPU_DRV_ERR("sre_mmap fail or virt_base is null, fatal");
		ret = -EFAULT;
		goto free_head;
	}

	dev_ctx->shm_mem[NPU_SHM_SQ].phy_base = phy_base;
	dev_ctx->shm_mem[NPU_SHM_SQ].virt_base = virt_base;
	dev_ctx->shm_mem[NPU_SHM_SQ].size = (size_t)sq_len;

	dev_ctx->shm_mem[NPU_SHM_CQ].phy_base = phy_base + sq_len;
	dev_ctx->shm_mem[NPU_SHM_CQ].virt_base = virt_base + sq_len;
	dev_ctx->shm_mem[NPU_SHM_CQ].size = (size_t)cq_len;

	dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].phy_base = phy_base + NPU_S_HWTS_SQCQ_SIZE;
	dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].virt_base = virt_base + NPU_S_HWTS_SQCQ_SIZE;
	dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].size = (size_t)smmu_queue_len;

	ret = npu_init_dev_chip_cfg_shm(dev_ctx);
	if (ret != 0) {
		NPU_DRV_ERR("init chip cfg shm fail ret %d ", ret);
		ret = -EFAULT;
		goto free_virt_base;
	}
	return 0;

free_virt_base:
	if (sre_unmap(virt_base, length) != 0)
		NPU_DRV_ERR("sre_unmap virt_base fail");
free_head:
	if (sre_unmap((uintptr_t)head, head_length) != 0)
		NPU_DRV_ERR("sre_unmap head fail");
	return ret;
}

int npu_init_dev_ctx(u8 dev_id)
{
	int ret = 0;
	npu_dev_ctx_t *dev_ctx = NULL;
	if (dev_id < NPU_DEV_NUM) {
		dev_ctx = &(g_dev_ctxs[dev_id]);

		dev_ctx->dev_id = dev_id;
		dev_ctx->power_stage = DEVDRV_PM_DOWN;
		INIT_LIST_HEAD(&(dev_ctx->proc_ctx_list));

		ret = npu_init_dev_ctx_shm(dev_ctx);
		if (ret) {
			NPU_DRV_ERR("npu_init_dev_ctx_shm fail, can not support sec mode");
			return ret;
		}

		npu_init_task_info_mngr(&(g_dev_ctxs[dev_id].task_mngr));
		npu_init_stream_info_mngr(&(g_dev_ctxs[dev_id].stream_mngr));
		npu_init_model_info_mngr(&(g_dev_ctxs[dev_id].model_mngr));
		npu_init_event_info_mngr(&(g_dev_ctxs[dev_id].event_mngr));
		npu_init_hwts_sq_mngr(&(g_dev_ctxs[dev_id].sq_mngr));

		return 0;
	}

	return -ENODEV;
}

void npu_deinit_dev_ctx(u8 dev_id)
{
	npu_dev_ctx_t *dev_ctx = NULL;
	npu_proc_ctx_t *proc_ctx = NULL;
	struct list_head *pos = NULL;
	struct list_head *n = NULL;
	if (dev_id < NPU_DEV_NUM) {
		dev_ctx = &(g_dev_ctxs[dev_id]);
		list_for_each_safe(pos, n, &(dev_ctx->proc_ctx_list)) {
			proc_ctx = list_entry(pos, npu_proc_ctx_t, list_node);
			list_del(pos);

			npu_destroy_proc_ctx(proc_ctx);
		}
	}

	return;
}

npu_dev_ctx_t *npu_get_dev_ctx(u8 dev_id)
{
	if (dev_id < NPU_DEV_NUM)
		return &(g_dev_ctxs[dev_id]);

	return NULL;
}

int npu_get_res_mem_of_smmu(uintptr_t *phy_addr_ptr, uintptr_t *virt_addr_ptr, u32 *len_ptr)
{
	if (phy_addr_ptr == NULL || len_ptr == NULL || virt_addr_ptr == NULL) {
		NPU_DRV_ERR("invalid param, phy_addr_ptr = %p ,len_ptr = %p", phy_addr_ptr, len_ptr);
		return -1;
	}

	npu_dev_ctx_t *dev_ctx = &(g_dev_ctxs[0]);
	*phy_addr_ptr = dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].phy_base;
	*virt_addr_ptr = dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].virt_base;
	*len_ptr = dev_ctx->shm_mem[NPU_SHM_SMMU_QUEUE].size;

	NPU_DRV_DEBUG("phy_addr=%p, virt_addr=%p", (void *)(*phy_addr_ptr), (void *)(*virt_addr_ptr));

	return 0;
}

int npu_get_res_mem_of_chip_cfg(uintptr_t *virt_addr_ptr)
{
	if (virt_addr_ptr == NULL) {
		NPU_DRV_ERR("invalid virt_addr_ptr");
		return -1;
	}

	npu_dev_ctx_t *dev_ctx = &(g_dev_ctxs[0]);
	*virt_addr_ptr = dev_ctx->shm_mem[NPU_CHIP_CFG].virt_base;
	return 0;
}
