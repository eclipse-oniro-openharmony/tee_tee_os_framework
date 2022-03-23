/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu map and unmap
 */

#include "npu_shm.h"

#include <errno.h>
#include <sre_syscall.h>
#include <sys/mman.h>
#include <plat_cfg.h>
#include <mem_ops_ext.h> // __task_map_from_ns_page && __virt_to_phys
#include <mem_drv_map.h>
#include <drv_task_map.h>
#include <drv_mem.h> // sre_mmap
#include <drv_pal.h> // task_caller
#include "tee_mem_mgmt_api.h"
#include "tee_defines.h"
#include "mem_page_ops.h"
#include "procmgr_ext.h"
#include "secmem.h"
#include "npu_custom_info_share.h"

#include "drv_log.h"
#include "npu_platform.h"
#include "npu_doorbell.h"
#include "npu_mailbox.h"
#include "npu_resmem.h"
#include "npu_cma.h"
#include "svm.h"
#include "npu_reg.h"
#include "npu_platform_register.h"

struct tee_svm_para_list g_hisi_svm;

static u64 g_info_mem_page_align_size = 0;

struct npu_mem_desc g_sq_desc;

static struct npu_mem_info g_shm_desc[NPU_DEV_NUM][DEVDRV_MAX_MEM];

static npu_shm_entry_t s_shm_entries[NPU_DEV_NUM][NPU_SHM_TYPES];

static int npu_hisi_svm_init(u8 dev_id)
{
	struct npu_dev_ctx *dev_ctx;
	dev_ctx = get_dev_ctx_by_id(dev_id);
	if (dev_ctx == NULL) {
		NPU_ERR("npu dev %d `s dev_ctx is null", dev_id);
		return -1;
	}

	dev_ctx->hisi_svm = &g_hisi_svm;
	return 0;
}

struct npu_ts_sq_info *npu_calc_sq_info(u8 devid, u32 index)
{
	struct npu_ts_sq_info *sq = NULL;
	u64 addr = g_shm_desc[devid][DEVDRV_INFO_MEM].virt_addr;
	sq = (struct npu_ts_sq_info *)(uintptr_t) (addr +
		(long)(unsigned)sizeof(struct npu_ts_sq_info) * (index));
	return sq;
}

struct npu_ts_cq_info *npu_calc_cq_info(u8 devid, u32 index)
{
	struct npu_ts_cq_info *cq = NULL;
	u64 addr = g_shm_desc[devid][DEVDRV_INFO_MEM].virt_addr;
	cq = (struct npu_ts_cq_info *)(uintptr_t) (addr + DEVDRV_SQ_INFO_OCCUPY_SIZE +
		(long)(unsigned)sizeof(struct npu_ts_cq_info) * (index));
	return cq;
}

struct npu_stream_info *npu_calc_stream_info(u8 devid, u32 index)
{
	struct npu_stream_info *stream_info = NULL;

	u64 addr = g_shm_desc[devid][DEVDRV_INFO_MEM].virt_addr;
	stream_info = (struct npu_stream_info *)(uintptr_t) (addr +
		DEVDRV_SQ_INFO_OCCUPY_SIZE + DEVDRV_CQ_INFO_OCCUPY_SIZE +
		(long)(unsigned)sizeof(struct npu_stream_info) * (index));
	return stream_info;
}

u32 *npu_get_ts_work_status(u8 devid, u32 index)
{
	u32 *ts_status = NULL;

	u64 addr = g_shm_desc[devid][DEVDRV_INFO_MEM].virt_addr;
	ts_status = (u32 *)(uintptr_t) (addr + DEVDRV_SQ_INFO_OCCUPY_SIZE + DEVDRV_CQ_INFO_OCCUPY_SIZE +
		DEVDRV_STREAM_INFO_OCCUPY_SIZE + (long)(unsigned)sizeof(u32) * (index));
	return ts_status;
}

int npu_shm_init(u8 dev_id)
{
	npu_res_mem_entry_t res_mem_entry;
	struct npu_platform_info *plat_info = NULL;
	char *tmp = NULL;
	u32 info_mem_page_num;
	u64 doorbell_base;
	u32 doorbell_size;
	u32 *ts_status = NULL;
	int ret;

	COND_RETURN_ERROR(dev_id >= NPU_DEV_NUM, -1, "illegal npu dev id = %d", dev_id);

	plat_info = npu_plat_get_info();
	COND_RETURN_ERROR(plat_info == NULL, -1, "npu_plat_get_info failed");

	// doorbell
	doorbell_base = DEVDRV_PLAT_GET_REG_DESC(plat_info, DEVDRV_REG_TS_DOORBELL).base;
	doorbell_size = DEVDRV_PLAT_GET_REG_DESC(plat_info, DEVDRV_REG_TS_DOORBELL).len;
	g_shm_desc[dev_id][DEVDRV_DOORBELL_MEM].phy_addr = doorbell_base;
	g_shm_desc[dev_id][DEVDRV_DOORBELL_MEM].size = doorbell_size;
	s_shm_entries[dev_id][NPU_SHM_DB].phy_addr = doorbell_base;
	s_shm_entries[dev_id][NPU_SHM_DB].size = doorbell_size;

	// mmap info mem drv vaddr (A+B-1)/B
	info_mem_page_num = (DEVDRV_MAX_INFO_SIZE + PAGE_SIZE - 1) / PAGE_SIZE ;
	g_info_mem_page_align_size = info_mem_page_num * PAGE_SIZE;
	tmp = (char *)mmap(NULL, g_info_mem_page_align_size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS, -1, 0);
	COND_RETURN_ERROR(tmp == MAP_FAILED, -ENOMEM, "mmap share mem descriptor memory failed !");

	g_shm_desc[dev_id][DEVDRV_INFO_MEM].phy_addr = __virt_to_phys((uintptr_t)tmp);
	g_shm_desc[dev_id][DEVDRV_INFO_MEM].virt_addr =(vir_addr_t) (uintptr_t) tmp;
	g_shm_desc[dev_id][DEVDRV_INFO_MEM].size = g_info_mem_page_align_size;
	s_shm_entries[dev_id][NPU_SHM_INFO].phy_addr =__virt_to_phys((uintptr_t)tmp);
	s_shm_entries[dev_id][NPU_SHM_INFO].drv_vaddr = (uint32_t)(uintptr_t)tmp;
	s_shm_entries[dev_id][NPU_SHM_INFO].size = g_info_mem_page_align_size;
	ts_status = npu_get_ts_work_status(dev_id, 0);
	*ts_status = DEVDRV_TS_DOWN;
	NPU_DEBUG("alloc share mem descriptor memory size = 0x%x g_info_mem_page_align_size = 0x%x "
	          "drv_vaddr = %p!\n", DEVDRV_MAX_INFO_SIZE, g_info_mem_page_align_size, tmp);

	//sq
	ret = npu_get_res_mem_area_by_name(CALC_SQ_AREA_NAME, &res_mem_entry);
	COND_RETURN_ERROR(ret, -ENOMEM, "get %s mem info failed", CALC_SQ_AREA_NAME);

	g_sq_desc.base = res_mem_entry.area_base;
	g_sq_desc.len = res_mem_entry.area_len;


	g_shm_desc[dev_id][DEVDRV_SQ_MEM].phy_addr = res_mem_entry.area_base;
	g_shm_desc[dev_id][DEVDRV_SQ_MEM].size = res_mem_entry.area_len;

	s_shm_entries[dev_id][NPU_SHM_SQ].phy_addr = res_mem_entry.area_base;
	s_shm_entries[dev_id][NPU_SHM_SQ].size = res_mem_entry.area_len;


	// cq
	ret = npu_get_res_mem_area_by_name(CALC_CQ_AREA_NAME, &res_mem_entry);
	COND_RETURN_ERROR(ret, -ENOMEM, "get %s mem info failed", CALC_CQ_AREA_NAME);
	s_shm_entries[dev_id][NPU_SHM_CQ].phy_addr = res_mem_entry.area_base;
	s_shm_entries[dev_id][NPU_SHM_CQ].size = res_mem_entry.area_len;

	// persistent task buff
	ret = npu_get_res_mem_area_by_name(PERSISTENT_TASK_BUFF_AREA_NAME,&res_mem_entry);
	COND_RETURN_ERROR(ret, -ENOMEM, "get %s mem info failed", PERSISTENT_TASK_BUFF_AREA_NAME);
	s_shm_entries[dev_id][NPU_SHM_PERSISTENT_TASK_BUFF].phy_addr = res_mem_entry.area_base;
	s_shm_entries[dev_id][NPU_SHM_PERSISTENT_TASK_BUFF].size = res_mem_entry.area_len;

	// tscpu log reserve memory
	ret = npu_get_res_mem_area_by_name(TSCPU_LOG_AREA_NAME,&res_mem_entry);
	COND_RETURN_ERROR(ret, -ENOMEM, "get %s mem info failed", TSCPU_LOG_AREA_NAME);
	s_shm_entries[dev_id][NPU_SHM_TSCPU_LOG].phy_addr = res_mem_entry.area_base;
	s_shm_entries[dev_id][NPU_SHM_TSCPU_LOG].size = res_mem_entry.area_len;

	s_shm_entries[dev_id][NPU_SHM_POWER_STATUS].phy_addr = npu_plat_get_vaddr(DEVDRV_REG_POWER_STATUS);
	s_shm_entries[dev_id][NPU_SHM_POWER_STATUS].size = SHM_POWER_STATUS_SIZE;

	NPU_DEBUG("sq mem: phy_addr = 0x%llx, size = 0x%lx\n", g_shm_desc[dev_id][DEVDRV_SQ_MEM].phy_addr,
		g_shm_desc[dev_id][DEVDRV_SQ_MEM].size);

	NPU_DEBUG("info mem: virt_addr = 0x%llx, page_num = %u, size = 0x%lx\n phy_addr = 0x%llx, ",
		g_shm_desc[dev_id][DEVDRV_INFO_MEM].virt_addr,
		info_mem_page_num, g_shm_desc[dev_id][DEVDRV_INFO_MEM].size,
		g_shm_desc[dev_id][DEVDRV_INFO_MEM].phy_addr);

	NPU_DEBUG("doorbell mem: phy_addr = 0x%llx, size = 0x%lx\n", g_shm_desc[dev_id][DEVDRV_DOORBELL_MEM].phy_addr,
		g_shm_desc[dev_id][DEVDRV_DOORBELL_MEM].size);

	(void)npu_hisi_svm_init(dev_id);
	// init continuous memory resource
	ret = npu_cma_init(dev_id);

	return ret;
}

void npu_clear_mem_data(void *addr, u32 size)
{
	u32 i;
	u32 *tmp_addr = (u32 *) addr;
	for (i = 0; i < size / sizeof(u32); i++) {
		*tmp_addr = 0;
		tmp_addr++;
	}
}

uint32_t npu_sec_mem_map(paddr_t paddr, uint32_t size, uint32_t *vaddr, uint32_t secure_mode, uint32_t cache_mode)
{
	int ret;
	int drv_pid;
	uint32_t ta_pid = 0;
	uint32_t drv_vaddr = 0;
	int32_t prot;

	COND_RETURN_ERROR(vaddr == NULL, 1, "vaddr is NULL");

	drv_pid = hm_getpid();
	COND_RETURN_ERROR(drv_pid < 0, 1, "get drv pid failed");

	ret = SRE_TaskSelf(&ta_pid);
	COND_RETURN_ERROR(ret < 0, 1, "get ta pid failed");

	if (cache_mode == cache) {
		ret = __task_map_from_ns_page(ta_pid, paddr, size, vaddr, secure_mode);
		COND_RETURN_ERROR(ret, 1, "ta_pid = %d task map error, size = 0x%x", ta_pid, size);
		return 0;
	} else {
		/* doorbell sram do not sre_mmap */
		if (paddr == TS_DOORBELL_BASE_ADDR || paddr == TS_SRAM_BASE_ADDR || paddr == DRV_NPU_POWER_STATUS_REG) {
			NPU_DEBUG("paddr = %llx", paddr);
			bool drv_map_result = true;
			ret = drv_map_from_task(drv_pid, paddr, size, ta_pid, vaddr, &prot);
			if (ret) {
				NPU_ERR("map size = 0x%x failed", size);
				drv_map_result = false;
			}

			if (!drv_map_result)
				return 1;
		} else {
			NPU_DEBUG("paddr = %llx", paddr);
			ret = sre_mmap(paddr, size, &drv_vaddr, (secure_mode_type)secure_mode, (cache_mode_type)cache_mode);
			COND_RETURN_ERROR(ret, 1, "sre_map failed err = %d", ret);
			bool drv_map_result = true;
			ret = drv_map_from_task(drv_pid, drv_vaddr, size, ta_pid, vaddr, &prot);
			if (ret) {
				NPU_ERR("drv_map_from_task fail, size = 0x%x, %d", size, ret);
				drv_map_result = false;
			}
			ret = sre_unmap(drv_vaddr, size);
			COND_RETURN_ERROR(ret, 1, "sre_unmap failed");

			if (!drv_map_result)
				return 1;
		}
	}
	return 0;
}

uint32_t npu_sec_mem_unmap(uint32_t vaddr, uint32_t size)
{
	uint32_t ta_pid;
	int ret;

	NPU_DEBUG("ta vaddr = %p ,size = 0x%x", (void *)(uintptr_t)vaddr, size);

	if ((void *)(uintptr_t)vaddr == NULL) {
		NPU_ERR("vaddr is NULL");
		return 1;
	}

	ret = SRE_TaskSelf(&ta_pid);
	if (ret < 0) {
		NPU_ERR("get ta pid failed");
		return 1;
	}

	ret = __task_unmap_from_ns_page(ta_pid, vaddr, size);
	if (ret) {
		NPU_ERR("unmap from task failed");
		return 1;
	}

	// flush NPU SMMU TLB
	npu_flush_smmu_tlb(0);

	return 0;
}

int npu_map_internal_reg(struct npu_dev_ctx *dev_ctx)
{
	// non_cache mapping
	// map npu doorbell cfg 512k space
	npu_set_doorbell_base_vaddr(TS_DOORBELL_BASE_ADDR);
	npu_set_mailbox_base_vaddr(dev_ctx, TS_SRAM_BASE_ADDR);

	return 0;
}

void npu_unmap_internal_reg(struct npu_dev_ctx *dev_ctx)
{
	u64 drv_db_vaddr = 0;
	u64 drv_sram_vaddr = 0;
	int ret;

	ret = npu_get_doorbell_base_vaddr(&drv_db_vaddr);
	if (ret) {
		NPU_ERR("get_doorbell_base_vaddr failed");
		goto unmap_sram;
	}

	// invalid db vaddr
	npu_set_doorbell_base_vaddr(0);

unmap_sram:
	ret = npu_get_mailbox_base_vaddr(dev_ctx, &drv_sram_vaddr);
	if (ret) {
		NPU_ERR("get mailbox base addr failed");
		return;
	}

	// invalid mailbox sram vaddr
	npu_set_mailbox_base_vaddr(dev_ctx, 0);
}

static int __npu_map_l2_buff(ta_vm_area_t* vma, uint32_t secure_mode, uint32_t cache_mode)
{
	unsigned long size;
	struct npu_mem_desc *l2_desc = NULL;
	unsigned long l2_base;
	unsigned long l2_len;
	uint32_t tmp_ta_vaddr = 0;
	int ret;

	if (vma == NULL) {
		NPU_ERR("invalid para vma,vma is null");
		return -EFAULT;
	}

	if (vma->vm_end <= vma->vm_start) {
		NPU_ERR("invalid para vma,vma_end = 0x%x vma_start = 0x%x", vma->vm_end, vma->vm_start);
		return -EFAULT;
	}
	size = vma->vm_end - vma->vm_start;

	l2_desc = npu_plat_get_reg_desc(DEVDRV_REG_L2BUF_BASE);
	if (l2_desc == NULL) {
		NPU_ERR("npu_plat_get_reg_desc failed");
		return -EFAULT;
	}

	l2_base = l2_desc->base;
	l2_len = l2_desc->len;	// becasue of dts will minus 1

	NPU_DEBUG("l2_base %lx l2_len %lx l2_mask %lx", l2_base, l2_len, l2_mask);

	if (size > l2_len) {
		NPU_ERR("invalid l2 mem size = %lu", size);
		return -ENOMEM;
	}

	// map vaddr for HIAI TA use
	ret = npu_sec_mem_map(l2_base, size, &tmp_ta_vaddr, secure_mode, cache_mode);
	if (ret) {
		NPU_ERR("map L2 buff phy addr failed, size = 0x%x"
			" secure_mode = %d mode = %d", size, secure_mode, cache_mode);
		return -EFAULT;
	}
	vma->ta_vaddr_after_drv_map = tmp_ta_vaddr;
	NPU_DEBUG("l2_ta_vaddr_after_drv_map 0x%x", vma->ta_vaddr_after_drv_map);

	return 0;
}

int npu_map_l2_buff(ta_vm_area_t* vma)
{
	// cache_mode_device
	return __npu_map_l2_buff(vma, secure, cache_mode_device);
}

// map dev_id npu`s info 、sq and cq to hiai ta space
static int __npu_share_mem_mmap(u8 dev_id, uint32_t secure_mode)
{
	pid_t drv_pid;
	uint32_t ta_pid = 0;
	int shm_type;
	int32_t prot = 0;
	int ret;
	int i;

	COND_RETURN_ERROR(dev_id >= NPU_DEV_NUM, -1, "illegal npu dev id %d", dev_id);

	drv_pid  = hm_getpid();
	COND_RETURN_ERROR(drv_pid < 0, -1, "get drv pid failed");

	ret = SRE_TaskSelf(&ta_pid);
	COND_RETURN_ERROR(ret < 0, -1, "get ta pid failed");

	/*
		|___SQ()___|____INFO()_____|__DOORBELL()___|___CQ()
	*/
	// map npu shm except info mem
	for (shm_type = 0; shm_type < NPU_SHM_INFO; shm_type++) {
		ret = npu_sec_mem_map(s_shm_entries[dev_id][shm_type].phy_addr,
			s_shm_entries[dev_id][shm_type].size,
			&s_shm_entries[dev_id][shm_type].ta_vaddr,
			secure_mode, non_cache);
		if (ret) {
			NPU_ERR("npu shm map dev_id %d shm_type %d err = %d failed", dev_id, shm_type, ret);
			goto SHM_MAP_FAILED;
		}
	}

	// map info mem independly
	ret = drv_map_from_task (drv_pid, s_shm_entries[dev_id][NPU_SHM_INFO].drv_vaddr,
	                         s_shm_entries[dev_id][NPU_SHM_INFO].size, ta_pid,
	                         &s_shm_entries[dev_id][NPU_SHM_INFO].ta_vaddr, &prot);
	if (ret) {
		NPU_ERR("map size = 0x%x failed", s_shm_entries[dev_id][NPU_SHM_INFO].size);
		goto SHM_MAP_FAILED;
	}

	NPU_INFO("npu shm map dev_id %d success", dev_id);
	return 0;
SHM_MAP_FAILED:
	// unmap npu shm
	for (i = 0; i < shm_type; i++) {
		(void)npu_sec_mem_unmap(s_shm_entries[dev_id][i].ta_vaddr, s_shm_entries[dev_id][i].size);
	}
	return ret;
}

int npu_reg_map(u8 dev_id, uintptr_t* ip_vaddr, enum npu_shm_type type)
{
	int ret;

	COND_RETURN_ERROR(dev_id >= NPU_DEV_NUM, -1, "illegal npu dev id %d", dev_id);
	COND_RETURN_ERROR(type > NPU_SHM_TYPES, -1, "illegal type %d", type);
	COND_RETURN_ERROR(ip_vaddr == NULL, -1, "npu ip_vaddr is null");
	COND_RETURN_ERROR(s_shm_entries[dev_id][type].phy_addr == 0, -1, "npu not support type %d", type);

	ret = npu_sec_mem_map(s_shm_entries[dev_id][type].phy_addr,
		s_shm_entries[dev_id][type].size,
		&s_shm_entries[dev_id][type].ta_vaddr, secure, cache_mode_device);
	COND_RETURN_ERROR(ret != 0, -1, "npu shm map dev_id %d, type = %d, ret = %d failed", dev_id, type, ret);

	*ip_vaddr = s_shm_entries[dev_id][type].ta_vaddr;
	NPU_DEBUG("npu ip_vaddr is 0x%lx \n", *ip_vaddr);

	return ret;
}

int npu_reg_unmap(u8 dev_id, enum npu_shm_type type)
{
	int ret;
	COND_RETURN_ERROR(type > NPU_SHM_TYPES, -1, "illegal type %d", type);
	COND_RETURN_ERROR(dev_id >= NPU_DEV_NUM, -1, "illegal npu dev id %d", dev_id);

	if (s_shm_entries[dev_id][type].ta_vaddr == 0) {
		// not support, return normal
		return 0;
	}

	ret = npu_sec_mem_unmap(s_shm_entries[dev_id][type].ta_vaddr,
	                        s_shm_entries[dev_id][type].size);
	if (ret) {
		NPU_ERR("npu shm unmap dev_id %d, type = %d, ret = %d failed", dev_id, type, ret);
	}

	s_shm_entries[dev_id][type].ta_vaddr = 0;
	return ret;
}

int npu_doorbell_mmap(u8 dev_id, uintptr_t* db_vaddr)
{
	int ret;

	ret = npu_reg_map(dev_id, db_vaddr, NPU_SHM_DB);
	COND_RETURN_ERROR(ret != 0, -1, "npu doorbell reg map dev_id %d doorbell ret = %d failed", dev_id, ret);

	return ret;
}

int npu_doorbell_unmap(u8 dev_id)
{
	int ret;

	ret = npu_reg_unmap(dev_id, NPU_SHM_DB);
	COND_RETURN_ERROR(ret, ret, "npu doorbell reg unmap dev_id %d doorbell ret = %d failed", dev_id, ret);

	return ret;
}

int npu_power_status_mmap(u8 dev_id, uintptr_t* power_status_vaddr)
{
	int ret;

	ret = npu_reg_map(dev_id, power_status_vaddr, NPU_SHM_POWER_STATUS);
	COND_RETURN_ERROR(ret != 0, -1, "npu power status reg map dev_id %d , ret = %d failed", dev_id, ret);

	NPU_DEBUG("npu db_vaddr is 0x%lx \n", *power_status_vaddr);

	return ret;
}

int npu_power_status_unmap(u8 dev_id)
{
	int ret;

	ret = npu_reg_unmap(dev_id, NPU_SHM_POWER_STATUS);
	COND_RETURN_ERROR(ret, ret, "npu power status reg unmap dev_id %d, ret = %d failed", dev_id, ret);

	return ret;
}

int npu_shm_mmap(u8 dev_id, npu_shm_vaddr_t* shm_vaddrs)
{
	int ret;

	if (shm_vaddrs == NULL) {
		NPU_ERR("npu shm_vaddrs is null");
		return -1;
	}

	ret = __npu_share_mem_mmap(dev_id, secure);
	shm_vaddrs->sq_vaddr = s_shm_entries[dev_id][NPU_SHM_SQ].ta_vaddr;
	shm_vaddrs->cq_vaddr = s_shm_entries[dev_id][NPU_SHM_CQ].ta_vaddr;
	shm_vaddrs->info_vaddr = s_shm_entries[dev_id][NPU_SHM_INFO].ta_vaddr;
	shm_vaddrs->ts_log_vaddr = s_shm_entries[dev_id][NPU_SHM_TSCPU_LOG].ta_vaddr;
	shm_vaddrs->pesistent_vaddr = s_shm_entries[dev_id][NPU_SHM_PERSISTENT_TASK_BUFF].ta_vaddr;

	return ret;
}

int npu_shm_unmap(u8 dev_id)
{
	int ret = -1;
	int shm_type = 0;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d", dev_id);
		return -1;
	}
	// map npu shm include info mem at the same time
	for (shm_type = 0; shm_type < NPU_SHM_TYPES; shm_type++) {
		if ((shm_type == NPU_SHM_DB) && (s_shm_entries[dev_id][shm_type].ta_vaddr == 0)) {
			continue;
		}
		ret = npu_sec_mem_unmap(s_shm_entries[dev_id][shm_type].ta_vaddr,
		                        s_shm_entries[dev_id][shm_type].size);
		if (ret) {
			NPU_ERR("npu shm unmap dev_id %d shm_type %d ret = %d failed", dev_id, shm_type, ret);
		}
	}

	return 0;
}

void npu_shm_destroy(u8 dev_id)
{
	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d", dev_id);
		return;
	}

	if (g_info_mem_page_align_size == 0) {
		NPU_ERR("illegal g_info_mem_page_align_size");
		return;
	}

	munmap((uint32_t *)(uintptr_t)g_shm_desc[dev_id][DEVDRV_INFO_MEM].virt_addr, g_info_mem_page_align_size);
}

int npu_dev_map(u8 dev_id, ta_vm_area_t* vma)
{
	unsigned int vm_pgoff;
	u32 map_type;
	int ret;

	if (dev_id >= NPU_DEV_NUM) {
		NPU_ERR("illegal npu dev id %d", dev_id);
		return -1;
	}

	vm_pgoff = vma->vm_pgoff;
	map_type = MAP_GET_TYPE(vm_pgoff);

	NPU_DEBUG("map_type = %d memory mmap start", map_type);
	switch (map_type) {
		case MAP_L2_BUFF:
			ret = npu_map_l2_buff(vma);
			break;
		default:
			ret = -1;
			break;
	}

	if (ret != 0) {
		NPU_ERR("map_type = %d ret = %d memory mmap failed", map_type, ret);
	}
	return ret;
}

int npu_dev_unmap(uint32_t vaddr, uint32_t size)
{
	return npu_sec_mem_unmap(vaddr, size);
}

int npu_flush_smmu_tlb(u8 dev_id)
{
	struct npu_dev_ctx* dev_ctx = get_dev_ctx_by_id(dev_id);
	if ((dev_ctx) == NULL) {
		NPU_ERR("dev_id: %d  is null ", dev_id);
		return -EFAULT;
	}

	MUTEX_LOCK(pm);
	if (atomic_read(&dev_ctx->poweron_success) == 1 || (npu_pm_query_ree_status() != NPU_POWER_ON)) {
		MUTEX_UNLOCK(pm);
		NPU_WARN("npu dev %d is powerdown !" "can`t flush smmu tlb \n", dev_ctx->devid);
		return -EFAULT;
	}

	hisi_smmu_group_flush_tlb();
	MUTEX_UNLOCK(pm);
	return 0;
}

