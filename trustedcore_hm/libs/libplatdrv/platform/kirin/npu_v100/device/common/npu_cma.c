/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu creat and free
 */

#include "npu_cma.h"
#include <errno.h>

#include <sre_syscall.h>
#include <sys/mman.h>
#include <list.h>
#include <mem_mode.h> // non_cache
#include "drv_log.h"
#include "tee_mem_mgmt_api.h"
#include "mem_page_ops.h"
#include "npu_shm_internal.h"
#include "npu_platform.h"
#include "npu_common.h"
#include "npu_resmem.h"

npu_rsv_cma_desc_t s_cma_desc;

// MEM_TOTAL_SIZE (0x80000)
// (0x800000/(64/4)) = 0.5M = 4 streams * 256 cmd slot * 512 byte(per aicore task)
int npu_cma_init(u8 dev_id)
{
	UNUSED(dev_id);
	npu_res_mem_entry_t res_mem_entry = {0};
	int pg_idx = 0;
	int ret;

	// l2ctrl cma reserve memory
	ret = npu_get_res_mem_area_by_name(L2CTRL_CMA_AREA_NAME, &res_mem_entry);
	if (ret) {
		NPU_ERR("get %s mem info failed", L2CTRL_CMA_AREA_NAME);
		return -ENOMEM;
	}

	s_cma_desc.base_addr = res_mem_entry.area_base;
	s_cma_desc.total_len = res_mem_entry.area_len;
	for (pg_idx = 0; pg_idx < NPU_CMA_PAGE_NUM ; pg_idx++) {
		s_cma_desc.pages[pg_idx].dma_handle =
			s_cma_desc.base_addr + pg_idx * NPU_CMA_PAGE_SIZE;
		s_cma_desc.pages[pg_idx].ta_vaddr = 0;
		s_cma_desc.pages[pg_idx].state = NPU_CMA_PAGE_FREE;
	}

	return 0;
}

// for implementation function like dma_alloc_coherent n linux world
static int __npu_cma_phyaddr_alloc(unsigned int size, u64 *dma_handle, u32 *pg_str_idx)
{
	u32 pg_idx;

	for (pg_idx = 0; pg_idx < NPU_CMA_PAGE_NUM; pg_idx++) {
		if (s_cma_desc.pages[pg_idx].state != NPU_CMA_PAGE_FREE) {
			continue;
		}

		// finded free cma page
		*dma_handle = s_cma_desc.pages[pg_idx].dma_handle;
		s_cma_desc.pages[pg_idx].state = NPU_CMA_PAGE_OCCUPIED;

		// record it for store ta_vaddr to cma_pages[pg_idx] quickly
		*pg_str_idx = pg_idx;

		NPU_DEBUG("cma_index = %d dma_handle = %p", pg_idx, (void *)*dma_handle);

		return 0;
	}

	NPU_ERR("npu cma request size = 0x%x failed,no enough pages", size);
	return -ENOMEM;
}

static int __npu_cma_phyaddr_free(u32 size, u64 dma_handle)
{
	u32 pg_idx;
	if (size != NPU_CMA_PAGE_SIZE) {
		NPU_ERR("cma phyaddr free size 0x%x is not illegal", size);
		return -EINVAL;
	}

	pg_idx = (dma_handle - s_cma_desc.base_addr) / NPU_CMA_PAGE_SIZE;
	if (pg_idx >= NPU_CMA_PAGE_NUM || dma_handle < s_cma_desc.base_addr) {
		NPU_ERR("invalid dma_handle = %p ,pg_idx = %d", (void *)(uintptr_t)dma_handle, pg_idx);
		return -EINVAL;
	}

	if (s_cma_desc.pages[pg_idx].state == NPU_CMA_PAGE_FREE) {
		NPU_ERR("illagal free dma_handle = %p ,pg_idx = %d failed, "
			"(maybe freed before),", (void *)(uintptr_t)dma_handle, pg_idx);
		return -EINVAL;
	}

	s_cma_desc.pages[pg_idx].state = NPU_CMA_PAGE_FREE;
	NPU_DEBUG("free dma_handle = %p ,pg_idx = %d success", (void *)dma_handle, pg_idx);
	return 0;
}

// for implementation function like dma_alloc_coherent n linux world but return hiai ta vaddr directly
int npu_cma_alloc(unsigned int size, u32 *ta_vaddr)
{
	u32 tmp_ta_vaddr = 0;
	u64 dma_handle = 0;
	u32 pg_idx = 0;
	int ret;

	if (ta_vaddr == NULL) {
		NPU_ERR("illegal param, dma_handle is null");
		return -ENOMEM;
	}

	if (size != NPU_CMA_PAGE_SIZE) {
		NPU_ERR("cma request size 0x%x is not illegal", size);
		return -ENOMEM;
	}

	// alloc phy addr from reserve cma block of npu
	ret = __npu_cma_phyaddr_alloc(size, &dma_handle, &pg_idx);
	if (ret) {
		NPU_ERR("cma request phyaddr size 0x%x failed", size);
		return -ENOMEM;
	}

	// map vaddr for hiai ta
	ret = npu_sec_mem_map(dma_handle, size, &tmp_ta_vaddr, secure, non_cache);
	if (ret) {
		__npu_cma_phyaddr_free(size, dma_handle);
		NPU_ERR("map cma phyaddr=%p size 0x%x failed", (void *)(uintptr_t)dma_handle, size);
		return -ENOMEM;
	}

	// record ta_vaddr for free cma use
	s_cma_desc.pages[pg_idx].ta_vaddr = tmp_ta_vaddr;
	*ta_vaddr = tmp_ta_vaddr;

	NPU_DEBUG("npu cma request size=0x%x ta_vaddr = %p success", size, (void *)*ta_vaddr);
	return 0;
}

int npu_cma_free(void *vaddr)
{
	u64 dma_handle;
	u32 pg_idx;
	u32 hiai_ta_vaddr = (u32)(uintptr_t)vaddr;
	int ret = 0;

	for (pg_idx = 0; pg_idx < NPU_CMA_PAGE_NUM; pg_idx++) {
		if (s_cma_desc.pages[pg_idx].ta_vaddr != hiai_ta_vaddr) {
			continue;
		}

		// find correponding vaddr and free dma_handle first
		dma_handle = s_cma_desc.pages[pg_idx].dma_handle;
		ret = __npu_cma_phyaddr_free(NPU_CMA_PAGE_SIZE, dma_handle);
		if (ret) {
			NPU_ERR("illagal free dma_handle = %p ,pg_idx = %d failed,",
				(void *)(uintptr_t)dma_handle, pg_idx);
			return ret;
		}

		// unmap vaddr mapping
		ret = npu_sec_mem_unmap(hiai_ta_vaddr, NPU_CMA_PAGE_SIZE);
		if (ret) {
			NPU_ERR("unmap tavaddr = %p ,pg_idx = %d failed,", vaddr, pg_idx);
			return ret;
		}

		// clean ta_vaddr of cma page
		s_cma_desc.pages[pg_idx].ta_vaddr = 0;
		NPU_INFO("free npu cma ta_vaddr = %p ,pg_idx = %d success", vaddr, pg_idx);
		break;
	}

	if (ret) {
		NPU_ERR("free npu cma ta_vaddr = %p failed, illegal vaddr", vaddr);
	}

	return ret;
}

// 1 is free : 0 occupied
static int is_cma_page_free(u32 pg_idx)
{
	if (pg_idx >= NPU_CMA_PAGE_NUM) {
		NPU_ERR("invalid param pg_idx\n");
		return 0;
	}
	return s_cma_desc.pages[pg_idx].state == NPU_CMA_PAGE_FREE;
}

int npu_cma_ta_vaddr_to_paddr(void *ta_vaddr, u32 *phy_addr)
{
	u32 hiai_ta_vaddr = (u32)((uintptr_t)ta_vaddr);
	u32 cma_page_inner_offset;
	u32 addr_distance;
	u64 dma_handle;
	u32 pg_idx;
	int ret = -1;

	if (ta_vaddr == NULL || phy_addr == NULL) {
		NPU_ERR("illegal ta_vaddr = %p or phy_addr = %p param", ta_vaddr, phy_addr);
		return -1;
	}

	for (pg_idx = 0; pg_idx < NPU_CMA_PAGE_NUM; pg_idx++) {
		if (hiai_ta_vaddr < s_cma_desc.pages[pg_idx].ta_vaddr) {
			NPU_ERR("addr_distance less than s_cma_desc.pages[pg_idx].ta_vaddr.");
			continue;
		}
		addr_distance = hiai_ta_vaddr - s_cma_desc.pages[pg_idx].ta_vaddr;
		NPU_DEBUG("pg_idx = %d hiai_ta_vaddr = %p ,addr_distance = %llx",
			pg_idx, hiai_ta_vaddr, addr_distance);

		// addr_distance / NPU_CMA_PAGE_SIZE
		if (addr_distance >> NPU_CMA_PAGE_SIZE_ORDER != 0) { // not n this cma page ,continue
			continue;
		}

		// find correponding vaddr and free dma_handle first
		dma_handle = s_cma_desc.pages[pg_idx].dma_handle;
		if ((u32)(uintptr_t)ta_vaddr < s_cma_desc.pages[pg_idx].ta_vaddr) {
			NPU_ERR("ta_vaddr less than s_cma_desc.pages[pg_idx].ta_vaddr");
			continue;
		}
		cma_page_inner_offset = (u32)(uintptr_t)ta_vaddr -
		s_cma_desc.pages[pg_idx].ta_vaddr;
		*phy_addr = (u32)(dma_handle + cma_page_inner_offset);
		NPU_DEBUG("ta_vaddr base cma page dma_handle = %p ,pg_idx = %d "
			"phy_addr = %p cma_page_inner_offset = 0x%x ta_vaddr = %p",
			(void *)dma_handle, pg_idx, (void *)(*phy_addr), cma_page_inner_offset, ta_vaddr);
		ret = 0;
		break;
	}

	if (ret) {
		NPU_ERR("illegal ta_vaddr = %p", ta_vaddr);
	}

	return ret;
}

int npu_cma_resource_recycle(struct npu_dev_ctx *dev_ctx)
{
	int pg_idx;
	int ret = 0;
	(void)dev_ctx;

	for (pg_idx = 0; pg_idx < NPU_CMA_PAGE_NUM; pg_idx++) {
		if (!is_cma_page_free(pg_idx)) { // free occpied cma pages
			MUTEX_LOCK(cma);
			ret += npu_cma_free((void *)(uintptr_t)s_cma_desc.pages[pg_idx].ta_vaddr);
			MUTEX_UNLOCK(cma);
			NPU_ERR("recycle cm mem pg_idx = 0x%x ret = %d", pg_idx, ret);
		}
	}

	return ret;
}
