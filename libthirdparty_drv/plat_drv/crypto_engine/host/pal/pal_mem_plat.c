/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: memory platform adapter
 * Author     : m00475438
 * Create     : 2018/08/15
 */
#include <stdlib.h>
#include <eps_ddr_layout_define.h>
#include <pal_libc.h>
#include <pal_heap.h>
#include <common_utils.h>
#include <drv_mem.h>

/* set the module to which the file belongs
 * each .C file needs to be configured
 */
#define BSP_THIS_MODULE         BSP_MODULE_SYS

#define PAL_MEM_DDR_SIZE        HIEPS_SHARE_DDR_IMAGE_SIZE
#define PAL_MEM_DDR_ADDR        EPS_SHARE_DDR_IMAGE_ADDR(HIEPS_DDR_SPACE_BASE_ADDR)

/* workspace for SCE1 and SCE2 */
#define HIEPS_SHARE_MEM_POOL    (EPS_ENHANCE_DDR_START_ADDR(HIEPS_DDR_SPACE_BASE_ADDR))
#define HIEPS_SHARE_MEM_SIZE    HIEPS_ENHANCE_DDR_REGION_TOTAL_SIZE
#define PAL_SCE1_WORKSPACE_ADDR HIEPS_SHARE_MEM_POOL
#define PAL_SCE1_WORKSPACE_SIZE (HIEPS_SHARE_MEM_SIZE >> 1)
#define PAL_SCE2_WORKSPACE_ADDR (PAL_SCE1_WORKSPACE_ADDR + \
				 PAL_SCE1_WORKSPACE_SIZE)
#define PAL_SCE2_WORKSPACE_SIZE PAL_SCE1_WORKSPACE_SIZE

struct mspe_ddr_mgr {
	u64 mspe_ddr_base_addr;
	u64 mspe_symm_workspace;
	u64 mspe_heap_pool;
};

static struct mspe_ddr_mgr g_mspe_ddr_mgr;

u8 *g_pal_mem_pool;

err_bsp_t pal_ddr_mgr_init(void)
{
	u32 ret;

	ret = sre_mmap(HIEPS_SHARE_MEM_POOL, HIEPS_SHARE_MEM_SIZE,
		       (unsigned int *)&g_mspe_ddr_mgr.mspe_ddr_base_addr,
		       secure, cache);
	if (PAL_CHECK(ret != 0)) {
		PAL_ERROR("sre_mmap fail, ret = %d\n", ret);
		return ERR_HAL(ERRCODE_MEMORY);
	}
	g_mspe_ddr_mgr.mspe_symm_workspace = g_mspe_ddr_mgr.mspe_ddr_base_addr;

	return BSP_RET_OK;
}

/* return size of symm workspace */
u32 pal_get_symm_workspace(u32 id, u64 *va, u64 *pa)
{
	u64 vaddr;
	u64 paddr;
	u32 size;

	switch (id) {
	case 0: /* first part of workspace */
		vaddr = g_mspe_ddr_mgr.mspe_symm_workspace;
		paddr = PAL_SCE1_WORKSPACE_ADDR;
		size = PAL_SCE1_WORKSPACE_SIZE;
		break;
	case 1:
		vaddr = g_mspe_ddr_mgr.mspe_symm_workspace + PAL_SCE1_WORKSPACE_SIZE;
		paddr = PAL_SCE2_WORKSPACE_ADDR;
		size = PAL_SCE2_WORKSPACE_SIZE;
		break;
	default:
		vaddr = 0;
		paddr = 0;
		size  = 0;
		break;
	}

	if (va)
		*va = vaddr;
	if (pa)
		*pa = paddr;

	return size;
}

/**
 * @brief      : free memory
 * @param[in]  : p memory pointer
 * @return     : void
 */
void pal_free(const void *p)
{
	if (!p || !g_pal_mem_pool)
		return;

	pal_heap_free(g_pal_mem_pool, PAL_MEM_DDR_SIZE, p);
}

/**
 * @brief      : memory alloc
 * @param[in]  : size    memory size
 * @return     : void *  memory address pointer
 */
void *pal_malloc(u32 size)
{
	int tee_ret;
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	UNUSED(ret);
	if (size == 0)
		return NULL;

	if (!g_pal_mem_pool) {
		tee_ret = sre_mmap(PAL_MEM_DDR_ADDR, PAL_MEM_DDR_SIZE,
				   (unsigned int *)&g_pal_mem_pool,
				   secure, cache);
		if (PAL_CHECK(tee_ret != 0)) {
			PAL_ERROR("tee_ret = %d\n", tee_ret);
			return NULL;
		}
		ret = pal_heap_init(g_pal_mem_pool, PAL_MEM_DDR_SIZE);
		if (PAL_CHECK(ret != BSP_RET_OK))
			return NULL;
	}

	return pal_heap_alloc(g_pal_mem_pool, PAL_MEM_DDR_SIZE, size);
}

err_bsp_t pal_mem_equ(const void *_s1, const void *_s2, u32 len)
{
	if (memcmp((void *)_s1,  _s2,  len) == 0)
		return BSP_RET_OK;
	else
		return ERR_HAL(ERRCODE_VERIFY);
}

