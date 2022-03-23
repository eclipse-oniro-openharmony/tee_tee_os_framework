/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: platform adapt for cpu
 * Author     : m00475438
 * Create     : 2019/08/25
 */
#include <pal_cpu.h>
#include <pal_types.h>
#include <pal_log.h>
#include <mspe_power.h>
#include <common_utils.h>
#include <drv_cache_flush.h>
#include <mem_ops_ext.h>

/* set the module to which the file belongs
 * each .C file needs to be configured
 */
#define BSP_THIS_MODULE               BSP_MODULE_SYS

err_bsp_t pal_seceng_power_check(u32 mid, u32 ip_idx, u32 onoff)
{
	UNUSED(ip_idx);

	if (onoff != SEC_ON)
		return BSP_RET_OK;

	if (PAL_CHECK(hieps_get_voted_nums() == 0))
		return ERR_API(ERRCODE_SYS);

	if (PAL_CHECK(mid == BSP_MODULE_SM9 && mspe_sm9_is_inited() != SEC_TRUE))
		return ERR_API(ERRCODE_INVALID);

	return BSP_RET_OK;
}

/**
 * @brief      : convert cpu add to master addr
 */
err_bsp_t pal_convert_addr_cpu2master(const pal_cpu_addr_t cpu_addr,
				      pal_master_addr_t *master_addr)
{
	if (!master_addr)
		return ERR_HAL(ERRCODE_NULL);

	*master_addr = (pal_master_addr_t)INTEGER(cpu_addr);

	return BSP_RET_OK;
}

/**
 * @brief      : convert master addr to cpu addr
 */
err_bsp_t pal_convert_addr_master2cpu(const pal_master_addr_t master_addr,
				      pal_cpu_addr_t *cpu_addr)
{
	if (!cpu_addr)
		return ERR_HAL(ERRCODE_NULL);

	*cpu_addr = (pal_cpu_addr_t)PTR(master_addr);

	return BSP_RET_OK;
}

/**
 * @brief      : get eng working frequency
 * @return     : frequency (M)
 */
u32 pal_get_eng_frequency(void)
{
	return 240; /* work freq is 240 MHZ */
}

u64 pal_virt_to_phy(const u8 *va)
{
	return __virt_to_phys((uintptr_t)va);
}

err_bsp_t pal_flush_dcache(const u8 *pbuffer, u32 size)
{
	v7_dma_flush_range((unsigned long)PTR(pbuffer),
			   (unsigned long)PTR(pbuffer + size));

	return BSP_RET_OK;
}

err_bsp_t pal_invalidate_dcache(const u8 *pbuffer, u32 size)
{
	v7_dma_inv_range((unsigned long)PTR(pbuffer),
			 (unsigned long)PTR(pbuffer + size));

	return BSP_RET_OK;
}

err_bsp_t pal_clean_dcache(const u8 *pbuffer, u32 size)
{
	v7_dma_clean_range((unsigned long)PTR(pbuffer),
			   (unsigned long)PTR(pbuffer + size));

	return BSP_RET_OK;
}
