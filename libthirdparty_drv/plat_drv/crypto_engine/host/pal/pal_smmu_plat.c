/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: platform adapt for smmu
 * Author: SecurityEngine
 * Create: 2020/03/09
 */
#include <pal_smmu_plat.h>
#include <pal_types.h>
#include <pal_log.h>
#include <common_utils.h>
#include <drv_cache_flush.h>
#include <secmem.h>
#include <mem_mode.h>
#include <stdbool.h>
#include <sec_smmu_com.h>
#include <hieps_smmu.h>

#define BSP_THIS_MODULE    BSP_MODULE_SYS

/* creat pte/cd for sid/ssid */
err_bsp_t pal_mmu_bind(void)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = sec_smmu_bind(SMMU_MEDIA2,
			    SECSMMU_STREAMID_EPS, SECSMMU_SUBSTREAMID_EPS, 0);
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_REQUEST);

	return BSP_RET_OK;
}

/* destroy pte/cd for sid/ssid */
err_bsp_t pal_mmu_unbind(void)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = sec_smmu_unbind(SMMU_MEDIA2,
			      SECSMMU_STREAMID_EPS, SECSMMU_SUBSTREAMID_EPS);
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_REQUEST);

	return BSP_RET_OK;
}

/* creat page table and map iova */
err_bsp_t pal_mmu_map(u32 buffer_id, u32 size, u32 *iova)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct mem_chunk_list mcl = {0};

	mcl.protect_id = SEC_TASK_DRM;
	mcl.buff_id    = buffer_id;
	mcl.size       = size;
	mcl.cache      = non_cache;
	ret = sion_map_iommu(&mcl);
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_SYS);

	*iova = mcl.va;

	return BSP_RET_OK;
}

/* destroy page table and unmap iova */
err_bsp_t pal_mmu_unmap(u32 buffer_id, u32 size)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct mem_chunk_list mcl = {0};

	mcl.protect_id = SEC_TASK_DRM;
	mcl.buff_id    = buffer_id;
	mcl.size       = size;
	mcl.cache      = non_cache;
	mcl.smmuid     = SMMU_MEDIA2;
	mcl.sid        = SECSMMU_STREAMID_EPS;
	mcl.ssid       = SECSMMU_SUBSTREAMID_EPS;
	ret = sion_unmap_iommu(&mcl);
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_SYS);

	return BSP_RET_OK;
}

err_bsp_t pal_mmu_poweron(void)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = sec_smmu_poweron(SMMU_MEDIA2);
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_REQUEST);

	return BSP_RET_OK;
}

err_bsp_t pal_mmu_poweroff(void)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = sec_smmu_poweroff(SMMU_MEDIA2);
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_REQUEST);

	return BSP_RET_OK;
}

/* connect tbu and tcu */
err_bsp_t pal_mmu_tbu_init(void)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = hieps_mmu_init();
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_REQUEST);

	return BSP_RET_OK;
}

/* disconnect tbu and tcu */
err_bsp_t pal_mmu_tbu_deinit(void)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = hieps_mmu_exit();
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_REQUEST);

	return BSP_RET_OK;
}

err_bsp_t pal_mmu_enable(u32 ip_idx, u32 read_en, u32 write_en, u32 is_sec)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	int sec = FALSE;

	if (is_sec)
		sec = TRUE;

	if (write_en == SEC_YES)
		write_en = TRUE;
	else
		write_en = FALSE;

	if (read_en == SEC_YES)
		read_en = TRUE;
	else
		read_en = FALSE;

	switch (ip_idx) {
	case 0: /* SYMM_SCE1 */
		ret = hieps_mmu_sce1_enable(read_en, write_en, sec);
		if (PAL_CHECK(ret != 0))
			return ERR_API(ERRCODE_SYS);
		break;
	case 1: /* SYMM_SCE2 */
		ret = hieps_mmu_sce2_enable(read_en, write_en, sec);
		if (PAL_CHECK(ret != 0))
			return ERR_API(ERRCODE_SYS);
		break;
	default:
		return ERR_API(ERRCODE_PARAMS);
	}

	return BSP_RET_OK;
}

err_bsp_t pal_mmu_disable(u32 ip_idx, u32 is_sec)
{
	UNUSED(ip_idx);
	UNUSED(is_sec);
	return BSP_RET_OK;
}

