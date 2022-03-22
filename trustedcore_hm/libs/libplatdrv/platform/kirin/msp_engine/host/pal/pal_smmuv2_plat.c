/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: platform adapt for smmuv2
 * Author: Security Engine
 * Create: 2020/10/13
 */
#include <pal_smmu_plat.h>
#include <pal_types.h>
#include <pal_log.h>
#include <secmem.h>
#include <mem_mode.h>
#include <sec_smmu_com.h>
#include <common_utils.h>
#include <mspe_smmu_v2.h>

#define BSP_THIS_MODULE    BSP_MODULE_SYS

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
	ret = sion_unmap_iommu(&mcl);
	if (PAL_CHECK(ret != 0))
		return ERR_API(ERRCODE_SYS);

	return BSP_RET_OK;
}

err_bsp_t pal_mmu_enable(u32 ip_idx, u32 read_en, u32 write_en, u32 is_sec)
{
	u32 rd_cfg = MSPE_SMMU_NON_SECURE;
	u32 wr_cfg = MSPE_SMMU_PROTECT;

	UNUSED(is_sec);

	if (read_en != SEC_YES)
		rd_cfg = MSPE_SMMU_BYPASS_SECURE;
	if (write_en != SEC_YES)
		wr_cfg = MSPE_SMMU_BYPASS_SECURE;

	PAL_ERROR("read_en=%x,write_en=%x\n", read_en, write_en);
	PAL_ERROR("rd_cfg=%x,wr_cfg=%x\n", rd_cfg, wr_cfg);
	if (ip_idx == 0)
		mspe_smmu_enable(MSPE_MID_SCE1, rd_cfg, wr_cfg);
	else
		mspe_smmu_enable(MSPE_MID_SCE2, rd_cfg, wr_cfg);

	return BSP_RET_OK;
}

err_bsp_t pal_mmu_disable(u32 ip_idx, u32 is_sec)
{
	UNUSED(is_sec);

	if (ip_idx == 0)
		mspe_smmu_disable(MSPE_MID_SCE1);
	else
		mspe_smmu_disable(MSPE_MID_SCE2);

	return BSP_RET_OK;
}
