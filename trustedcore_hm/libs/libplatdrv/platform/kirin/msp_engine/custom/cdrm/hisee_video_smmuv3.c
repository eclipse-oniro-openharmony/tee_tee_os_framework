/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: smmu ctrl for cdrm
 * Author: Security Engine
 * Create: 2020/10/13
 */
#include "hisee_video_smmu.h"
#include <pal_smmu_plat.h>
#include <pal_log.h>

#define BSP_THIS_MODULE            BSP_MODULE_SCE

err_bsp_t hisee_video_smmu_init(u32 buffer_id, u32 size, u32 *iova)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = pal_mmu_poweron();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	ret = pal_mmu_bind();
	if (PAL_CHECK(ret != BSP_RET_OK)) {
		(void)pal_mmu_poweroff();
		return ret;
	}
	ret = pal_mmu_map(buffer_id, size, iova);
	if (PAL_CHECK(ret != BSP_RET_OK)) {
		(void)pal_mmu_unbind();
		(void)pal_mmu_poweroff();
		return ret;
	}
	ret = pal_mmu_tbu_init();
	if (PAL_CHECK(ret != BSP_RET_OK)) {
		(void)pal_mmu_unmap(buffer_id, size);
		(void)pal_mmu_unbind();
		(void)pal_mmu_poweroff();
		return ret;
	}

	return ret;
}

void hisee_video_smmu_deinit(u32 buffer_id, u32 size)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = pal_mmu_tbu_deinit();
	if (PAL_CHECK(ret != BSP_RET_OK))
		PAL_ERROR("tbu deinit fail, ret=%x\n", ret);
	ret = pal_mmu_unmap(buffer_id, size);
	if (PAL_CHECK(ret != BSP_RET_OK))
		PAL_ERROR("smmu unmap fail, ret=%x\n", ret);
	ret = pal_mmu_unbind();
	if (PAL_CHECK(ret != BSP_RET_OK))
		PAL_ERROR("smmu unbind fail, ret=%x\n", ret);
	ret = pal_mmu_poweroff();
	if (PAL_CHECK(ret != BSP_RET_OK))
		PAL_ERROR("smmu poweroff fail, ret=%x\n", ret);
}

