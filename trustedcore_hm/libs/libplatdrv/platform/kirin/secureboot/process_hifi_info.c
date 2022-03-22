/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: process load hifi
 * Create: 2018-5-21
 */

#include "process_hifi_info.h"

#include <stdint.h>
#include <sre_typedef.h>
#include <platform.h>
#include <drv_mem.h>
#include <register_ops.h>
#include <mem_page_ops.h>
#include <hifi.h>
#include "secboot.h"
#include <securec.h>
#if ((TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI6250) && (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3660))
#include "sec_region_ops.h"
#endif

enum process_type {
	LOAD_TO_CMA_REGION,
	LOAD_TO_HIFI_RUN_REGION,
	PROCESS_HIFI_DEFAULT
};

/*
 * 1. check cma addr is valid
 * 2. store cma addr and size in global buffer
 */
UINT32 process_hifi_info_init(paddr_t soc_addr)
{
	INT32 ret;
	UINT32 img_size;
	UINT32 uint_ret;
	UINT32 cma_addr_size;
	UINT32 type_size;
	struct secboot_info *image_info_ptr = NULL;

	alogi("init start");

	cma_addr_size = get_cma_size(HIFI);
	if (cma_addr_size == SECBOOT_ILLEGAL_CMA_SIZE) {
		aloge("hifi cma size check fail");
		return SECBOOT_RET_PARAM_ERROR;
	}

	ret = check_secureos_addr(soc_addr, cma_addr_size);
	if (ret != 0) {
		aloge("addr check failed, ret: %d", ret);
		return SECBOOT_RET_INVALIED_CMA_ADDR;
	}

	uint_ret = get_hifi_image_size(&img_size);
	if (uint_ret != 0) {
		aloge("get hifi image size failed, ret: %u", uint_ret);
		return uint_ret;
	}

#if ((TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI6250) && (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3660))
	ret = ddr_sec_cfg_for_feature(soc_addr, soc_addr + cma_addr_size,
		DDR_SEC_HIFI_RESET);
	if (ret != 0) {
		aloge("configurate ddr's security failed, ret: %d", ret);
		return SECBOOT_RET_FAILURE;
	}
#endif

	img_size = ALIGNED_64BYTE_VALUE(img_size);

	uint_ret = secboot_get_image_info_addr(&image_info_ptr, &type_size);
	if (uint_ret != 0 || image_info_ptr == NULL) {
		aloge("invalid image info ptr");
		return SECBOOT_RET_PARAM_ERROR;
	}
	if (type_size <= HIFI) {
		aloge("invalid soc type");
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	image_info_ptr[HIFI].ddr_phy_addr = soc_addr;
	image_info_ptr[HIFI].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
	image_info_ptr[HIFI].image_addr = IMAGE_ADDR_INVALID_VALUE;
	image_info_ptr[HIFI].ddr_size = img_size;
	image_info_ptr[HIFI].unreset_dependcore = 0;

	return 0;
}

/*
 * 1. hifi verify fail to store error image data for debug
 * 2. to clean cma buffer
 */
static UINT32 download_hifi(enum process_type type)
{
	UINT32 uint_ret;
	UINT32 map_addr = 0;
	UINT32 cma_size = 0;
#if ((TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI6250) && (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3660))
	INT32 ret;
	UINT32 type_size;
	struct secboot_info *image_info_ptr = NULL;
#endif

	alogi("download begin");

	uint_ret = process_map_addr(HIFI, &map_addr, &cma_size);
	if (uint_ret) {
		aloge("soc addr check failed, ret: %u, cma size: 0x%x",
			uint_ret, cma_size);
		return uint_ret;
	}

	if (type == LOAD_TO_CMA_REGION) {
		/* save image data to cma addr */
		uint_ret = dump_cma_text((void *)(uintptr_t)map_addr);
		if (uint_ret != 0)
			aloge("dump hifi failed, uint_ret: %u", uint_ret);
	} else {
		/* load hifi image to hifi run addr */
		uint_ret = load_hifi_image((void *)(uintptr_t)map_addr);
		if (uint_ret != 0)
			aloge("load hifi image failed, uint_ret: %u", uint_ret);
	}

	process_clean_addr(map_addr, cma_size);

#if ((TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI6250) && (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_HI3660))
	{
		uint_ret = secboot_get_image_info_addr(&image_info_ptr, &type_size);
		if (uint_ret != 0 || image_info_ptr == NULL) {
			aloge("invalid image info ptr");
			return SECBOOT_RET_PARAM_ERROR;
		}

		if (type_size <= HIFI) {
			aloge("invalid soc type");
			return SECBOOT_RET_INVALIED_SOC_TYPE;
		}

		ret = ddr_sec_clean_for_feature(image_info_ptr[HIFI].ddr_phy_addr,
			image_info_ptr[HIFI].ddr_phy_addr + cma_size,
			DDR_SEC_HIFI_RESET);
		if (ret != 0) {
			aloge("configurate ddr's unsecurity failed, ret: %d", ret);
			return SECBOOT_RET_FAILURE;
		}
	}
#endif

	return uint_ret;
}

UINT32 process_hifi_info_fail(void)
{
	return download_hifi(LOAD_TO_CMA_REGION);
}

UINT32 process_hifi_info_succ(void)
{
	return download_hifi(LOAD_TO_HIFI_RUN_REGION);
}

#ifdef CONFIG_HISI_SECBOOT_IMG_V2
UINT32 hifi_reset(UINT32 soc_type)
{
	UINT32 ret;

	if (soc_type != HIFI) {
		aloge("%u not hifi", soc_type);
		return SECBOOT_RET_PARAM_ERROR;
	}

	ret = prepare_reload_hifi();
	if (ret != 0) {
		aloge("soctype: %u prepare reload hifi fail ret: 0x%x",
			soc_type, ret);
		return ret;
	}

	return 0;
}

UINT32 hifi_set(UINT32 soc_type)
{
	if (soc_type != HIFI) {
		aloge("%u not hifi", soc_type);
		return SECBOOT_RET_PARAM_ERROR;
	}

	return 0;
}
#endif

