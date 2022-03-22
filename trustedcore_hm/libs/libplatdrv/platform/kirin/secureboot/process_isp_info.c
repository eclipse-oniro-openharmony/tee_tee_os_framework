/*
* hisilicon ISP process, process_isp_info.c
*
* Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
*
*/

#include <sre_typedef.h>
#include <platform.h>
#include <register_ops.h>
#include <mem_page_ops.h>
#include <hisi_isp.h>
#include <drv_mem.h> // check_secureos_addr
#include "secboot.h"
#include <securec.h>
#ifdef CONFIG_HISI_ISP_SEC_IMAGE
#include "sec_region_ops.h"
#endif
/*
* 1.intial the ISP relevant variable in gloabal buffer
*
*/

UINT32 process_isp_info_init(paddr_t soc_addr)
{
	INT32 ret;
	UINT32 err;
	UINT32 type_size = 0;
	UINT32 img_size, cma_size;
	struct secboot_info *image_info_ptr = NULL;

	tloge("%s, ISP init start!\n", __func__);

	cma_size = get_cma_size(ISP);

	if (cma_size == SECBOOT_ILLEGAL_CMA_SIZE) {
		tloge("%s:isp cma_size fail!\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}
#ifdef CONFIG_HISI_ISP_SEC_IMAGE
#if ((TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI6260) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3670) || \
    (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI3680) || (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO))
	ret = is_sec_addr((u64)soc_addr, (u64)(soc_addr + cma_size));
	if (ret == 0) {
		tloge("%s, addr sec check failed, ret = %d\n", __func__, ret);
		return SECBOOT_RET_INVALIED_CMA_ADDR;
	}
#else
	struct sglist *isp_sglist = NULL;

	isp_sglist = malloc(sizeof(struct sglist) + sizeof(TEE_PAGEINFO));
	if (isp_sglist == NULL) {
		tloge("%s, isp sglist malloc fail\n", __func__);
		return SECBOOT_RET_INVALIED_CMA_ADDR;
	}

	isp_sglist->sglistSize = sizeof(struct sglist) + sizeof(TEE_PAGEINFO);
	isp_sglist->ion_size = cma_size;
	isp_sglist->infoLength = 1;
	isp_sglist->info[0].phys_addr = soc_addr;
	isp_sglist->info[0].npages = cma_size / PAGE_SIZE;

	ret = ddr_sec_cfg(isp_sglist, DDR_SEC_FACE, DDR_CHECK_SEC);
	if (ret != 0) {
		tloge("%s, addr sec check failed, ret = %d\n", __func__, ret);
		free(isp_sglist);
		return SECBOOT_RET_INVALIED_CMA_ADDR;
	}

	free(isp_sglist);
#endif
#endif

	ret = check_secureos_addr(soc_addr, cma_size);

	if (ret) {
		tloge("%s, addr check failed, ret = %d\n", __func__, ret);
		return SECBOOT_RET_INVALIED_CMA_ADDR;
	}

	img_size = get_isp_img_size();
	img_size = ALIGNED_64BYTE_VALUE(img_size);

	err = secboot_get_image_info_addr(&image_info_ptr, &type_size);
	if (err != SECBOOT_RET_SUCCESS || !image_info_ptr) {
		tloge("%s, invalid image_info_ptr\n", __func__);
		return SECBOOT_RET_PARAM_ERROR;
	}
	if (ISP >= type_size) {
		tloge("%s, invalid soc type\n", __func__);
		return SECBOOT_RET_INVALIED_SOC_TYPE;
	}

	image_info_ptr[ISP].ddr_phy_addr = soc_addr;
	image_info_ptr[ISP].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
	image_info_ptr[ISP].image_addr = IMAGE_ADDR_INVALID_VALUE;
	image_info_ptr[ISP].ddr_size = img_size;
	image_info_ptr[ISP].unreset_dependcore = 0;

	tloge("%s, ISP init success!\n", __func__);
	return SECBOOT_RET_SUCCESS;
}

/*
* 1.isp verify fail to do something for debug
*
*/
UINT32 process_isp_info_fail(void)
{
	UINT32 ret, map_soc_addr, cma_size;

	ret = process_map_addr(ISP, &map_soc_addr, &cma_size);

	if (ret) {
		tloge("%s, soc addr check failed, ret = %d\n", __func__, ret);
		return ret;
	}

	process_clean_addr(map_soc_addr, cma_size);

	return ret;
}

/*
* 1. ISP verify succ to copy isp image data to isp addr
*
*/
UINT32 process_isp_info_succ(void)
{
	return SECBOOT_RET_SUCCESS;
}

#ifdef CONFIG_HISI_SECBOOT_IMG_V2
UINT32 hisi_isp_reset_v2(UINT32 soc_type)
{
	if (soc_type != ISP) {
		tloge("%s %d not isp\n", __func__, soc_type);
		return SECBOOT_RET_PARAM_ERROR;
	}
	hisi_isp_reset();
	return SECBOOT_RET_SUCCESS;
}

UINT32 hisi_isp_set_v2(UINT32 soc_type)
{
	if (soc_type != ISP) {
		tloge("%s %d not isp\n", __func__, soc_type);
		return SECBOOT_RET_PARAM_ERROR;
	}
	hisi_isp_disreset((UINT32)g_image_info[soc_type].ddr_phy_addr);
	return SECBOOT_RET_SUCCESS;
}
#endif
