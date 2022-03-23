/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: This file implement secboot image interfaces
 * Create: 2019-05-24
 */

#include "process_ivp_info.h"
#include <ivp.h>
#include <sre_typedef.h>
#include <platform.h>
#include <mem_page_ops.h>
#include <mem_ops.h>
#include <drv_mem.h>
#include <register_ops.h>
#include <securec.h>
#include "secboot.h"
#include "sec_region_ops.h"

#define SEC_BIN_SIZE 0x100000

/* intial the IVP relevant variable in gloabal buffer */
UINT32 process_ivp_info_init(paddr_t soc_addr)
{
    tloge("%s, IVP init start\n", __func__);
    UINT32 cma_size = get_cma_size(IVP);
    if (cma_size == SECBOOT_ILLEGAL_CMA_SIZE) {
        tloge("%s:ivp cma_size fail\n", __func__);
        return SECBOOT_RET_PARAM_ERROR;
    }

    UINT32 ret = (UINT32)check_secureos_addr(soc_addr, cma_size);
    if (ret != 0) {
        tloge("%s, addr check failed, size = 0x%x, ret = %u\n", __func__, cma_size, ret);
        return SECBOOT_RET_INVALIED_CMA_ADDR;
    }

    UINT32 img_size = ALIGNED_64BYTE_VALUE(get_ivp_img_size());

    UINT32 type_size;
    struct secboot_info *image_info_ptr = NULL;
    ret = secboot_get_image_info_addr(&image_info_ptr, &type_size);
    if ((ret != SECBOOT_RET_SUCCESS) || (image_info_ptr == NULL)) {
        tloge("%s, invalid image_info_ptr\n", __func__);
        return SECBOOT_RET_PARAM_ERROR;
    }
    if (type_size <= IVP) {
        tloge("%s, soc_type err\n", __func__);
        return SECBOOT_RET_INVALIED_SOC_TYPE;
    }

    image_info_ptr[IVP].ddr_phy_addr = soc_addr;
    image_info_ptr[IVP].ddr_virt_addr = IMAGE_ADDR_INVALID_VALUE;
    image_info_ptr[IVP].image_addr = IMAGE_ADDR_INVALID_VALUE;
    image_info_ptr[IVP].ddr_size = img_size;
    image_info_ptr[IVP].unreset_dependcore = 0;

    tloge("%s, IVP init end\n", __func__);
    return SECBOOT_RET_SUCCESS;
}

/* ivp verify fail to do something for debug */
UINT32 process_ivp_info_fail(void)
{
    UINT32 map_soc_addr;
    UINT32 cma_size;
    UINT32 ret = process_map_addr(IVP, &map_soc_addr, &cma_size);
    if (ret != 0) {
        tloge("%s, soc addr check failed, ret %u\n", __func__, ret);
        return ret;
    }

    process_clean_addr(map_soc_addr, cma_size);

    return ret;
}

/* check ivp physical address */
#ifdef SEC_IVP
static UINT32 ivp_check_sec_addr(u64 start_addr, u64 end_addr)
{
#if defined(CHECK_DDR_SEC_CONFIG)
    INT32 ret;
    u64 sgl_size;
    struct sglist *sgl = NULL;

    sgl_size = sizeof(TEE_PAGEINFO) + sizeof(struct sglist);
    sgl = (struct sglist *)malloc(sgl_size);
    if (!sgl) {
        tloge("apply sgl memory fail\n");
        return 0;
    }
    (void)memset_s(sgl, sgl_size, 0, sgl_size);
    sgl->sglistSize = sgl_size;
    sgl->infoLength = 1; /* only one pageinfo */
    sgl->info[0].phys_addr = start_addr;
    sgl->info[0].npages = (end_addr - start_addr) / PAGE_SIZE;

    ret = ddr_sec_cfg(sgl, DDR_SEC_FACE, DDR_CHECK_SEC);
    free(sgl);
    if (ret != 0) {
        tloge("check sec_region fail\n");
        return 0;
    }
    return 1;
#elif defined(CHECK_SEC_ADDR)
    return (UINT32)is_sec_addr(start_addr, end_addr);
#else
    return 0;
#endif
}
#endif

/* IVP verify succ to copy ivp image data to ivp addr */
UINT32 process_ivp_info_succ(void)
{
#ifdef SEC_IVP
    tloge("%s, IVP process start\n", __func__);
    struct secboot_info *image_info_ptr = NULL;
    UINT32 type_size;
    UINT32 ret = secboot_get_image_info_addr(&image_info_ptr, &type_size);
    if ((ret != SECBOOT_RET_SUCCESS) || (image_info_ptr == NULL)) {
        tloge("%s, invalid image_info_ptr\n", __func__);
        return SECBOOT_RET_PARAM_ERROR;
    }
    if (type_size <= IVP) {
        tloge("%s, invalid soc type\n", __func__);
        return SECBOOT_RET_INVALIED_SOC_TYPE;
    }

    UINT32 cma_addr_size = image_info_ptr[IVP].ddr_size;

    /* in some abnormal scenes(memory misalignment), ivp can only use 1MB */
    ret = ivp_check_sec_addr((u64)image_info_ptr[IVP].ddr_phy_addr,
        (u64)(image_info_ptr[IVP].ddr_phy_addr + SEC_BIN_SIZE));
    if (ret == 0) {
        tloge("ivp addr isn't sec_addr\n");
        return SECBOOT_RET_INVALIED_ADDR_CHECK;
    }

    ret = (UINT32)check_secureos_addr(image_info_ptr[IVP].ddr_phy_addr, cma_addr_size);
    if (ret != 0) {
        tloge("%s, addr check failed, ret = %u\n", __func__, ret);
        return ret;
    }

    UINT32 tmp_soc_addr;
    ret = (UINT32)map_from_ns_page(image_info_ptr[IVP].ddr_phy_addr, cma_addr_size, &tmp_soc_addr, secure);
    if (ret != 0) {
        tloge("%s, soc addr check failed, ret = %u, cma_size = 0x%x\n",
            __func__, ret, cma_addr_size);
        return ret;
    }

    /* load ivp image to iram/dram/ddr */
    ret = (UINT32)load_ivp_image(tmp_soc_addr);
    if (ret != 0) {
        tloge("%s, load IVP image failed, result = %u\n", __func__, ret);
    }
    (void)unmap_from_ns_page(tmp_soc_addr, cma_addr_size);
    tloge("%s, IVP process end\n", __func__);
    return ret;
#else
    return SECBOOT_RET_PARAM_ERROR;
#endif
}

#ifdef CONFIG_HISI_SECBOOT_IMG_V2
UINT32 hisi_ivp_reset(UINT32 soc_type)
{
    if (soc_type != IVP) {
        tloge("%s %u not ivp\n", __func__, soc_type);
        return SECBOOT_RET_PARAM_ERROR;
    }
    return SECBOOT_RET_SUCCESS;
}

UINT32 hisi_ivp_set(UINT32 soc_type)
{
    if (soc_type != IVP) {
        tloge("%s %u not ivp\n", __func__, soc_type);
        return SECBOOT_RET_PARAM_ERROR;
    }
    return SECBOOT_RET_SUCCESS;
}
#endif
