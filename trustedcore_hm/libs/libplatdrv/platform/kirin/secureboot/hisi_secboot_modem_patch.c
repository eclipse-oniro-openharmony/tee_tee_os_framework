/*
 * hisilicon MODEM process, process_modem_info.c
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 */
#include <sre_typedef.h>
#include <drv_mem.h> // sre_mmap
#include <drv_cache_flush.h> // v7_dma_flush_range && v7_dma_inv_range
#include <register_ops.h>
#include "tee_log.h"
#include <mem_page_ops.h>
#include "bsp_secboot_adp.h"
#include "secboot.h"
#include <securec.h>
#include "crys_rnd.h"
#include "process_modem_info.h"
#include <platform.h>
#ifdef CONFIG_MODEM_COLD_PATCH
#include "secure_bspatch.h"
#endif

#ifdef CONFIG_MODEM_COLD_PATCH

struct secboot_modem_cold_patch_info_s g_modem_cold_patch_info;

size_t hisi_secboot_copy_splicing_img_to_run_addr_call_back(const uint8_t *src_addr, size_t size)
{
    int ret = 0;
    ;
    UINT32 offset;

    offset = g_modem_cold_patch_info.ccore_offset;

    ret = memcpy_s((void *)(g_modem_cold_patch_info.ccore_vir_addr + offset), size, (void *)src_addr, size);
    /* using dma cache flush in MP platform instead of flush cache all */
    v7_dma_flush_range(g_modem_cold_patch_info.ccore_vir_addr + offset,
                       g_modem_cold_patch_info.ccore_vir_addr + offset + size);
    g_modem_cold_patch_info.ccore_offset += size;
    if (ret) {
        tloge("%s, soc_type = %d,memcpy_s error: ret=[%d] error.\n", __func__, g_modem_cold_patch_info.soc_type, ret);
        return 0;
    }
    return size;
}

UINT32 hisi_secboot_splicing_modem_img(UINT32 SoC_Type, struct secboot_splicing_info_s *splicing_info)
{
    struct secboot_splicing_info_s vir_spli_info;
    UINT32 ret;

    if ((splicing_info->image_size == 0) || (splicing_info->patch_size == 0) || (splicing_info->splicing_size == 0)) {
        tloge(
            "%s, no need to splicing img, soc_type = %d, image_size = 0x%x, patch_size = 0x%x, splicing_size = 0x%x.\n",
            __func__, SoC_Type, splicing_info->image_size, splicing_info->patch_size, splicing_info->splicing_size);
        return SECBOOT_RET_MODEM_SPLICING_PARAM_INVALID;
    }

    if (sre_mmap(splicing_info->image_addr, splicing_info->image_size, &(vir_spli_info.image_addr), secure,
                 non_cache)) {
        tloge("%s, SoC_Type:%d map data buffer addr=0x%x size=0x%x error\n", __func__, SoC_Type,
              splicing_info->image_addr, splicing_info->image_size);
        return SECBOOT_RET_INVALIED_ADDR_MAP;
    }
    v7_dma_inv_range((unsigned long)(vir_spli_info.image_addr),
                     (unsigned long)(vir_spli_info.image_addr) + splicing_info->image_size);
    g_modem_cold_patch_info.ccore_vir_addr = vir_spli_info.image_addr;
    g_modem_cold_patch_info.ccore_offset = hisi_secboot_get_aslr_offset(SoC_Type);
    if (sre_mmap(splicing_info->patch_addr, splicing_info->patch_size, &(vir_spli_info.patch_addr), secure,
                 non_cache)) {
        tloge("%s, SoC_Type:%d map data buffer addr=0x%x size=0x%x error\n", __func__, SoC_Type,
              splicing_info->patch_addr, splicing_info->patch_size);
        sre_unmap(vir_spli_info.image_addr, splicing_info->image_size);
        return SECBOOT_RET_INVALIED_ADDR_MAP;
    }
    v7_dma_inv_range((unsigned long)(vir_spli_info.patch_addr),
                     (unsigned long)(vir_spli_info.patch_addr) + splicing_info->patch_size);
    if (sre_mmap(splicing_info->splicing_addr, splicing_info->splicing_size, &(vir_spli_info.splicing_addr), secure,
                 non_cache)) {
        tloge("%s, SoC_Type:%d map data buffer addr=0x%x size=0x%x error\n", __func__, SoC_Type,
              splicing_info->splicing_addr, splicing_info->splicing_size);
        sre_unmap(vir_spli_info.image_addr, splicing_info->image_size);
        sre_unmap(vir_spli_info.patch_addr, splicing_info->patch_size);
        return SECBOOT_RET_INVALIED_ADDR_MAP;
    }
    v7_dma_inv_range((unsigned long)(vir_spli_info.splicing_addr),
                     (unsigned long)(vir_spli_info.splicing_addr) + splicing_info->splicing_size);
    ret = secure_bspatch((uint8_t *)vir_spli_info.splicing_addr, splicing_info->splicing_size,
                         (uint8_t *)vir_spli_info.patch_addr, splicing_info->patch_size,
                         hisi_secboot_copy_splicing_img_to_run_addr_call_back);
    if (ret) {
        tloge("%s, SoC_Type:%d modem cold patch fail!\n", __func__, SoC_Type);
        ret = SECBOOT_SPLICING_RET_BASE_ADDR;
        goto error;
    }

    if (hisi_secboot_get_aslr_offset(SoC_Type)) {
        hisi_secboot_copy_code_for_aslr(SoC_Type, &vir_spli_info);
    }
error:
    sre_unmap(vir_spli_info.image_addr, splicing_info->image_size);
    sre_unmap(vir_spli_info.splicing_addr, splicing_info->splicing_size);
    sre_unmap(vir_spli_info.patch_addr, splicing_info->patch_size);
    return ret;
}
#else
UINT32 hisi_secboot_splicing_modem_img(UINT32 SoC_Type, struct secboot_splicing_info_s *splicing_info)
{
    return 0;
}
#endif
