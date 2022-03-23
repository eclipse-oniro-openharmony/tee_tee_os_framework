/*
 * hisilicon MODEM process, process_modem_info.c
 * Copyright (c) 2013 Hisilicon Technologies CO., Ltd.
 */
#include <sre_typedef.h>
#include "tee_log.h"
#include <mem_page_ops.h>
#include <drv_cache_flush.h> // v7_dma_flush_range
#include <register_ops.h>
#include "bsp_secboot_adp.h"
#include "secboot.h"
#include <securec.h>
#include "crys_rnd.h"
#include "process_modem_info.h"
#include <platform.h>

#ifdef CONFIG_MODEM_BALONG_ASLR

UINT32 hisi_secboot_get_aslr_offset(UINT32 SoC_Type)
{
    struct aslr_sec_param *aslr_sec_param = NULL;

    aslr_sec_param = hisi_secboot_get_aslr_sec_param_st();
    if (aslr_sec_param == NULL) {
        tloge("%s, fail to get aslr sec param.\n", __func__);
        return 0;
    }
    if (SoC_Type == MODEM) {
        return aslr_sec_param->image_offset;
    } else {
        return 0;
    }
}

void hisi_secboot_copy_code_for_aslr(UINT32 SoC_Type, struct secboot_splicing_info_s *virt_splicing_info)
{
    struct aslr_sec_param *aslr_sec_param = NULL;

    aslr_sec_param = hisi_secboot_get_aslr_sec_param_st();
    if (aslr_sec_param == NULL) {
        tloge("%s, fail to get aslr sec param.\n", __func__);
        return;
    }

    if (SoC_Type == MODEM) {
        if (memmove_s((uint8_t *)(uintptr_t)(virt_splicing_info->image_addr), MODEM_REL_COPY_CODE_SIZE,
                      (uint8_t *)(uintptr_t)(virt_splicing_info->image_addr + aslr_sec_param->image_offset),
                      MODEM_REL_COPY_CODE_SIZE)) {
            tloge("%s, memmove_s failed.\n", __func__);
            return;
        }
        writel(aslr_sec_param->image_offset, virt_splicing_info->image_addr + MODEM_IMAGE_OFFSET);
        writel(aslr_sec_param->stack_guard, virt_splicing_info->image_addr + MODEM_STACK_GUARD_OFFSET);
        writel(aslr_sec_param->heap_offset, virt_splicing_info->image_addr + MODEM_MEM_PT_OFFSET);
        v7_dma_flush_range(virt_splicing_info->image_addr, virt_splicing_info->image_addr + MODEM_REL_COPY_CODE_SIZE);
        (void)memset_s(aslr_sec_param, sizeof(struct aslr_sec_param), 0, sizeof(struct aslr_sec_param));
    }
}
#else
UINT32 hisi_secboot_get_aslr_offset(UINT32 SoC_Type)
{
    return 0;
}
void hisi_secboot_copy_code_for_aslr(UINT32 SoC_Type, struct secboot_splicing_info_s *virt_splicing_info)
{
    return;
}
#endif
