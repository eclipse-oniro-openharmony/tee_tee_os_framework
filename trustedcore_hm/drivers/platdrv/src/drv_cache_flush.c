/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: wrapper the cache flush function for driver
 * Create: 2020-03
 */
#include <stdio.h>
#include <stdarg.h>
#include "drv_cache_flush.h"

/*
 * CODEREVIEW CHECKLIST
 * CALLER: CC_PalDmaBufferUnmap, zstd_inflate_image
 * ARG: start: caller ensure valid
 *        end: caller ensure valid
 */
void v7_dma_inv_range(unsigned long start, unsigned long end)
{
    /* Keep this function for thirdparty driver comatibilty */
    dma_inv_range(start, end);
}

/*
 * CODEREVIEW CHECKLIST
 * CALLER: CC_PalDmaBufferMap, ivp_load_section, process_isp_info_succ,
 *            zstd_inflate_image, process_clean_addr, secboot_copy_vrl_data,
 *            secboot_soc_verification, buffer_data_clean, sion_free,
 *            terminateSecureContentPath,
 *            fr_flush_cache, release_SecureContentMem, SECURE_FlushCache
 * ARG: start: caller ensure valid
 *        end: caller ensure valid
 */
void v7_dma_flush_range(unsigned long start, unsigned long end)
{
    /* Keep this function for thirdparty driver comatibilty */
    dma_flush_range(start, end);
}
