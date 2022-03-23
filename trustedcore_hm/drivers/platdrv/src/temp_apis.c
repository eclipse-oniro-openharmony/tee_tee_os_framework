/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: temp apis for fit platform
 * Create: 2020-06-22
 */

#include <stdio.h>
#include <stdint.h>
#include <types.h>
#include <sre_typedef.h>
#include <hifi.h>
#include <hisi_isp.h>
#include <ivp.h>
#include <sec_region_ops.h>
#include <dynion.h>

uint32_t __attribute__((weak)) get_hifi_image_size(uint32_t *image_size)
{
    (void)image_size;
    return 0;
}

#ifndef TEMP_API_WITHOUT_ISP
uint32_t __attribute__((weak)) get_isp_img_size(void)
{
    return 0;
}

int32_t __attribute__((weak)) hisi_isp_reset(void)
{
    return 0;
}

int32_t __attribute__((weak)) hisi_isp_disreset(unsigned int remapddr)
{
    (void)remapddr;
    return 0;
}

uint32_t __attribute__((weak)) get_isp_cma_size(void)
{
    return 0;
}

uint32_t __attribute__((weak)) get_isp_baseaddr(void)
{
    return 0;
}
#endif

int32_t __attribute__((weak)) ddr_sec_cfg_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
    (void)start_addr;
    (void)end_addr;
    (void)feature_id;
    return 0;
}

int32_t __attribute__((weak)) ddr_sec_cfg(struct sglist *sg, int32_t feature_id, int32_t ddr_cfg_type)
{
    (void)sg;
    (void)feature_id;
    (void)ddr_cfg_type;
    return 0;
}

int32_t __attribute__((weak)) ddr_sec_clean_for_feature(u64 start_addr, u64 end_addr, enum SEC_FEATURE feature_id)
{
    (void)start_addr;
    (void)end_addr;
    (void)feature_id;
    return 0;
}

uint32_t __attribute__((weak)) get_ivp_img_size(void)
{
    return 0;
}

uint32_t __attribute__((weak)) get_hifi_cma_size(void)
{
    return 0;
}

uint32_t __attribute__((weak)) get_ivp_cma_size(void)
{
    return 0;
}

int32_t __attribute__((weak)) load_ivp_image(uint32_t fw_addr)
{
    (void)fw_addr;
    return 0;
}

uint32_t __attribute__((weak)) prepare_reload_hifi(void)
{
    return 0;
}

uint32_t __attribute__((weak)) dump_cma_text(const void *img_buf)
{
    (void)img_buf;
    return 0;
}

uint32_t __attribute__((weak)) load_hifi_image(const void *img_buf)
{
    (void)img_buf;
    return 0;
}
