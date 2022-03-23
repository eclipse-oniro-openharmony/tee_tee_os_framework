/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: smmu plat include
 * Author: SecurityEngine
 * Create: 2020/03/09
 */

#ifndef __PAL_SMMU_PLAT_H__
#define __PAL_SMMU_PLAT_H__
#include <pal_types.h>

typedef s32 pid_t;

/* enable tcu */
err_bsp_t pal_mmu_poweron(void);

/* disable tcu */
err_bsp_t pal_mmu_poweroff(void);

/* creat page table and map iova */
err_bsp_t pal_mmu_map(u32 buffer_id, u32 size, u32 *iova);

/* destroy page table and unmap iova */
err_bsp_t pal_mmu_unmap(u32 buffer_id, u32 size);

/* creat pte/cd for sid/ssid */
err_bsp_t pal_mmu_bind(void);

/* destroy pte/cd for sid/ssid */
err_bsp_t pal_mmu_unbind(void);

/* poweron tbu and connect tbu and tcu */
err_bsp_t pal_mmu_tbu_init(void);

/* disconnect tbu and tcu */
err_bsp_t pal_mmu_tbu_deinit(void);

/* config sid/ssid to hardware,
 * hardware use this to find ste/cd and find page table
 */
err_bsp_t pal_mmu_enable(u32 ip_idx, u32 read_en, u32 write_en, u32 is_sec);

err_bsp_t pal_mmu_disable(u32 ip_idx, u32 is_sec);

#endif
