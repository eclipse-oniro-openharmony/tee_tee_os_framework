/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: platform adapter for cpu
 * Author     : m00475438
 * Create     : 2018/08/15
 */
#ifndef __PAL_CPU_PLAT_H__
#define __PAL_CPU_PLAT_H__
#include <common_define.h>

err_bsp_t pal_seceng_power_check(u32 mid, u32 ip_idx, u32 onoff);

#define PAL_PM_POWER_CONFIG(mid, ip_idx, onoff) \
	pal_seceng_power_check(mid, ip_idx, onoff)

u64 pal_virt_to_phy(const u8 *va);

err_bsp_t pal_flush_dcache(const u8 *pbuffer, u32 size);

err_bsp_t pal_invalidate_dcache(const u8 *pbuffer, u32 size);

err_bsp_t pal_clean_dcache(const u8 *pbuffer, u32 size);

#endif /* __PAL_CPU_PLAT_H__ */
