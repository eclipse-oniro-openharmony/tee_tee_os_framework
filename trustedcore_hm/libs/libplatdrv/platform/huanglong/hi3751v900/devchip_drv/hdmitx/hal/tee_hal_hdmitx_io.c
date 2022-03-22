/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hdmitx hal level io src file.
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-08
 */

#include "tee_hal_hdmitx_io.h"
#include "stdint.h"

#define RIGHT_SHIFT_MAX 32

hi_u32 hdmi_readl(volatile hi_void *base, hi_u32 offset)
{
    if (base != HI_NULL) {
        return *((volatile hi_u32 *)(uintptr_t)(base + offset));
    }
    return 0;
}

hi_void hdmi_writel(volatile hi_void *base, hi_u32 offset, hi_u32 value)
{
    if (base != HI_NULL) {
        *((volatile hi_u32 *)(uintptr_t)(base + offset)) = value;
    }
    return;
}

static inline hi_u32 get_right_shift_cnt(hi_u32 bit_mask)
{
    hi_u32 i;

    for (i = 0; i < RIGHT_SHIFT_MAX; i++) {
        if (bit_mask & (1 << i)) {
            break;
        }
    }

    return i;
}

hi_u32 hdmi_read_bits(volatile hi_void *base, hi_u32 offset, hi_u32 bit_mask)
{
    hi_u32 reg_val;
    hi_u32 right_shift_cnt;

    right_shift_cnt = get_right_shift_cnt(bit_mask);
    reg_val = hdmi_readl(base, offset);
    return (reg_val & bit_mask) >> right_shift_cnt;
}

hi_void hdmi_write_bits(volatile hi_void *base, hi_u32 offset, hi_u32 bit_mask, hi_u32 val)
{
    hi_u32 shift_cnt;
    hi_u32 reg_val;

    shift_cnt = get_right_shift_cnt(bit_mask);
    reg_val = hdmi_readl(base, offset);
    reg_val &= ~bit_mask;
    reg_val |= (val << shift_cnt) & bit_mask;
    hdmi_writel(base, offset, reg_val);
}
