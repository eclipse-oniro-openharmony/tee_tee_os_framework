/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hdmitx hal level io head file.
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-08
 */

#ifndef __TEE_HAL_HDMITX_IO_H__
#define __TEE_HAL_HDMITX_IO_H__

#include "hi_type_dev.h"

hi_u32 hdmi_readl(volatile hi_void *base,  hi_u32 offset);

hi_void hdmi_writel(volatile hi_void *base, hi_u32 offset, hi_u32 value);

hi_u32 hdmi_read_bits(volatile hi_void *base, hi_u32 offset, hi_u32 bit_mask);

hi_void hdmi_write_bits(volatile hi_void *base, hi_u32 offset, hi_u32 bit_mask, hi_u32 val);

#define hdmi_clr(s, r, v)       hdmi_writel((s), (r), hdmi_readl((s), (r)) & ~(v))

#define hdmi_set(s, r, v)       hdmi_writel((s), (r), hdmi_readl((s), (r)) | (v))

#define hdmi_clrset(s, r, m, v) hdmi_writel((s), (r), (hdmi_readl((s), (r)) & ~(m)) | (v))

#endif /* __TEE_HAL_HDMITX_IO_H__ */
