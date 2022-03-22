/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hdmi hal level hdcp2x head file.
 * Author: Hisilicon multimedia interface software group
 * Create: 2019-11-15
 */
#ifndef __TEE_HAL_HDMITX_HDCP2X_H__
#define __TEE_HAL_HDMITX_HDCP2X_H__

#include "hi_type_dev.h"

struct tee_hdmitx;
struct hdcp2x_downstream_info;

struct tee_hdcp2x_hal_ops {
    hi_s32 (*load_mcu_code)(struct tee_hdmitx *tee);
    hi_void (*set_mode)(struct tee_hdmitx *tee);
    hi_void (*set_stream_id)(struct tee_hdmitx *tee, hi_u8 stream_id);
    hi_s32 (*verify_mcu)(struct tee_hdmitx *tee);
    hi_s32 (*get_ds_info)(struct tee_hdmitx *tee, struct hdcp2x_downstream_info *ds_info);
    hi_s32 (*get_recvid)(struct tee_hdmitx *tee, hi_u8 *data, hi_u32 size);
    hi_void (*get_irq_status)(struct tee_hdmitx *tee, hi_u32 *status);
    hi_void (*enable_irq)(struct tee_hdmitx *tee, hi_bool enable);
    hi_void (*clear_irq)(struct tee_hdmitx *tee, hi_u32 status);
};

struct tee_hdcp2x_hal_ops *tee_hal_hdmitx_hdcp2x_get_ops(hi_void);

#endif /* __TEE_HAL_HDMITX_HDCP2X_H__ */
