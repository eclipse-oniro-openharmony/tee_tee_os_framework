/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee hdcp1.x hal layer head file
 * Author: Hisilicon HDMI software group
 *  Create: 2019-01-17
 */

#ifndef __TEE_HAL_HDMITX_HDCP1X_H__
#define __TEE_HAL_HDMITX_HDCP1X_H__

#include "hi_type_dev.h"

struct tee_hdmitx;

#define HDCP1X_KSV_SIZE_5BYTES       5
#define HDCP1X_RI_SIZE_2BYTES        2
#define HDCP1X_VI_SIZE_20BYTES       20

/* Bstatus ,Rd,OFFSET 0x41,see <HDCP1.4> table 2-4 */
union hdcp1x_bstatus {
    struct {
        hi_u16 device_cnt           : 7;
        hi_u16 max_devs_exceeded    : 1;
        hi_u16 depth                : 3;
        hi_u16 max_cascade_exceeded : 1;
        hi_u16 hdmi_mode            : 1;
        hi_u16 hdmi_rsvd            : 1;
        hi_u16 rsvd                 : 2;
    } u16;
    hi_u16 word;
};

struct tee_hdcp1x_hal_ops {
    hi_void (*set_mode)(struct tee_hdmitx *tee);
    hi_s32 (*get_mode)(struct tee_hdmitx *tee);
    hi_s32 (*verify_r0)(struct tee_hdmitx *tee, hi_u8 *r0, hi_u32 size);
    hi_void (*set_b_ksv)(struct tee_hdmitx *tee, hi_u8 *bksv, hi_u32 size);
    hi_void (*set_b_ksv_list)(struct tee_hdmitx *tee, hi_u8 *bksv_l, hi_u32 buf_size, hi_u32 avail_size);
    hi_void (*set_encryption)(struct tee_hdmitx *tee, hi_bool enable);
    hi_bool (*get_encryption)(struct tee_hdmitx *tee);
    hi_void (*set_repeater)(struct tee_hdmitx *tee, hi_bool enable);
    hi_void (*set_b_vi)(struct tee_hdmitx *tee, hi_u8 *v_bi, hi_u32 size);
    hi_u16 (*get_b_status)(struct tee_hdmitx *hdmi);
};

struct tee_hdcp1x_hal_ops *tee_hal_hdmitx_hdcp1x_get_ops(hi_void);

#endif /* __TEE_HAL_HDMITX_HDCP1X_H__ */

