/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description :Module hdmitx head drivers.
 * Author : Hisilicon multimedia interface software group
 * Created : 2020-01-08
 */

#ifndef __TEE_HAL_HDMITX_H__
#define __TEE_HAL_HDMITX_H__

#include "hi_type_dev.h"
#include "hi_tee_drv_hdmitx.h"

enum tee_hdmitx_id {
    TEE_HDMITX_ID_0,
    TEE_HDMITX_ID_1,
    TEE_HDMITX_ID_MAX,
};

struct tee_hdcp14_info {
    hi_bool set_bksv;
    struct hdcp14_downstream_info ds_info;
};

struct tee_hdcp2x_info {
    hi_bool auth_success;
    struct hdcp2x_downstream_info ds_info;
};

#define TEE_HDMITX_SIZE_IO_BUF   1024

struct tee_hdmitx {
    hi_u32 dev_id;
    hi_u32 sec_irq_num;
    volatile hi_void *pwd_regs;
    volatile hi_void *aon_regs;
    volatile hi_void *phy_regs;

    hi_u8 io_buf[TEE_HDMITX_SIZE_IO_BUF];
    hi_u8 io_size;
    hi_bool timer_hpd;
    struct tee_hdcp14_info hdcp14_info;
    struct tee_hdcp2x_info hdcp2x_info;
    struct hdmitx_callback *callback;

    struct tee_ctrl_hal_ops *ctrl_ops;
    struct tee_hdcp2x_hal_ops *hdcp2x_ops;
    struct tee_hdcp1x_hal_ops *hdcp1x_ops;
};

#endif /* __TEE_HAL_HDMITX_H__ */
