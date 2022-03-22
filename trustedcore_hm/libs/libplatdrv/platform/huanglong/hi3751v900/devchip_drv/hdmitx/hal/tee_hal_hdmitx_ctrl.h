/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hdmi hal level ctrl head file.
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-06-30
 */

#ifndef __TEE_HAL_HDMITX_CTRL_H__
#define __TEE_HAL_HDMITX_CTRL_H__

#include "hi_type_dev.h"

struct tee_hdmitx;

struct tee_ctrl_hal_ops {
    hi_void (*set_base_addr)(struct tee_hdmitx *tee);
    hi_bool (*get_hpd)(struct tee_hdmitx *tee);
    hi_bool (*get_rsen)(struct tee_hdmitx *tee);
    hi_bool (*get_phy_is_on)(struct tee_hdmitx *tee);
    hi_bool (*get_mcu_rst)(struct tee_hdmitx *tee);
};

struct tee_ctrl_hal_ops *tee_hal_hdmitx_ctrl_get_ops(hi_void);

#endif /* __TEE_HAL_HDMITX_CTRL_H__ */

