/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hdmitx timer & intterupt system head file.
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-08
 */

#ifndef __TEE_DRV_HDMITX_SYS_H__
#define __TEE_DRV_HDMITX_SYS_H__

#include "hi_type_dev.h"

struct tee_hdmitx;

hi_void tee_drv_hdmitx_sys_timer_init(struct tee_hdmitx *tee);

hi_void tee_drv_hdmitx_sys_timer_deinit(struct tee_hdmitx *tee);

hi_void tee_drv_hdmitx_sys_irq_enable(struct tee_hdmitx *tee, hi_bool enable);

hi_void tee_drv_hdmitx_sys_irq_init(struct tee_hdmitx *tee);

hi_void tee_drv_hdmitx_sys_irq_deinit(struct tee_hdmitx *tee);

#endif /* __TEE_DRV_HDMITX_SYS_H__ */
