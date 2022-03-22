/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definitions of ctrl functions
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-03-09
 */
#ifndef __TEE_HAL_HDMIRX_CTRL_H__
#define __TEE_HAL_HDMIRX_CTRL_H__

#include "hi_type_dev.h"

hi_u32 tee_hal_hdmirx_ctrl_get_licence(hi_void);
hi_void tee_hal_hdmirx_ctrl_crg_init(hi_void);
hi_void tee_hal_hdmirx_ctrl_crg_deinit(hi_void);

#endif
