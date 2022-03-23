/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definitions of ctrl functions, enumeration, and structures
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-03-09
 */
#ifndef __TEE_DRV_HDMIRX_CTRL_H__
#define __TEE_DRV_HDMIRX_CTRL_H__

#include "hi_type_dev.h"

hi_bool tee_drv_hdmirx_get_licence(hi_void);
hi_void tee_drv_hdmirx_ctrl_init(hi_void);
hi_void tee_drv_hdmirx_crg_init(hi_void);
hi_void tee_drv_hdmirx_crg_deinit(hi_void);

#endif
