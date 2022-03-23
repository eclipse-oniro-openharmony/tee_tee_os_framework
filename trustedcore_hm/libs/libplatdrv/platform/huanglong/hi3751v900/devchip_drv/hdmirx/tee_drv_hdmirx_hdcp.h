/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definitions of hdcp functions, enumeration, and structures
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-20
 */
#ifndef __TEE_DRV_HDMIRX_HDCP_H__
#define __TEE_DRV_HDMIRX_HDCP_H__

#include "tee_drv_hdmirx_struct.h"

hi_void tee_drv_hdmirx_hdcp_init(hi_void);
hi_s32 tee_drv_hdmirx_hdcp_load_mcu_code(hi_tee_drv_hdmirx_port port);
hi_s32 tee_drv_hdmirx_hdcp_check_mcu_code(hi_tee_drv_hdmirx_port port);

#endif

