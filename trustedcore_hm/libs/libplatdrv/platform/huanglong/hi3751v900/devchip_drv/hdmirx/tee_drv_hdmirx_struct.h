/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definitions of common functions, enumeration, and structures
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-20
 */
#ifndef __TEE_DRV_HDMIRX_STRUCT_H__
#define __TEE_DRV_HDMIRX_STRUCT_H__

#include "hi_type_dev.h"

typedef enum {
    HI_TEE_DRV_HDMIRX_PORT0,
    HI_TEE_DRV_HDMIRX_PORT1,
    HI_TEE_DRV_HDMIRX_PORT2,
    HI_TEE_DRV_HDMIRX_PORT3,
    HI_TEE_DRV_HDMIRX_PORT_MAX
} hi_tee_drv_hdmirx_port;

typedef enum {
    HI_TEE_DRV_HDMIRX_HDCPTYPE_14,
    HI_TEE_DRV_HDMIRX_HDCPTYPE_22,
    HI_TEE_DRV_HDMIRX_HDCPTYPE_UNKNOWN,
    HI_TEE_DRV_HDMIRX_HDCPTYPE_MAX
} hi_tee_drv_hdmirx_hdcp_type;

#endif

