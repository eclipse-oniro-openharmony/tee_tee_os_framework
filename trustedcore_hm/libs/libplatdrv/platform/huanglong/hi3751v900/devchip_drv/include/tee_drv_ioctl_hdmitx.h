/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: hdmitx ioctl defination.
 * Author: Linux SDK team
 * Create: 2020/01/08
 */
#ifndef __TEE_DRV_HDMITX_IOCTL_H__
#define __TEE_DRV_HDMITX_IOCTL_H__

#include "hi_tee_module_id.h"
#include "tee_drv_common_ioctl.h"
#ifdef __cplusplus
extern "C" {
#endif

enum tee_hdmitx_cmd_id {
    HDMITX_CMD_SESSION_BASE = 0x100,
    HDMITX_CMD_SESSION_VERIFY_MCU,
    HDMITX_CMD_SESSION_SET_HDCP_MODE,
    HDMITX_CMD_SESSION_HDCP1X_SET_BKSV,
    HDMITX_CMD_SESSION_HDCP1X_ENABLE_RPT,
    HDMITX_CMD_SESSION_HDCP1X_VERIFY_R0,
    HDMITX_CMD_SESSION_HDCP1X_SET_KSVLIST,
    HDMITX_CMD_SESSION_HDCP1X_VERIFY_VI,
    HDMITX_CMD_SESSION_HDCP1X_ENABLE_ENC,
    HDMITX_CMD_SESSION_MAX,

    HDMITX_CMD_API_BASE = 0x200,
    HDMITX_CMD_API_MAX,
};

typedef struct tee_hdmitx_ioctl {
    hi_u32 hdmi_id;
    hi_u32 cmd_id;  /* see enum tee_hdmitx_cmd_id */
    hi_void *data;
    hi_u32 data_size;
} tee_hdmitx_ioctl_def;

#define HDMITX_IOCTL_CMD            _IOWR(HI_ID_HDMITX, 0x0, tee_hdmitx_ioctl_def)

#endif /* __TEE_DRV_HDMITX_IOCTL_H__ */
