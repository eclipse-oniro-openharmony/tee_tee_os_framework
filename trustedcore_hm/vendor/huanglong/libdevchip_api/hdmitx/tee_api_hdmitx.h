/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description : hdmitx api head file.
 * Author : Hisilicon multimedia interface software group
 * Created : 2020-01-08
 */

#ifndef __TEE_API_HDMI_H__
#define __TEE_API_HDMI_H__

#include "hi_tee_hal.h"
#include "hi_log.h"
#include "tee_drv_ioctl_hdmitx.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

hi_s32 tee_api_hdmitx_ioctl(unsigned int cmd, struct tee_hdmitx_ioctl *data);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __TEE_API_HDMI_H__ */
