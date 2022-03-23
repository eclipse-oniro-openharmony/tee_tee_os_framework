/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description : tee hdmirx ioctl definitions
 * Author : Hisilicon multimedia interface software group
 * Create : 2020-2-5
 */
#ifndef __TEE_DRV_HDMIRX_IOCTL_H__
#define __TEE_DRV_HDMIRX_IOCTL_H__

#include "hi_tee_drv_syscall_id.h"
#include "hi_type_dev.h"
#include "hi_tee_module_id.h"
#include "tee_drv_common_ioctl.h"
#include "hi_tee_drv_hdmitx.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    TEE_HDMIRX_IOCTL_CHK_MCU_CODE,
    TEE_HDMIRX_IOCTL_GET_MAP,
    TEE_HDMIRX_IOCTL_CHK_DOWNSTREAM_READY,
    TEE_HDMIRX_IOCTL_MAX
} tee_hdmirx_ioctl_cmd;

typedef struct {
    hi_bool is_rpt;
    hi_bool cur_map[HI_TEE_DRV_HDMITX_ID_1 + 1];
    hi_bool request_reauth;
} tee_hdmirx_rpt_map;

typedef struct {
    hi_u32 port;
    tee_hdmirx_rpt_map map;
} tee_hdmirx_ioctl_rpt_map;

typedef struct {
    hi_bool ready;
} tee_hdmirx_ds_ready;

typedef struct {
    hi_u32 port;
    tee_hdmirx_ds_ready downstream;
} tee_hdmirx_ioctl_ds_ready;

#define HDMIRX_IOCTL_CHK_MCU_CODE _IOWR(HI_ID_HDMIRX, TEE_HDMIRX_IOCTL_CHK_MCU_CODE, hi_u32)
#define HDMIRX_IOCTL_GET_MAP      _IOWR(HI_ID_HDMIRX, TEE_HDMIRX_IOCTL_GET_MAP, tee_hdmirx_ioctl_rpt_map)
#define HDMIRX_IOCTL_CHK_DS_READY _IOWR(HI_ID_HDMIRX, TEE_HDMIRX_IOCTL_CHK_DOWNSTREAM_READY, tee_hdmirx_ioctl_ds_ready)

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif

