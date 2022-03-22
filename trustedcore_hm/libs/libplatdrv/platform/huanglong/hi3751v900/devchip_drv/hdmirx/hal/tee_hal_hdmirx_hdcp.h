/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Definitions of hdcp functions
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-01-20
 */
#ifndef __TEE_HAL_HDMIRX_HDCP_H__
#define __TEE_HAL_HDMIRX_HDCP_H__

#include "hi_type_dev.h"
#include "tee_drv_hdmirx_struct.h"

typedef enum {
    TEE_HDCP_AUTH_NONE,
    TEE_HDCP_AUTH_ING,
    TEE_HDCP_AUTH_SUCCESS,
    TEE_HDCP_AUTH_FAILED,
    TEE_HDCP_AUTH_MAX
} tee_hdmirx_hdcp_auth_status;

typedef struct {
    hi_u8 depth;
    hi_u8 device_count;
    hi_bool max_devs_exceeded;
    hi_bool max_cascade_exceeded;
} tee_hdmirx_hdcp14_bstatus;

typedef enum {
    TEE_HDMIRX_HDCP2X_REPEATER_CHANGE,
    TEE_HDMIRX_HDCP2X_RCVID_LIST_READY,
    TEE_HDMIRX_HDCP2X_RE_AUTH,
    TEE_HDMIRX_HDCP2X_MAX,
} tee_hdmirx_hdcp2x_irq;

typedef struct {
    hi_u8 depth;
    hi_u8 device_count;
    hi_bool max_devs_exceeded;
    hi_bool max_cascade_exceeded;
    hi_bool hdcp2_0_repeater_downstream;
    hi_bool hdcp1_device_downstream;
} tee_hdmirx_hdcp2x_rxinfo;

hi_void tee_hal_hdmirx_hdcp14_set_rpt_bcaps(hi_tee_drv_hdmirx_port port, hi_bool repeater);
hi_void tee_hal_hdmirx_hdcp14_set_rpt_bstatus(hi_tee_drv_hdmirx_port port, const tee_hdmirx_hdcp14_bstatus *bstatus);
hi_u32 tee_hal_hdmirx_hdcp14_set_rpt_bksv_list(hi_tee_drv_hdmirx_port port, const hi_u8 *bksv_list, hi_u8 len);
hi_void tee_hal_hdmirx_hdcp14_start_rpt_sha1(hi_tee_drv_hdmirx_port port);

hi_s32 tee_hal_hdmirx_hdcp_load_mcu(hi_tee_drv_hdmirx_port port, const hi_u32 *pram, hi_u32 max_len);
hi_s32 tee_hal_hdmirx_hdcp_check_mcu_code(hi_tee_drv_hdmirx_port port, const hi_u32 *pram, hi_u32 max_len);
hi_void tee_hal_hdmirx_hdcp2x_set_rpt_rxcaps(hi_tee_drv_hdmirx_port port, hi_bool repeater);
hi_void tee_hal_hdmirx_hdcp2x_set_rpt_irq(hi_tee_drv_hdmirx_port port, tee_hdmirx_hdcp2x_irq irq);
hi_void tee_hal_hdmirx_hdcp2x_set_rpt_rxinfo(hi_tee_drv_hdmirx_port port, const tee_hdmirx_hdcp2x_rxinfo *rxinfo);
hi_u32 tee_hal_hdmirx_hdcp2x_set_rpt_rcvid_list(hi_tee_drv_hdmirx_port port, const hi_u8 *rcvid_list, hi_u8 len);

hi_void tee_hal_hdmirx_streamtype_irq_en(hi_tee_drv_hdmirx_port port, hi_bool en);
hi_void tee_hal_hdmirx_streamtype_intr_clear(hi_tee_drv_hdmirx_port port);
hi_u32 tee_hal_hdmirx_streamtype_get(hi_tee_drv_hdmirx_port port);

tee_hdmirx_hdcp_auth_status tee_hal_hdcp_get_auth_status(hi_tee_drv_hdmirx_port port,
    hi_tee_drv_hdmirx_hdcp_type hdcp_type);
hi_tee_drv_hdmirx_hdcp_type tee_hal_hdcp_check_type(hi_tee_drv_hdmirx_port port);

#endif

