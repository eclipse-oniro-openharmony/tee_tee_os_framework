/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description : Definition of hdcp repeater functions in TEE side
 * Author : Hisilicon multimedia interface software group
 * Create : 2020-06-23
 */
#ifndef __TEE_DRV_HDMIRX_RPT_H__
#define __TEE_DRV_HDMIRX_RPT_H__

#include "tee_drv_hdmirx_struct.h"
#include "tee_drv_hdmirx_ioctl.h"
#include "hi_tee_drv_hdmitx.h"

typedef struct {
    hi_tee_drv_hdmirx_port bind_rx_port; /* bind to which rx port */
    hi_bool                is_connect; /* repeater tx is connect (HPD is high) or not */
    hi_tee_drv_hdmitx_hdcp_status hdcp_status; /* hdcp authentication status */
    hi_bool                       downstream_ready; /* downstream is ready */
    hi_tee_drv_hdmitx_hdcp14_downstream_info hdcp14_info; /* ksv list */
    hi_tee_drv_hdmitx_hdcp2x_downstream_info hdcp2x_info; /* recvid list */
} tee_hdmirx_rpt_tx_ctx;

typedef struct {
    hi_bool is_rpt; /* current rx port is repeater or not (user set) */
    /*
     * current repeater rx has how many transmitters.
     * this value will be changed when tx plug-in and plug-out.
     */
    hi_bool request_reauth;
    hi_bool user_map[HI_TEE_DRV_HDMITX_ID_1 + 1];
    hi_bool cur_map[HI_TEE_DRV_HDMITX_ID_1 + 1];
    hi_tee_drv_hdmirx_hdcp_type hdcp_type;  /* rx hdcp type */
    hi_tee_drv_hdmitx_hdcp_stream_id streamtype;
    hi_tee_drv_hdmitx_hdcp14_downstream_info hdcp14_info; /* the final ksv list (tx0 and tx1) */
    hi_tee_drv_hdmitx_hdcp2x_downstream_info hdcp2x_info; /* the final recvid list (tx0 and tx1) */
} tee_hdmirx_rpt_rx_ctx;

typedef struct {
    tee_hdmirx_rpt_tx_ctx tx[HI_TEE_DRV_HDMITX_ID_1 + 1]; /* repeater tx infomation and status, max support 2 tx */
    tee_hdmirx_rpt_rx_ctx rx[HI_TEE_DRV_HDMIRX_PORT_MAX]; /* repeater rx infomation and status */
} tee_hdmirx_rpt_ctx;

hi_s32 tee_drv_hdmirx_rpt_init(hi_void);
hi_void tee_drv_hdmirx_rpt_deinit(hi_void);
hi_s32 tee_drv_hdmirx_rpt_set_map(hi_tee_drv_hdmirx_port port, hi_tee_drv_hdmitx_id id);
hi_s32 tee_drv_hdmirx_rpt_set_unmap(hi_tee_drv_hdmirx_port port, hi_tee_drv_hdmitx_id id);
hi_s32 tee_drv_hdmirx_rpt_set_downstream_info(hi_tee_drv_hdmirx_port port);
hi_s32 tee_drv_hdmirx_rpt_get_map(hi_tee_drv_hdmirx_port port, tee_hdmirx_rpt_map *map);

#endif

