/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Implementation of hdcp repeater functions in TEE side
 * Author: Hisilicon multimedia interface software group
 * Create: 2020-04-22
 */
#include "tee_drv_hdmirx_rpt.h"
#include "hi_tee_drv_os_hal.h"
#include "tee_drv_hdmirx_comm.h"
#include "tee_hal_hdmirx_hdcp.h"

#define get_rpt_ctx() g_rpt_ctx
#define BIG_ENDIAN    HI_TRUE
#define LITTLE_ENDIAN HI_FALSE

#define TEE_HDMIRX0_PWD_IRQ_NUM  (149 + 32)
#define TEE_HDMIRX1_PWD_IEQ_NUM  (150 + 32)

#define TEE_HDCP14_DEPTH_MAX 7
#define TEE_HDCP2X_DEPTH_MAX 4

tee_hdmirx_rpt_ctx *g_rpt_ctx = HI_NULL;
hi_tee_drv_hdmitx_callback g_rpt_callback;

static hi_void rpt_downstream_1x_info_chk(hi_tee_drv_hdmitx_hdcp14_downstream_info *out)
{
    hi_log_info("out->depth = %d\n", out->depth);
    hi_log_info("out->dev_cnt = %d\n", out->dev_cnt);

    out->max_devs_exceeded = (out->dev_cnt > HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) ? HI_TRUE : HI_FALSE;
    out->dev_cnt = (out->dev_cnt > HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) ?
        HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX : out->dev_cnt;

    out->depth++;
    out->depth = (out->depth > TEE_HDCP14_DEPTH_MAX) ? TEE_HDCP14_DEPTH_MAX : out->depth;
    out->max_cascade_exceeded = (out->depth > TEE_HDCP14_DEPTH_MAX) ? HI_TRUE : HI_FALSE;
    out->downstream_is_rpt = HI_TRUE;
}

static hi_void rpt_downstream_info_copy(hi_u8 *out, const hi_u8 *in, hi_bool big_endian)
{
    hi_u32 i;

    if (big_endian == HI_FALSE) {
        for (i = 0; i < HI_TEE_DRV_HDMITX_HDCP_RECVID; i++) {
            *(out + i) = *(in + i);
        }
    } else {
        for (i = 0; i < HI_TEE_DRV_HDMITX_HDCP_RECVID; i++) {
            *(out + i) = *(in + HI_TEE_DRV_HDMITX_HDCP_RECVID - i - 1);
        }
    }
}

static hi_void rpt_downstream_info_14to14(const hi_tee_drv_hdmitx_hdcp14_downstream_info *in,
                                          hi_tee_drv_hdmitx_hdcp14_downstream_info *out)
{
    hi_u8 i, j, tmp;

    hi_log_info("downstream_is_rpt %d\n", in->downstream_is_rpt);

    /* downstream is a repeater */
    if (in->downstream_is_rpt == HI_TRUE) {
        i = out->dev_cnt;  /* start addr */
        tmp = out->dev_cnt + in->dev_cnt + 1; /* downstream cnt and repeater tx */
        out->dev_cnt = tmp; /* all device count */
        if (tmp <= HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) {
            tmp = in->dev_cnt; /* tmp: how many bksv should be copy */
        } else {
            tmp = HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX - out->dev_cnt;
        }

        /* copy the downstream bksv list */
        for (j = 0; j < tmp && i < HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX; i++, j++) {
            rpt_downstream_info_copy(out->bksv_list[i], in->bksv_list[j], LITTLE_ENDIAN);
        }
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) {
            rpt_downstream_info_copy(out->bksv_list[i], in->bksv, LITTLE_ENDIAN); /* copy the bksv */
        }
    } else { /* downstream is a receiver */
        out->dev_cnt++;
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) {
            rpt_downstream_info_copy(out->bksv_list[out->dev_cnt - 1], in->bksv, LITTLE_ENDIAN);
        }
    }
    rpt_downstream_1x_info_chk(out);
}

static hi_void rpt_downstream_info_2xto14(const hi_tee_drv_hdmitx_hdcp2x_downstream_info *in,
                                          hi_tee_drv_hdmitx_hdcp14_downstream_info *out)
{
    hi_u8 i, j, tmp;

    hi_log_info("downstream_is_rpt %d\n", in->downstream_is_rpt);

    if (in->downstream_is_rpt == HI_TRUE) {
        i = out->dev_cnt;  /* start addr */
        tmp = out->dev_cnt + in->dev_cnt + 1; /* downstream cnt and repeater tx */
        out->dev_cnt = tmp; /* all device count */
        if (tmp <= HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) {
            tmp = in->dev_cnt; /* tmp: how many bksv should be copy */
        } else {
            tmp = HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX - out->dev_cnt;
        }

        for (j = 0; j < tmp && i < HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX; i++, j++) { /* copy the downstream bksv list */
            rpt_downstream_info_copy(out->bksv_list[i], in->recvid_list[j], BIG_ENDIAN);
        }
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) {
            rpt_downstream_info_copy(out->bksv_list[i], in->recvid, BIG_ENDIAN);
        }
    } else {
        out->dev_cnt++;
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_BKSV_LIST_MAX) {
            rpt_downstream_info_copy(out->bksv_list[out->dev_cnt - 1], in->recvid, BIG_ENDIAN);
        }
    }
    rpt_downstream_1x_info_chk(out);
}

static hi_void rpt_downstream_2x_info_chk(hi_tee_drv_hdmitx_hdcp2x_downstream_info *out)
{
    hi_log_info("out->depth = %d\n", out->depth);
    hi_log_info("out->dev_cnt = %d\n", out->dev_cnt);

    out->max_devs_exceeded = (out->dev_cnt > HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) ? HI_TRUE : HI_FALSE;
    out->dev_cnt = (out->dev_cnt > HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) ?
        HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX : out->dev_cnt;

    out->depth++;
    out->depth = (out->depth > TEE_HDCP2X_DEPTH_MAX) ? TEE_HDCP2X_DEPTH_MAX : out->depth;
    out->max_cascade_exceeded = (out->depth > TEE_HDCP2X_DEPTH_MAX) ? HI_TRUE : HI_FALSE;
    out->downstream_is_rpt = HI_TRUE;
}

static hi_void rpt_downstream_info_2xto2x(const hi_tee_drv_hdmitx_hdcp2x_downstream_info *in,
                                          hi_tee_drv_hdmitx_hdcp2x_downstream_info *out)
{
    hi_u8 i, j, tmp;

    hi_log_info("downstream_is_rpt %d\n", in->downstream_is_rpt);

    if (in->downstream_is_rpt == HI_TRUE) {
        i = out->dev_cnt;  /* start addr */
        tmp = out->dev_cnt + in->dev_cnt + 1; /* downstream cnt and repeater tx */
        out->dev_cnt = tmp; /* all device count */
        if (tmp <= HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) {
            tmp = in->dev_cnt; /* tmp: how many recvid should be copy */
        } else {
            tmp = HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX - out->dev_cnt;
        }

        /* copy the downstream recvid list */
        for (j = 0; j < tmp && i < HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX; i++, j++) {
            rpt_downstream_info_copy(out->recvid_list[i], in->recvid_list[j], LITTLE_ENDIAN);
        }
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) {
            rpt_downstream_info_copy(out->recvid_list[i], in->recvid, LITTLE_ENDIAN); /* copy the recvid */
        }
    } else {
        out->dev_cnt++;
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) {
            rpt_downstream_info_copy(out->recvid_list[out->dev_cnt - 1], in->recvid, LITTLE_ENDIAN);
        }
    }
    rpt_downstream_2x_info_chk(out);
}

static hi_void rpt_downstream_info_14to2x(const hi_tee_drv_hdmitx_hdcp14_downstream_info *in,
                                          hi_tee_drv_hdmitx_hdcp2x_downstream_info *out)
{
    hi_u8 i, j, tmp;

    hi_log_info("downstream_is_rpt %d\n", in->downstream_is_rpt);

    if (in->downstream_is_rpt == HI_TRUE) {
        i = out->dev_cnt;  /* start addr */
        tmp = out->dev_cnt + in->dev_cnt + 1; /* downstream cnt and repeater tx */
        out->dev_cnt = tmp; /* all device count */
        if (tmp <= HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) {
            tmp = in->dev_cnt; /* tmp: how many recvid should be copy */
        } else {
            tmp = HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX - out->dev_cnt;
        }

        /* copy the downstream bksv_list list */
        for (j = 0; j < tmp && i < HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX; i++, j++) {
            rpt_downstream_info_copy(out->recvid_list[i], in->bksv_list[j], BIG_ENDIAN);
        }
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) {
            rpt_downstream_info_copy(out->recvid_list[i], in->bksv, BIG_ENDIAN); /* copy the bksv */
        }
    } else {
        out->dev_cnt++;
        if (out->dev_cnt <= HI_TEE_DRV_HDMITX_HDCP_RECVID_LIST_MAX) {
            rpt_downstream_info_copy(out->recvid_list[out->dev_cnt - 1], in->bksv, LITTLE_ENDIAN);
        }
    }
    rpt_downstream_2x_info_chk(out);
}

static hi_s32 rpt_downstream_info_process(hi_tee_drv_hdmirx_port port)
{
    hi_u32 i;
    tee_hdmirx_rpt_ctx *rpt_ctx = get_rpt_ctx();

    /* all mapped and active tx's downstream info should be proceed */
    for (i = 0; i <= HI_TEE_DRV_HDMITX_ID_1; i++) {
        if (rpt_ctx->tx[i].downstream_ready == HI_FALSE) {
            continue;
        }
        hi_log_info("rx hdcp type %d\n", rpt_ctx->rx[port].hdcp_type);
        hi_log_info("tx hdcp ver  %d\n", rpt_ctx->tx[i].hdcp_status.work_version); /* tx ready before geted */
        if (rpt_ctx->rx[port].hdcp_type == HI_TEE_DRV_HDMIRX_HDCPTYPE_14) {
            if (rpt_ctx->tx[i].hdcp_status.work_version == HI_TEE_DRV_HDMITX_HDCP_VERSION_1X) {
                rpt_downstream_info_14to14(&rpt_ctx->tx[i].hdcp14_info, &rpt_ctx->rx[port].hdcp14_info);
            } else if (rpt_ctx->tx[i].hdcp_status.work_version == HI_TEE_DRV_HDMITX_HDCP_VERSION_2X) {
                rpt_downstream_info_2xto14(&rpt_ctx->tx[i].hdcp2x_info, &rpt_ctx->rx[port].hdcp14_info);
            }
        } else if (rpt_ctx->rx[port].hdcp_type == HI_TEE_DRV_HDMIRX_HDCPTYPE_22) {
            if (rpt_ctx->tx[i].hdcp_status.work_version == HI_TEE_DRV_HDMITX_HDCP_VERSION_2X) {
                rpt_downstream_info_2xto2x(&rpt_ctx->tx[i].hdcp2x_info, &rpt_ctx->rx[port].hdcp2x_info);
            } else if (rpt_ctx->tx[i].hdcp_status.work_version == HI_TEE_DRV_HDMITX_HDCP_VERSION_1X) {
                rpt_downstream_info_14to2x(&rpt_ctx->tx[i].hdcp14_info, &rpt_ctx->rx[port].hdcp2x_info);
            }
        }
    }

    return (i == HI_TEE_DRV_HDMITX_ID_1 + 1) ? HI_FAILURE : HI_SUCCESS;
}

static hi_void rpt_start(hi_tee_drv_hdmirx_port port)
{
    tee_hdmirx_rpt_ctx *rpt_ctx = get_rpt_ctx();
    tee_hdmirx_hdcp14_bstatus bstatus;
    tee_hdmirx_hdcp2x_rxinfo rxinfo;
    hi_u32 len1x, len2x;

    hi_log_info("rx hdcp type %d \n", rpt_ctx->rx[port].hdcp_type);

    if (rpt_ctx->rx[port].hdcp_type == HI_TEE_DRV_HDMIRX_HDCPTYPE_14) {
        bstatus.depth = rpt_ctx->rx[port].hdcp14_info.depth;
        bstatus.device_count = rpt_ctx->rx[port].hdcp14_info.dev_cnt;
        bstatus.max_devs_exceeded = rpt_ctx->rx[port].hdcp14_info.max_devs_exceeded;
        bstatus.max_cascade_exceeded = rpt_ctx->rx[port].hdcp14_info.max_cascade_exceeded;
        len1x = rpt_ctx->rx[port].hdcp14_info.dev_cnt * HI_TEE_DRV_HDMITX_HDCP_BKSV;

        tee_hal_hdmirx_hdcp14_set_rpt_bstatus(port, &bstatus);
        tee_hal_hdmirx_hdcp14_set_rpt_bksv_list(port, (hi_u8 *)rpt_ctx->rx[port].hdcp14_info.bksv_list, len1x);
        tee_hal_hdmirx_hdcp14_start_rpt_sha1(port);
        hi_log_info("rpt start sha1 ok\n");
    } else if (rpt_ctx->rx[port].hdcp_type == HI_TEE_DRV_HDMIRX_HDCPTYPE_22) {
        rxinfo.depth = rpt_ctx->rx[port].hdcp2x_info.depth;
        rxinfo.device_count = rpt_ctx->rx[port].hdcp2x_info.dev_cnt;
        rxinfo.max_devs_exceeded = rpt_ctx->rx[port].hdcp2x_info.max_devs_exceeded;
        rxinfo.max_cascade_exceeded = rpt_ctx->rx[port].hdcp2x_info.max_cascade_exceeded;
        rxinfo.hdcp2_0_repeater_downstream = rpt_ctx->rx[port].hdcp2x_info.hdcp20_repeater_downstream;
        rxinfo.hdcp1_device_downstream = rpt_ctx->rx[port].hdcp2x_info.hdcp1x_device_downstream;
        len2x = rpt_ctx->rx[port].hdcp2x_info.dev_cnt * HI_TEE_DRV_HDMITX_HDCP_RECVID;

        tee_hal_hdmirx_hdcp2x_set_rpt_rxinfo(port, &rxinfo);
        tee_hal_hdmirx_hdcp2x_set_rpt_rcvid_list(port, (hi_u8 *)rpt_ctx->rx[port].hdcp2x_info.recvid_list, len2x);
        tee_hal_hdmirx_hdcp2x_set_rpt_irq(port, TEE_HDMIRX_HDCP2X_RCVID_LIST_READY);
        hi_log_info("rpt recvid ready\n");
    } else {
        hi_log_err("rx hdcp type %d is invalid!\n", rpt_ctx->rx[port].hdcp_type);
    }
}

static hi_bool rpt_downstream_ready(hi_tee_drv_hdmirx_port port)
{
    tee_hdmirx_rpt_ctx *rpt_ctx = get_rpt_ctx();
    hi_u32 i;

    /*
     * do not check tx auth status
     * maybe this port mapped one or two tx
     */
    for (i = 0; i <= HI_TEE_DRV_HDMITX_ID_1; i++) {
        if (rpt_ctx->tx[i].bind_rx_port != port) {
            continue;
        }
        if (rpt_ctx->tx[i].is_connect == HI_FALSE) {
            continue;
        }
        if (rpt_ctx->tx[i].downstream_ready == HI_FALSE) {
            return HI_FALSE;
        }
    }
    return (i == HI_TEE_DRV_HDMITX_ID_1 + 1) ? HI_FALSE : HI_TRUE;
}

hi_s32 tee_drv_hdmirx_rpt_set_downstream_info(hi_tee_drv_hdmirx_port port)
{
    hi_s32 ret;
    tee_hdmirx_rpt_ctx *rpt_ctx = HI_NULL;

    if (port >= HI_TEE_DRV_HDMIRX_PORT_MAX) {
        hi_log_err("port(port) is invalid\n", port);
        return HI_FAILURE;
    }
    rpt_ctx = get_rpt_ctx();
    if (rpt_ctx == HI_NULL) {
        hi_log_err("rpt ctx null pointer\n");
        return HI_FAILURE;
    }

    /* convert bksv and recvid */
    if (rpt_downstream_ready(port) == HI_FALSE) {
        return HI_FAILURE;
    }

    rpt_ctx->rx[port].hdcp_type = tee_hal_hdcp_check_type(port);
    ret = rpt_downstream_info_process(port);
    if (ret != HI_SUCCESS) {
        hi_log_err("call rpt_downstream_info_process failed\n");
        return HI_FAILURE;
    }
    rpt_start(port);

    return HI_SUCCESS;
}

static hi_void rpt_set_rpt_caps(hi_tee_drv_hdmirx_port port, hi_bool is_rpt)
{
    tee_hal_hdmirx_hdcp14_set_rpt_bcaps(port, is_rpt);
    tee_hal_hdmirx_hdcp2x_set_rpt_rxcaps(port, is_rpt);
    tee_hal_hdmirx_hdcp2x_set_rpt_irq(port, TEE_HDMIRX_HDCP2X_REPEATER_CHANGE);
}

static hi_void rpt_plugin_process(hi_tee_drv_hdmitx_id id)
{
    tee_hdmirx_rpt_ctx *rpt_ctx = get_rpt_ctx();
    hi_tee_drv_hdmirx_port port;

    rpt_ctx->tx[id].is_connect = HI_TRUE;

    port = rpt_ctx->tx[id].bind_rx_port;
    rpt_ctx->rx[port].cur_map[id] = HI_TRUE;
}

static hi_void rpt_plugout_proccess(hi_tee_drv_hdmitx_id id)
{
    tee_hdmirx_rpt_ctx *rpt_ctx = get_rpt_ctx();
    hi_tee_drv_hdmirx_port port;

    rpt_ctx->tx[id].is_connect = HI_FALSE;
    rpt_ctx->tx[id].downstream_ready = HI_FALSE;

    port = rpt_ctx->tx[id].bind_rx_port;
    rpt_ctx->rx[port].cur_map[id] = HI_FALSE;
    /* if user unmap all device, do not trigger re-auth */
    if (rpt_ctx->rx[port].is_rpt == HI_FALSE) {
        return;
    }
    /* it should be reauth when any downstream device plugin or plugout */
    rpt_ctx->rx[port].request_reauth = HI_TRUE;
}

static hi_s32 rpt_get_downstream_info(hi_tee_drv_hdmitx_id id)
{
    hi_s32 ret;
    tee_hdmirx_rpt_ctx *rpt_ctx = get_rpt_ctx();

    if (rpt_ctx->tx[id].is_connect == HI_FALSE) {
        hi_log_err("tx status error\n");
    }

    hi_log_info("rpt start to get downstream info\n");
    hi_tee_hdmitx_get_hdcp_status(id, &rpt_ctx->tx[id].hdcp_status);
    if (rpt_ctx->tx[id].hdcp_status.work_version == HI_TEE_DRV_HDMITX_HDCP_VERSION_1X) {
        ret = hi_tee_hdmitx_get_hdcp14_downstream_info(id, &rpt_ctx->tx[id].hdcp14_info);
        if (ret != HI_SUCCESS) {
            hi_log_err("rpt call get_hdcp1x_downstream_info failed!\n");
            return HI_FAILURE;
        }
        rpt_ctx->tx[id].downstream_ready = HI_TRUE;
    } else if (rpt_ctx->tx[id].hdcp_status.work_version == HI_TEE_DRV_HDMITX_HDCP_VERSION_2X) {
        ret = hi_tee_hdmitx_get_hdcp2x_downstream_info(id, &rpt_ctx->tx[id].hdcp2x_info);
        if (ret != HI_SUCCESS) {
            hi_log_err("rpt call get_hdcp2x_downstream_info failed!\n");
            return HI_FAILURE;
        }
        rpt_ctx->tx[id].downstream_ready = HI_TRUE;
    } else {
        hi_log_err("rpt hdcp_status.ver %d is error!\n", rpt_ctx->tx[id].hdcp_status.work_version);
    }

    return HI_SUCCESS;
}

static hi_void rpt_tx_callback(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_event event, hi_void *private_data)
{
    hi_s32 ret;
    tee_hdmirx_rpt_ctx *rpt_ctx = get_rpt_ctx();

    (hi_void)private_data;
    if (id > HI_TEE_DRV_HDMITX_ID_1) {
        hi_log_err("rpt id(%d) is invalid\n");
        return;
    }

    if (rpt_ctx->tx[id].bind_rx_port >= HI_TEE_DRV_HDMIRX_PORT_MAX) {
        hi_log_info("port(%d) is not bind or is invalid\n", rpt_ctx->tx[id].bind_rx_port);
        return;
    }

    switch (event) {
        case HI_TEE_DRV_HDMITX_EVENT_PLUG_IN:
            rpt_plugin_process(id);
            break;
        case HI_TEE_DRV_HDMITX_EVENT_PLUG_OUT:
            rpt_plugout_proccess(id);
            break;
        case HI_TEE_DRV_HDMITX_EVENT_DOWNSTREAM_INFO_READY:
            ret = rpt_get_downstream_info(id);
            if (ret == HI_FAILURE) {
                hi_log_err("hdmirx_rpt_get_downstream_info failed!\n");
            }
            break;
        case HI_TEE_DRV_HDMITX_EVENT_START_AUTH:
            break;
        default:
            break;
    }
}

hi_s32 tee_drv_hdmirx_rpt_set_map(hi_tee_drv_hdmirx_port port, hi_tee_drv_hdmitx_id id)
{
    tee_hdmirx_rpt_ctx *rpt_ctx = HI_NULL;
    hi_tee_drv_hdmitx_status tx_status = {0};

    if (port >= HI_TEE_DRV_HDMIRX_PORT_MAX || id > HI_TEE_DRV_HDMITX_ID_1) {
        hi_log_err("id(%d) or port(port) is invalid\n", id, port);
        return HI_FAILURE;
    }
    rpt_ctx = get_rpt_ctx();
    if (rpt_ctx == HI_NULL) {
        hi_log_err("rpt ctx null pointer\n");
        return HI_FAILURE;
    }

    /* check map id has been bind or not. */
    if (rpt_ctx->tx[id].bind_rx_port != HI_TEE_DRV_HDMIRX_PORT_MAX) {
        hi_log_warn("this tx(%d) has been bind to port(%d), please unbind firstly\n", id, port);
        return HI_FAILURE;
    }
    hi_tee_hdmitx_get_status(id, &tx_status);
    rpt_ctx->tx[id].bind_rx_port = port;
    rpt_ctx->tx[id].is_connect = (tx_status.hotplug == HI_TEE_DRV_HDMITX_HOTPLUG_IN) ? HI_TRUE : HI_FALSE;
    rpt_ctx->tx[id].downstream_ready = HI_FALSE;
    rpt_ctx->rx[port].user_map[id] = HI_TRUE;
    rpt_ctx->rx[port].cur_map[id] = (tx_status.hotplug == HI_TEE_DRV_HDMITX_HOTPLUG_IN) ? HI_TRUE : HI_FALSE;
    rpt_ctx->rx[port].is_rpt = HI_TRUE;

    rpt_set_rpt_caps(port, HI_TRUE);
    rpt_ctx->rx[port].request_reauth = HI_TRUE;

    return HI_SUCCESS;
}

hi_s32 tee_drv_hdmirx_rpt_set_unmap(hi_tee_drv_hdmirx_port port, hi_tee_drv_hdmitx_id id)
{
    tee_hdmirx_rpt_ctx *rpt_ctx = HI_NULL;
    hi_tee_drv_hdmirx_port real_port;
    hi_u32 i;

    if (port >= HI_TEE_DRV_HDMIRX_PORT_MAX || id > HI_TEE_DRV_HDMITX_ID_1) {
        hi_log_err("id(%d) or port(port) is invalid\n", id, port);
        return HI_FAILURE;
    }
    rpt_ctx = get_rpt_ctx();
    if (rpt_ctx == HI_NULL) {
        hi_log_err("rpt ctx null pointer\n");
        return HI_FAILURE;
    }

    if (rpt_ctx->tx[id].bind_rx_port == HI_TEE_DRV_HDMIRX_PORT_MAX) {
        hi_log_info("no tx map!\n");
        return HI_SUCCESS;
    }

    if (rpt_ctx->tx[id].bind_rx_port != port) {
        hi_log_warn("unmap port(%d) is not correct!", port);
    }
    real_port = rpt_ctx->tx[id].bind_rx_port;
    rpt_ctx->rx[real_port].user_map[id] = HI_FALSE;
    for (i = 0; i <= HI_TEE_DRV_HDMITX_ID_1; i++) {
        rpt_ctx->rx[real_port].cur_map[i] = HI_FALSE;
    }
    rpt_ctx->tx[id].bind_rx_port = HI_TEE_DRV_HDMIRX_PORT_MAX;
    rpt_ctx->tx[id].is_connect = HI_FALSE;
    rpt_ctx->tx[id].downstream_ready = HI_FALSE;

    /* if repeater is not active, set caps to false */
    for (i = 0; i <= HI_TEE_DRV_HDMITX_ID_1; i++) {
        if (rpt_ctx->tx[i].bind_rx_port == real_port) {
            break;
        }
    }
    if (i == HI_TEE_DRV_HDMITX_ID_1 + 1) {
        rpt_ctx->rx[real_port].is_rpt = HI_FALSE;
        rpt_set_rpt_caps(real_port, HI_FALSE);
    }
    rpt_ctx->rx[real_port].request_reauth = HI_TRUE;

    return HI_SUCCESS;
}

static hi_u32 hdmirx_rpt_isr(hi_void *args)
{
    tee_hdmirx_rpt_ctx *rpt_ctx = (tee_hdmirx_rpt_ctx *)args;
    hi_tee_drv_hdmitx_hdcp_stream_id streamtype;
    hi_u32 i;

    if (rpt_ctx == HI_NULL) {
        hi_log_err("rpt args null pointer!\n");
        return HI_TEE_HAL_IRQ_NONE;
    }
    /* clear irq */
    tee_hal_hdmirx_streamtype_intr_clear(HI_TEE_DRV_HDMIRX_PORT0);

    /* get receive streamtype */
    streamtype = tee_hal_hdmirx_streamtype_get(HI_TEE_DRV_HDMIRX_PORT0) ?
        HI_TEE_DRV_HDMITX_HDCP_STREAM_ID_TYPE1 : HI_TEE_DRV_HDMITX_HDCP_STREAM_ID_TYPE0;
    rpt_ctx->rx[HI_TEE_DRV_HDMIRX_PORT0].streamtype = streamtype;
    /* set streamtype id to binded Tx */
    for (i = 0; i <= HI_TEE_DRV_HDMITX_ID_1; i++) {
        if (rpt_ctx->tx[i].bind_rx_port == HI_TEE_DRV_HDMIRX_PORT0) {
            hi_tee_hdmitx_set_stream_id(i, streamtype);
        }
    }

    return HI_TEE_HAL_IRQ_HANDLED;
}

hi_s32 tee_drv_hdmirx_rpt_init(hi_void)
{
    hi_u32 i;
    hi_s32 ret;

    g_rpt_ctx = (tee_hdmirx_rpt_ctx *)hi_tee_drv_hal_malloc(sizeof(tee_hdmirx_rpt_ctx));
    if (g_rpt_ctx == HI_NULL) {
        hi_log_err("rpt malloc failed!\n");
        return HI_FAILURE;
    }
    /* param init */
    (hi_void)memset_s(g_rpt_ctx, sizeof(tee_hdmirx_rpt_ctx), 0, sizeof(tee_hdmirx_rpt_ctx));
    for (i = 0; i <= HI_TEE_DRV_HDMITX_ID_1; i++) {
        g_rpt_ctx->tx[i].bind_rx_port = HI_TEE_DRV_HDMIRX_PORT_MAX;
        hi_tee_hdmitx_set_stream_id(i, HI_TEE_DRV_HDMITX_HDCP_STREAM_ID_TYPE1);
    }

    /* register Tx callback */
    g_rpt_callback.func = rpt_tx_callback;
    g_rpt_callback.private = HI_NULL;
    ret = hi_tee_hdmitx_register_callback(HI_TEE_DRV_HDMITX_ID_0, &g_rpt_callback);
    if (ret != HI_SUCCESS) {
        hi_tee_drv_hal_free(g_rpt_ctx);
        g_rpt_ctx = HI_NULL;
        return HI_FAILURE;
    }

    /* request irq */
    ret = hi_tee_drv_hal_request_irq(TEE_HDMIRX0_PWD_IRQ_NUM, (hi_void *)hdmirx_rpt_isr, 0, g_rpt_ctx);
    if (ret != HI_SUCCESS) {
        hi_log_err("rpt request irq(%d) failed!\n", TEE_HDMIRX0_PWD_IRQ_NUM);
        hi_tee_drv_hal_free(g_rpt_ctx);
        g_rpt_ctx = HI_NULL;
        return HI_FAILURE;
    }
    tee_hal_hdmirx_streamtype_irq_en(HI_TEE_DRV_HDMIRX_PORT0, HI_TRUE); /* enable streamtype irq */

    return ret;
}

hi_void tee_drv_hdmirx_rpt_deinit(hi_void)
{
    /* unregister callback */
    hi_tee_hdmitx_unregister_callback(HI_TEE_DRV_HDMITX_ID_0, &g_rpt_callback);
    /* unregister irq */
    hi_tee_drv_hal_unregister_irq(TEE_HDMIRX0_PWD_IRQ_NUM);

    if (g_rpt_ctx != HI_NULL) {
        hi_tee_drv_hal_free(g_rpt_ctx);
    }
}

hi_s32 tee_drv_hdmirx_rpt_get_map(hi_tee_drv_hdmirx_port port, tee_hdmirx_rpt_map *map)
{
    hi_s32 ret;
    tee_hdmirx_rpt_ctx *rpt_ctx = HI_NULL;

    if (port >= HI_TEE_DRV_HDMIRX_PORT_MAX) {
        hi_log_err("port(port) is invalid\n",  port);
        return HI_FAILURE;
    }
    rpt_ctx = get_rpt_ctx();
    if (rpt_ctx == HI_NULL) {
        hi_log_err("rpt ctx null pointer\n");
        return HI_FAILURE;
    }
    map->is_rpt = rpt_ctx->rx[port].is_rpt;
    ret = memcpy_s(map->cur_map, sizeof(map->cur_map),
                   rpt_ctx->rx[port].cur_map, sizeof(rpt_ctx->rx[port].cur_map));
    if (ret != EOK) {
        hi_log_err("memcpy_s error\n");
        return HI_FAILURE;
    }
    map->request_reauth = rpt_ctx->rx[port].request_reauth;
    rpt_ctx->rx[port].request_reauth = HI_FALSE; /* clear request reauth flag */

    return HI_SUCCESS;
}


