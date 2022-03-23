/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description :Module tee system intterupt & timer for hdmitx drivers.
 * Author : Hisilicon multimedia interface software group
 * Created : 2020-06-30
 */

#include "hi_log.h"
#include "hi_tee_drv_os_hal.h"
#include "tee_drv_hdmitx.h"
#include "tee_drv_hdmitx_sys.h"
#include "tee_hal_hdmitx_hdcp2x.h"
#include "tee_hal_hdmitx_ctrl.h"

#define HDMITX_TIME_EXPIRES_50MS  (50 * 1000)
#define bit(x)                    (0x1 << (x))

/* mcu sec intr, define same name & order in MCU code */
enum hdmitx_mcu_sec_intr_type {
    INTR_TYPE_REVID_READY,
    INTR_TYPE_REVID_LIST_READY,
    INTR_TYPE_RE_AUTH_REQ,
    INTR_TYPE_AUTH_FAIL,
    INTR_TYPE_AUTH_DONE,
    INTR_TYPE_STOP_DONE,
};

struct tee_hdmitx_timer {
    hi_u32 hdmitx_cnt;
    struct tee_hdmitx *tee_ptr[TEE_HDMITX_ID_MAX];
    hi_tee_hal_timer timer;
};

static hi_u32 sys_timer_handlle(unsigned long args);

static struct tee_hdmitx_timer g_hdmitx_tm = {
    .hdmitx_cnt = 0,
    .tee_ptr[0] = HI_NULL,
    .tee_ptr[1] = HI_NULL,
    .timer = {
        .handler = sys_timer_handlle,
        .expires = HDMITX_TIME_EXPIRES_50MS,
        .data = 0,
        .timer = HI_NULL,
    },
};

static hi_u32 sys_timer_handlle(unsigned long args)
{
    hi_u32 ret, i;
    hi_bool hpd = HI_FALSE;
    enum hdmitx_event event;
    struct tee_hdmitx_timer *timer_ptr = (struct tee_hdmitx_timer *)(args);
    struct tee_hdmitx *tee = HI_NULL;

    timer_ptr = &g_hdmitx_tm;
    tee = timer_ptr->tee_ptr[0];
    for (i = 0;(tee != HI_NULL) && (i < timer_ptr->hdmitx_cnt); i++, tee++) {
        hpd = tee->ctrl_ops->get_hpd(tee);
        if ((tee->callback != HI_NULL) && (hpd != tee->timer_hpd)) {
            event = hpd ? HI_TEE_DRV_HDMITX_EVENT_PLUG_IN : HI_TEE_DRV_HDMITX_EVENT_PLUG_OUT;
            tee->callback->func(tee->dev_id, event, tee->callback->private);
            tee->timer_hpd = hpd;
        }
    }

    ret = hi_tee_drv_hal_timer_start(&timer_ptr->timer);
    if (ret) {
        hi_log_alert("hi_tee_drv_hal_timer_start fail out.timer stop.\n");
    }

    return 0;
}

hi_void tee_drv_hdmitx_sys_timer_init(struct tee_hdmitx *tee)
{
    int ret;
    struct tee_hdmitx_timer *timer_ptr = &g_hdmitx_tm;

    if (tee == HI_NULL || tee->ctrl_ops == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    if (tee->dev_id > TEE_HDMITX_ID_MAX || timer_ptr->hdmitx_cnt >= TEE_HDMITX_ID_MAX) {
        hi_log_alert("err id(%d) or exceed cnt(%d)\n", tee->dev_id, timer_ptr->hdmitx_cnt);
        return ;
    }

    if (timer_ptr->hdmitx_cnt == 0) {
        timer_ptr->timer.handler = sys_timer_handlle;
        timer_ptr->timer.expires = HDMITX_TIME_EXPIRES_50MS;
        timer_ptr->timer.data = 0;
        timer_ptr->timer.timer = HI_NULL;

        ret = hi_tee_drv_hal_timer_init(&timer_ptr->timer);
        if (ret) {
            hi_log_alert("hi_tee_drv_hal_timer_init failed\n");
            return;
        }

        ret = hi_tee_drv_hal_timer_start(&timer_ptr->timer);
        if (ret) {
            hi_log_alert("hi_tee_drv_hal_timer_start failed\n");
            goto out;
        }
    }

    timer_ptr->tee_ptr[tee->dev_id] = tee;
    tee->timer_hpd = tee->ctrl_ops->get_hpd(tee);
    timer_ptr->hdmitx_cnt++;

    return ;

out:
    ret = hi_tee_drv_hal_timer_delete(&timer_ptr->timer);
    if (ret) {
        hi_log_alert("hi_tee_drv_hal_timer_delete failed\n\n");
        hi_tee_drv_hal_sys_reset();
    }
}

hi_void tee_drv_hdmitx_sys_timer_deinit(struct tee_hdmitx *tee)
{
    hi_s32 ret;
    struct tee_hdmitx_timer *timer_ptr = &g_hdmitx_tm;

    if (tee == HI_NULL || tee->ctrl_ops == HI_NULL) {
        hi_log_alert("null ptr");
        return ;
    }

    if (tee->dev_id > TEE_HDMITX_ID_MAX || timer_ptr->tee_ptr[tee->dev_id] == HI_NULL) {
        hi_log_alert("err id(%d)\n", tee->dev_id);
        return ;
    }

    if (timer_ptr->hdmitx_cnt == 0) {
        return ;
    }

    timer_ptr->tee_ptr[tee->dev_id] = HI_NULL;
    timer_ptr->hdmitx_cnt--;

    if (timer_ptr->hdmitx_cnt == 0) {
        ret = hi_tee_drv_hal_timer_delete(&timer_ptr->timer);
        if (ret) {
            hi_log_alert("hi_tee_drv_hal_timer_delete failed\n\n");
            hi_tee_drv_hal_sys_reset();
        }
    }
}

static hi_void sys_irq_handlle(hi_void *arg)
{
    hi_u32 irq_status;
    struct tee_hdmitx *tee = (struct tee_hdmitx *)arg;

    if (arg == NULL || tee->hdcp2x_ops == HI_NULL) {
        return ;
    }

    tee_drv_hdmitx_sys_irq_enable(tee, HI_FALSE);
    tee->hdcp2x_ops->get_irq_status(tee, &irq_status);
    tee->hdcp2x_ops->clear_irq(tee, irq_status);

    if (irq_status & bit(INTR_TYPE_REVID_READY)) {
        tee->hdcp2x_ops->get_recvid(tee, tee->hdcp2x_info.ds_info.recvid,
            sizeof(tee->hdcp2x_info.ds_info.recvid));
    }

    if (irq_status & bit(INTR_TYPE_REVID_LIST_READY)) {
        tee->hdcp2x_ops->get_ds_info(tee, &tee->hdcp2x_info.ds_info);
        if ((tee->callback != HI_NULL) && tee->hdcp2x_info.ds_info.downstream_is_rpt) {
            tee->callback->func(tee->dev_id, HI_TEE_DRV_HDMITX_EVENT_DOWNSTREAM_INFO_READY,
                tee->callback->private);
        }
    }

    /* bit(INTR_TYPE_RE_AUTH_REQ) should clear hdcp2x_info, this ops do by set_mode */
    if (irq_status & bit(INTR_TYPE_AUTH_FAIL)) {
        tee->hdcp2x_info.auth_success = HI_FALSE;
        if ((tee->callback != HI_NULL) && (!tee->hdcp2x_info.ds_info.downstream_is_rpt)) {
            tee->callback->func(tee->dev_id, HI_TEE_DRV_HDMITX_EVENT_DOWNSTREAM_INFO_READY,
                tee->callback->private);
        }
    }

    if (irq_status & bit(INTR_TYPE_AUTH_DONE)) {
        tee->hdcp2x_info.auth_success = HI_TRUE;
        if ((tee->callback != HI_NULL) && (!tee->hdcp2x_info.ds_info.downstream_is_rpt)) {
            tee->callback->func(tee->dev_id, HI_TEE_DRV_HDMITX_EVENT_DOWNSTREAM_INFO_READY,
                tee->callback->private);
        }
    }

    tee_drv_hdmitx_sys_irq_enable(tee, HI_TRUE);
}

hi_void tee_drv_hdmitx_sys_irq_enable(struct tee_hdmitx *tee, hi_bool enable)
{
    if (tee == NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    tee->hdcp2x_ops->enable_irq(tee, enable);
}

hi_void tee_drv_hdmitx_sys_irq_init(struct tee_hdmitx *tee)
{
    hi_s32 ret;

    if (tee == NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    ret = hi_tee_drv_hal_request_irq(tee->sec_irq_num, (void *)sys_irq_handlle, 0, tee);
    if (ret != TEE_SUCCESS) {
        hi_log_alert("tee hdmitx[%d] irq init fail\n", tee->dev_id);
        return ;
    }
}

hi_void tee_drv_hdmitx_sys_irq_deinit(struct tee_hdmitx *tee)
{
    if (tee == NULL || tee->pwd_regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    tee_drv_hdmitx_sys_irq_enable(tee, HI_FALSE);
    hi_tee_drv_hal_unregister_irq(tee->sec_irq_num);
}

