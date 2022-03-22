/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description :Module init and exit API for hdmitx drivers.
 * Author : Hisilicon multimedia interface software group
 * Created : 2020-01-08
 */

#include "hi_log.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_errcode.h"
#include "hi_tee_drv_hdmitx.h"
#include "tee_drv_hdmitx.h"
#include "tee_drv_ioctl_hdmitx.h"
#include "tee_drv_hdmitx_sys.h"
#include "tee_hal_hdmitx_hdcp1x.h"
#include "tee_hal_hdmitx_hdcp2x.h"
#include "tee_hal_hdmitx_ctrl.h"

static struct tee_hdmitx g_hdmi_tee[TEE_HDMITX_ID_MAX];

/* structure definition */
struct tee_hdmitx_ioctl_node {
    hi_u32 cmd_id;
    hi_s32(*ioctl_func)(struct tee_hdmitx_ioctl *tee_ioctl);
};

static struct tee_hdmitx *hdmitx_id_2_tee(enum tee_hdmitx_id id)
{
    if (id < TEE_HDMITX_ID_MAX) {
        return &g_hdmi_tee[id];
    }

    hi_log_alert("id=%d,too large,error!\n", id);

    return HI_NULL;
}

static hi_s32 hdmitx_verify_mcu(struct tee_hdmitx_ioctl *tee_ioctl)
{
    hi_s32 ret;
    struct tee_hdmitx *tee = HI_NULL;

    if (tee_ioctl == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    ret = tee->hdcp2x_ops->verify_mcu(tee);

    return ret;
}

static hi_s32 hdmitx_set_hdcp_mode(struct tee_hdmitx_ioctl *tee_ioctl)
{
    hi_u32 mode;
    struct tee_hdmitx *tee = HI_NULL;

    if (tee_ioctl == HI_NULL || tee_ioctl->data == NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size != sizeof(mode)) {
        hi_log_alert("err size %d\n", tee_ioctl->data_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    mode = 0;
    if (memmove_s((hi_void *)&mode, sizeof(mode), tee_ioctl->data, tee_ioctl->data_size) != EOK) {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    if (memset_s((hi_void *)&tee->hdcp14_info, sizeof(tee->hdcp14_info), 0, sizeof(tee->hdcp14_info)) != EOK) {
        hi_log_alert("err memset\n");
        return HI_FAILURE;
    }

    if (memset_s((hi_void *)&tee->hdcp2x_info, sizeof(tee->hdcp2x_info), 0, sizeof(tee->hdcp2x_info)) != EOK) {
        hi_log_alert("err memset\n");
        return HI_FAILURE;
    }

    if (mode) {
        tee->hdcp2x_ops->set_mode(tee);
        tee_drv_hdmitx_sys_irq_enable(tee, HI_TRUE);
        if (tee->callback != HI_NULL) {
            tee->callback->func(tee->dev_id, HI_TEE_DRV_HDMITX_EVENT_START_AUTH, tee->callback->private);
        }
    } else {
        tee_drv_hdmitx_sys_irq_enable(tee, HI_FALSE);
        tee->hdcp1x_ops->set_mode(tee);
    }

    return HI_SUCCESS;
}

static hi_s32 hdmitx_hdcp1x_set_b_ksv(struct tee_hdmitx_ioctl *tee_ioctl)
{
    hi_u8 bksv[HDCP1X_KSV_SIZE_5BYTES];
    struct tee_hdmitx *tee = HI_NULL;
    struct tee_hdcp14_info *info = HI_NULL;

    if (tee_ioctl == HI_NULL || tee_ioctl->data == NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size != sizeof(bksv)) {
        hi_log_alert("err size %d\n", tee_ioctl->data_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (memmove_s((hi_void *)bksv, sizeof(bksv), tee_ioctl->data, tee_ioctl->data_size) != EOK) {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    tee->hdcp1x_ops->set_b_ksv(tee, bksv, sizeof(bksv));
    info = &tee->hdcp14_info;
    info->set_bksv = HI_TRUE;
    if (memmove_s(info->ds_info.bksv, sizeof(info->ds_info.bksv), (hi_void *)bksv, sizeof(bksv)) != EOK) {
        hi_log_alert("err memmove_s\n");
        return HI_FAILURE;
    }

    if (tee->callback != HI_NULL) {
        tee->callback->func(tee->dev_id, HI_TEE_DRV_HDMITX_EVENT_START_AUTH, tee->callback->private);
    }

    if ((tee->callback != HI_NULL) && (!tee->hdcp14_info.ds_info.downstream_is_rpt)) {
        tee->callback->func(tee->dev_id, HI_TEE_DRV_HDMITX_EVENT_DOWNSTREAM_INFO_READY,
            tee->callback->private);
    }

    return HI_SUCCESS;
}

static hi_void hdmitx_hdcp1x_get_bstatus(struct tee_hdmitx *tee)
{
    union hdcp1x_bstatus bstatus;
    struct hdcp14_downstream_info *info = HI_NULL;

    if (tee == HI_NULL || tee->hdcp1x_ops == HI_NULL) {
        hi_log_alert("null ptr\n");
        return ;
    }

    bstatus.word = tee->hdcp1x_ops->get_b_status(tee);
    info = &tee->hdcp14_info.ds_info;
    info->depth = bstatus.u16.depth;
    info->dev_cnt = bstatus.u16.device_cnt;
    info->max_devs_exceeded = bstatus.u16.max_devs_exceeded;
    info->max_cascade_exceeded = bstatus.u16.max_cascade_exceeded;
}

static hi_s32 hdmitx_hdcp1x_set_b_ksv_list(struct tee_hdmitx_ioctl *tee_ioctl)
{
    struct tee_hdmitx *tee = HI_NULL;

    if (tee_ioctl == HI_NULL || tee_ioctl->data == NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size > sizeof(tee->io_buf)) {
        hi_log_alert("err size %d\n", tee_ioctl->data_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (memmove_s((hi_void *)tee->io_buf, sizeof(tee->io_buf),
        tee_ioctl->data, tee_ioctl->data_size) != EOK) {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size < sizeof(tee->io_buf) &&
        tee_ioctl->data_size <= sizeof(tee->hdcp14_info.ds_info.bksv_list)) {
        tee->io_size = tee_ioctl->data_size;
    } else {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    hdmitx_hdcp1x_get_bstatus(tee);

    tee->hdcp1x_ops->set_b_ksv_list(tee, tee->io_buf, sizeof(tee->io_buf), tee->io_size);

    if (memmove_s((hi_void *)tee->hdcp14_info.ds_info.bksv_list, sizeof(tee->hdcp14_info.ds_info.bksv_list),
        tee->io_buf, tee->io_size) != EOK) {
        hi_log_alert("err memmove_s\n");
    }

    if ((tee->callback != HI_NULL) && tee->hdcp14_info.ds_info.downstream_is_rpt) {
        tee->callback->func(tee->dev_id, HI_TEE_DRV_HDMITX_EVENT_DOWNSTREAM_INFO_READY,
            tee->callback->private);
    }

    return HI_SUCCESS;
}

static hi_s32 hdmitx_hdcp1x_verify_r0(struct tee_hdmitx_ioctl *tee_ioctl)
{
    hi_u8 b_r0[HDCP1X_RI_SIZE_2BYTES];
    struct tee_hdmitx *tee = HI_NULL;

    if (tee_ioctl == HI_NULL || tee_ioctl->data == NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size != sizeof(b_r0)) {
        hi_log_alert("err size %d\n", tee_ioctl->data_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (memmove_s((hi_void *)b_r0, sizeof(b_r0), tee_ioctl->data, tee_ioctl->data_size) != EOK) {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    return tee->hdcp1x_ops->verify_r0(tee, b_r0, sizeof(b_r0));
}


static hi_s32 hdmitx_hdcp1x_set_encryption(struct tee_hdmitx_ioctl *tee_ioctl)
{
    hi_bool enable;
    struct tee_hdmitx *tee = HI_NULL;

    if (tee_ioctl == HI_NULL || tee_ioctl->data == NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size != sizeof(enable)) {
        hi_log_alert("err size %d\n", tee_ioctl->data_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    enable = HI_FALSE;

    if (memmove_s((hi_void *)&enable, sizeof(enable), tee_ioctl->data, tee_ioctl->data_size) != EOK) {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    tee->hdcp1x_ops->set_encryption(tee, enable);
    tee->hdcp14_info.set_bksv = enable;
    return HI_SUCCESS;
}

static hi_s32 hdmitx_hdcp1x_set_repeater(struct tee_hdmitx_ioctl *tee_ioctl)
{
    hi_bool enable;
    struct tee_hdmitx *tee = HI_NULL;

    if (tee_ioctl == HI_NULL || tee_ioctl->data == NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size != sizeof(enable)) {
        hi_log_alert("err size %d\n", tee_ioctl->data_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    enable = HI_FALSE;

    if (memmove_s((hi_void *)&enable, sizeof(enable), tee_ioctl->data, tee_ioctl->data_size) != EOK) {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    tee->hdcp1x_ops->set_repeater(tee, enable);
    tee->hdcp14_info.ds_info.downstream_is_rpt = enable;

    return HI_SUCCESS;
}

static hi_s32 hdmitx_hdcp1x_set_b_vi(struct tee_hdmitx_ioctl *tee_ioctl)
{
    hi_u8 b_vi[HDCP1X_VI_SIZE_20BYTES];
    struct tee_hdmitx *tee = HI_NULL;

    if (tee_ioctl == HI_NULL || tee_ioctl->data == NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee_ioctl->data_size != sizeof(b_vi)) {
        hi_log_alert("err size %d\n", tee_ioctl->data_size);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee = hdmitx_id_2_tee(tee_ioctl->hdmi_id);
    if (tee == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (memmove_s((hi_void *)b_vi, sizeof(b_vi), tee_ioctl->data, tee_ioctl->data_size) != EOK) {
        hi_log_alert("err size=%d\n", tee_ioctl->data_size);
        return HI_FAILURE;
    }

    tee->hdcp1x_ops->set_b_vi(tee, b_vi, sizeof(b_vi));

    return HI_SUCCESS;
}

static struct tee_hdmitx_ioctl_node g_hdmitx_ioctl_tab[] = {
    {HDMITX_CMD_SESSION_VERIFY_MCU, hdmitx_verify_mcu},
    {HDMITX_CMD_SESSION_SET_HDCP_MODE, hdmitx_set_hdcp_mode},
    {HDMITX_CMD_SESSION_HDCP1X_SET_BKSV, hdmitx_hdcp1x_set_b_ksv},
    {HDMITX_CMD_SESSION_HDCP1X_SET_KSVLIST, hdmitx_hdcp1x_set_b_ksv_list},
    {HDMITX_CMD_SESSION_HDCP1X_VERIFY_R0, hdmitx_hdcp1x_verify_r0},
    {HDMITX_CMD_SESSION_HDCP1X_ENABLE_ENC, hdmitx_hdcp1x_set_encryption},
    {HDMITX_CMD_SESSION_HDCP1X_ENABLE_RPT, hdmitx_hdcp1x_set_repeater},
    {HDMITX_CMD_SESSION_HDCP1X_VERIFY_VI, hdmitx_hdcp1x_set_b_vi},
};

static hi_s32 hdmitx_ioctl_process(hi_void *arg)
{
    hi_s32 ret = HI_ERR_HDMITX_INVALID_PARA;
    hi_u32 size;
    struct tee_hdmitx_ioctl_node *node = HI_NULL;
    struct tee_hdmitx_ioctl *tee_ioctl = HI_NULL;

    if (arg == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_ERR_HDMITX_NULL_PTR;
    }

    tee_ioctl = (struct tee_hdmitx_ioctl *)arg;
    for (size = 0, node = &g_hdmitx_ioctl_tab[0];
        size < sizeof(g_hdmitx_ioctl_tab) / sizeof(g_hdmitx_ioctl_tab[0]);
        size++, node = &g_hdmitx_ioctl_tab[size]) {
        if (node->cmd_id == tee_ioctl->cmd_id) {
            if (node->ioctl_func != HI_NULL) {
                ret = node->ioctl_func(tee_ioctl);
            } else {
                hi_log_alert("null ptr\n");
                ret = HI_ERR_HDMITX_NULL_PTR;
            }
            break;
        }
    }

    return ret;
}

static hi_void hdmitx_dev_init(hi_void)
{
    enum tee_hdmitx_id id;
    struct tee_hdmitx *tee = HI_NULL;

    for (id = TEE_HDMITX_ID_0; id < TEE_HDMITX_ID_MAX; id++) {
        tee = hdmitx_id_2_tee(id);
        tee->dev_id = id;
        tee->hdcp2x_ops = tee_hal_hdmitx_hdcp2x_get_ops();
        tee->hdcp1x_ops = tee_hal_hdmitx_hdcp1x_get_ops();
        tee->ctrl_ops = tee_hal_hdmitx_ctrl_get_ops();
        tee->ctrl_ops->set_base_addr(tee);
        tee_drv_hdmitx_sys_irq_init(tee);
        if (tee->hdcp2x_ops->load_mcu_code(tee)) {
            hi_log_alert("id=%d,load mcu fail!\n", id);
        } else {
            hi_log_info("id=%d,load mcu success!\n", id);
        }
    }
}

static hi_void hdmitx_dev_deinit(hi_void)
{
    enum tee_hdmitx_id id;
    struct tee_hdmitx *tee = HI_NULL;

    for (id = TEE_HDMITX_ID_0; id < TEE_HDMITX_ID_MAX; id++) {
        tee = hdmitx_id_2_tee(id);
        tee_drv_hdmitx_sys_irq_deinit(tee);
    }
}

/* use the macro definition */
static int hdmitx_syscall(int swi_id, TSK_REGS_S *regs, UINT64 permissions)
{
    hi_s32 ret = HI_SUCCESS;
    struct tee_hdmitx_ioctl *tee_ioctl = HI_NULL;

    if (regs == HI_NULL) {
        hi_log_alert("null ptr\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_HDMITX, permissions, GENERAL_GROUP_PERMISSION)
        ACCESS_CHECK(regs->r1, _IOC_SIZE(regs->r0))
        tee_ioctl = (struct tee_hdmitx_ioctl *)regs->r1;
        if (tee_ioctl != HI_NULL && tee_ioctl->data != HI_NULL) {
            ACCESS_CHECK(tee_ioctl->data, tee_ioctl->data_size); /* ACCESS_CHECK finished ioremap */
            /* r0 is cmd, r1 is arg */
            ret = hdmitx_ioctl_process((hi_void *)regs->r1);
        } else {
            ret = -EINVAL;
        }
        if (ret != HI_SUCCESS) {
            regs->r0 = ret;
        } else {
            regs->r0 = HI_SUCCESS;
        }
        SYSCALL_END

        default:
        return -EINVAL;
    }

    return ret;
}

hi_s32 hdmitx_suspend(hi_void)
{
    hdmitx_dev_deinit();
    return HI_SUCCESS;
}

hi_s32 hdmitx_resume(hi_void)
{
    hdmitx_dev_init();

    hi_log_alert("resume secure hdmitx success. build time:[%s, %s]\n", __DATE__,  __TIME__);

    return HI_SUCCESS;
}

hi_s32 hdmitx_init(hi_void)
{
    hdmitx_dev_init();
    hi_log_alert("load secure hdmitx success. build time:[%s, %s]\n", __DATE__,  __TIME__);
    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init(g_hdmitx, 0, hdmitx_init, hdmitx_syscall,\
    hdmitx_suspend, hdmitx_resume);


hi_s32 hi_tee_hdmitx_register_callback(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_callback *callback_func)
{
    struct tee_hdmitx *tee = HI_NULL;

    tee = hdmitx_id_2_tee(id);
    if (tee == HI_NULL || callback_func == HI_NULL || callback_func->func == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee->callback != HI_NULL) {
        hi_log_alert("you have register the callback!\n");
        return HI_FAILURE;
    }

    tee->callback = callback_func;
    tee_drv_hdmitx_sys_timer_init(tee);

    return HI_SUCCESS;
}

hi_s32 hi_tee_hdmitx_unregister_callback(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_callback *callback_func)
{
    struct tee_hdmitx *tee = HI_NULL;

    tee = hdmitx_id_2_tee(id);
    if (tee == HI_NULL || callback_func == HI_NULL || tee->callback == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee->callback->func != callback_func->func) {
        hi_log_alert("you haven't register the callback %p!\n", callback_func->func);
        return HI_FAILURE;
    }

    tee_drv_hdmitx_sys_timer_deinit(tee);
    tee->callback = HI_NULL;

    return HI_SUCCESS;
}

hi_s32 hi_tee_hdmitx_set_stream_id(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_hdcp_stream_id stream_id)
{
    struct tee_hdmitx *tee = HI_NULL;

    tee = hdmitx_id_2_tee(id);
    if (tee == HI_NULL || tee->hdcp2x_ops == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    tee->hdcp2x_ops->set_stream_id(tee, stream_id);

    return HI_SUCCESS;
}

hi_s32 hi_tee_hdmitx_get_status(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_status *status)
{
    struct tee_hdmitx *tee = HI_NULL;

    tee = hdmitx_id_2_tee(id);
    if (tee == HI_NULL || tee->ctrl_ops == HI_NULL || status == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (tee->ctrl_ops->get_hpd(tee)) {
        status->hotplug = HI_TEE_DRV_HDMITX_HOTPLUG_IN;
    } else {
        status->hotplug = HI_TEE_DRV_HDMITX_HOTPLUG_OUT;
        if (tee->hdcp14_info.set_bksv) {
            status->hotplug = HI_TEE_DRV_HDMITX_HOTPLUG_DET_FAIL;
        }
    }
    status->rxsen = tee->ctrl_ops->get_rsen(tee) ?
        HI_TEE_DRV_HDMITX_RSEN_CONNECT : HI_TEE_DRV_HDMITX_RSEN_DISCONNECT;
    status->output_en = tee->ctrl_ops->get_phy_is_on(tee);

    return HI_SUCCESS;
}

hi_s32 hi_tee_hdmitx_get_hdcp_status(hi_tee_drv_hdmitx_id id, hi_tee_drv_hdmitx_hdcp_status *hdcp_status)
{
    hi_s32 mode;
    hi_bool hpd = HI_FALSE;
    hi_tee_drv_hdmitx_status status;
    struct tee_hdmitx *tee = HI_NULL;

    tee = hdmitx_id_2_tee(id);
    if (tee == HI_NULL || tee->hdcp1x_ops == HI_NULL || tee->hdcp2x_ops == HI_NULL ||
        tee->ctrl_ops == HI_NULL || hdcp_status == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    if (hi_tee_hdmitx_get_status(id, &status) != HI_SUCCESS) {
        hi_log_alert("get_status fail\n");
        return HI_FAILURE;
    }

    hpd = !(status.hotplug == HI_TEE_DRV_HDMITX_HOTPLUG_OUT);

    mode = tee->hdcp1x_ops->get_mode(tee);
    if (mode) {
        hdcp_status->work_version = HI_TEE_DRV_HDMITX_HDCP_VERSION_2X;
        hdcp_status->auth_start = !tee->ctrl_ops->get_mcu_rst(tee) && hpd;
        hdcp_status->auth_success = tee->hdcp2x_info.auth_success && hpd;
    } else {
        hdcp_status->auth_start = tee->hdcp14_info.set_bksv && hpd;
        hdcp_status->auth_success = tee->hdcp1x_ops->get_encryption(tee) && hpd;
        hdcp_status->work_version = (hdcp_status->auth_start || hdcp_status->work_version) ?
            HI_TEE_DRV_HDMITX_HDCP_VERSION_1X : HI_TEE_DRV_HDMITX_HDCP_VERSION_NONE;
    }

    return HI_SUCCESS;
}

hi_s32 hi_tee_hdmitx_get_hdcp14_downstream_info(hi_tee_drv_hdmitx_id id, struct hdcp14_downstream_info *info)
{
    struct tee_hdmitx *tee = HI_NULL;

    tee = hdmitx_id_2_tee(id);
    if (tee == HI_NULL || info == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    *info = tee->hdcp14_info.ds_info;

    return HI_SUCCESS;
}

hi_s32 hi_tee_hdmitx_get_hdcp2x_downstream_info(hi_tee_drv_hdmitx_id id, struct hdcp2x_downstream_info *info)
{
    struct tee_hdmitx *tee = HI_NULL;

    tee = hdmitx_id_2_tee(id);
    if (tee == HI_NULL || info == HI_NULL) {
        hi_log_alert("null ptr\n");
        return HI_FAILURE;
    }

    *info = tee->hdcp2x_info.ds_info;

    return HI_SUCCESS;
}

