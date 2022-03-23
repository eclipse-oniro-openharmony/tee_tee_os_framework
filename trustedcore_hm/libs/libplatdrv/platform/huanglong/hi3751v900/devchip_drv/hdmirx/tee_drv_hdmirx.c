/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Implementation of common functions
 * Author: Hisilicon multimedia interface software group
 * Create: 2020/01/20
 */
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_errcode.h"
#include "tee_drv_hdmirx_hdcp.h"
#include "tee_drv_hdmirx_rpt.h"
#include "tee_hal_hdmirx_product.h"
#include "tee_drv_hdmirx_ioctl.h"
#include "tee_drv_common_ioctl.h"
#include "tee_drv_hdmirx_ctrl.h"
#include "hi_tee_license.h"

static hi_s32 tee_drv_hdmirx_ioctl(tee_hdmirx_ioctl_cmd cmd, hi_void *args)
{
    hi_s32 ret = HI_ERR_HDMIRX_PARAM_INVALID;

    if (args == NULL) {
        hi_log_err("invalid parameter\n");
        return HI_ERR_HDMIRX_NULL_PTR;
    }

    switch (cmd) {
        case HDMIRX_IOCTL_CHK_MCU_CODE:
            ret = tee_drv_hdmirx_hdcp_check_mcu_code(*(hi_tee_drv_hdmirx_port *)args);
            break;
        case HDMIRX_IOCTL_GET_MAP: {
            tee_hdmirx_ioctl_rpt_map *rpt_map = (tee_hdmirx_ioctl_rpt_map *)args;

            ret = tee_drv_hdmirx_rpt_get_map(rpt_map->port, &rpt_map->map);
            break;
        }
        case HDMIRX_IOCTL_CHK_DS_READY: {
            tee_hdmirx_ioctl_ds_ready *ds = (tee_hdmirx_ioctl_ds_ready *)args;

            ret = tee_drv_hdmirx_rpt_set_downstream_info(ds->port);
            ds->downstream.ready = (ret == HI_SUCCESS) ? HI_TRUE : HI_FALSE;
            break;
        }
        default:
            break;
    }

    hi_log_info("tee drv ioctl ret: 0x%x", ret);

    return ret;
}

static int tee_drv_hdmirx_syscall(int swi_id, TSK_REGS_S *regs, UINT64 permissions)
{
    if (regs == NULL) {
        hi_log_err("invalid parameter\n");
        return HI_ERR_HDMIRX_NULL_PTR;
    }

    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_HDMIRX, permissions, GENERAL_GROUP_PERMISSION)
            ACCESS_CHECK(regs->r1, _IOC_SIZE(regs->r0))
            hi_log_info("tee drv hdmirx, r1_addr = 0x%x, r1_value = 0x%x\n", regs->r1, *(int *)regs->r1);
            /* regs->r0 return value for api */
            regs->r0 = tee_drv_hdmirx_ioctl(regs->r0, (hi_void *)regs->r1);
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return 0;
}

hi_s32 tee_drv_hdmirx_resume(hi_void)
{
    hi_u32 i;
    hi_s32 ret;
    hi_u32 license = 0;

    /* reg map */
    tee_drv_hdmirx_ctrl_init();

    /* if no license, disable all clk */
    ret = hi_tee_drv_get_license_support(HI_LICENSE_HDMI_RX_EN, &license);
    if (ret != HI_SUCCESS || license != HI_TRUE) {
        tee_drv_hdmirx_crg_deinit();
        hi_log_err("license get failed(0x%x) or not support hdmirx(%d)!\n", ret, license);
        return HI_ERR_HDMIRX_FEATURE_NOT_SUPPORT;
    }

    /* crg init */
    tee_drv_hdmirx_crg_init();

    /* load mcu code */
    for (i = 0; i < HDMIRX_CTRL_CNT; i++) {
        ret = tee_drv_hdmirx_hdcp_load_mcu_code(i);
        if (ret != HI_SUCCESS) {
            hi_log_err("mcu code load failed(%d)!\n", i);
        }
    }

    return ret;
}

hi_s32 tee_drv_hdmirx_init(hi_void)
{
    hi_u32 i;
    hi_s32 ret;
    hi_u32 license = 0;

    /* reg map */
    tee_drv_hdmirx_ctrl_init();

    /* if no license, disable all clk */
    ret = hi_tee_drv_get_license_support(HI_LICENSE_HDMI_RX_EN, &license);
    if (ret != HI_SUCCESS || license != HI_TRUE) {
        tee_drv_hdmirx_crg_deinit();
        hi_log_err("license get failed(0x%x) or not support hdmirx(%d)!\n", ret, license);
        return HI_ERR_HDMIRX_FEATURE_NOT_SUPPORT;
    }

    /* crg init */
    tee_drv_hdmirx_crg_init();
    /* load mcu code */
    for (i = 0; i < HDMIRX_CTRL_CNT; i++) {
        ret = tee_drv_hdmirx_hdcp_load_mcu_code(i);
        if (ret != HI_SUCCESS) {
            hi_log_err("mcu code load failed(%d)!\n", i);
            return ret;
        }
    }

    hi_tee_drv_hal_printf("load secure hdmirx success. build time:[%s, %s]\n", __DATE__,  __TIME__);

    return HI_SUCCESS;
}

hi_tee_drv_hal_driver_init(hdmirx, 0, tee_drv_hdmirx_init, tee_drv_hdmirx_syscall, NULL, tee_drv_hdmirx_resume);

