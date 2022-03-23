/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: define drv suspend/resume function
 * Create: 2021-07-28
 */
#include "drv_pm.h"
#include <stdint.h>
#include <sys/usrsyscall_ext.h>
#include <sys/hm_types.h>
#include <pm_msgtype.h>
#include <tee_log.h>
#include <ipclib.h>
#include <libdrv_frame.h>
#include <drv_pm_check.h>
#include "drv_operations.h"
#include "tee_drv_entry.h"

static void driver_suspend(void)
{
    const struct tee_driver_module *func = get_drv_func();
    if (func == NULL) {
        tloge("invalid func during suspend\n");
        return;
    }

    if (func->suspend != NULL)
        func->suspend();
}

static void driver_resume(void)
{
    const struct tee_driver_module *func = get_drv_func();
    if (func == NULL) {
        tloge("invalid func during resume\n");
        return;
    }

    if (func->resume != NULL)
        func->resume();
}

static void driver_suspend_s4(void)
{
    const struct tee_driver_module *func = get_drv_func();
    if (func == NULL) {
        tloge("invalid func during suspend_s4\n");
        return;
    }

    if (func->suspend_s4 != NULL)
        func->suspend_s4();
}

static void driver_resume_s4(void)
{
    const struct tee_driver_module *func = get_drv_func();
    if (func == NULL) {
        tloge("invalid func during resume_s4\n");
        return;
    }

    if (func->resume_s4 != NULL)
        func->resume_s4();
}

static void drv_pm_cmd_handle(uint16_t msg_id)
{
    switch (msg_id) {
    case HM_MSG_ID_DRV_PWRMGR_SUSPEND_CPU:
        driver_suspend();
        break;
    case HM_MSG_ID_DRV_PWRMGR_RESUME_CPU:
        driver_resume();
        break;
    case HM_MSG_ID_DRV_PWRMGR_SUSPEND_S4:
        driver_suspend_s4();
        break;
    case HM_MSG_ID_DRV_PWRMGR_RESUME_S4:
        driver_resume_s4();
        break;
    default:
        tloge("msg id:0x%x not support\n", msg_id);
    }
}

static bool check_msg_invalid(uint16_t msg_id, cref_t msg_hdl, hm_msg_header *msg,
    const struct hmcap_message_info *info)
{
    uint32_t auth_pid = get_drv_mgr_pid();
    if (pm_msg_param_check(msg_id, msg_hdl, msg, info, pid_to_hmpid(auth_pid)) != 0)
        return true;

    return false;
}

intptr_t driver_pm_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    if (info == NULL) {
        tloge("invalid cap message\n");
        return -1;
    }

    if (msg == NULL || p_msg_hdl == NULL)
        return -EINVAL;

    cref_t msg_hdl = *p_msg_hdl;
    uint16_t msg_id = ((hm_msg_header *)msg)->send.msg_id;

    if (check_msg_invalid(msg_id, msg_hdl, msg, info))
        return -1;

    drv_pm_cmd_handle(msg_id);

    int32_t ret = cs_server_reply_error(msg_hdl, 0);
    if (ret != 0) {
        printf("reply to PM msg error %d\n", ret);
        return ret;
    }

    printf("drv handle PM msg 0x%x done\n", msg_id);

    return 0;
}
