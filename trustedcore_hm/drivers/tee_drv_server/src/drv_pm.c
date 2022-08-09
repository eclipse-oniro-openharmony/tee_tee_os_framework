/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: define drv suspend/resume function
 * Create: 2021-03-01
 */
#include "drv_pm.h"
#include <stdint.h>
#include <sys/usrsyscall_ext.h>
#include <pm_msgtype.h>
#include <msg_ops.h>
#include <ipclib.h>
#include <hmlog.h>
#include <libdrv_frame.h>
#include <timer.h>
#include <drv_pm_check.h>
#include "task_mgr.h"

static bool check_msg_invalid(uint16_t msg_id, cref_t msg_hdl, hm_msg_header *msg,
    const struct hmcap_message_info *info)
{
    static uint32_t auth_pid = SMCMGR_PID;

    if (pm_msg_param_check(msg_id, msg_hdl, msg, info, pid_to_hmpid(auth_pid)) != 0)
        return true;

    return false;
}

intptr_t driver_pm_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    int32_t ret;

    if (msg == NULL || p_msg_hdl == NULL)
        return -EINVAL;

    cref_t msg_hdl = *p_msg_hdl;
    uint16_t msg_id = ((hm_msg_header *)msg)->send.msg_id;

    if (check_msg_invalid(msg_id, msg_hdl, msg, info)) {
        hm_error("check pm msg failed\n");
        return -1;
    }

    tee_drv_pm_cmd_handle(msg_id);

    /*
     * smcmgr will send suspend/resume cmd to tee_drv_server when there it no platdrv
     * in this case, tee_drv_server should send suspend/resume cmd to drv_timer
     * and call return_to_tee after all driver operations are done.
     */
    static cref_t timer_cref = 0;
    ret = pm_forward_msg_to_other_drv(msg_id, TIMER_PATH, &timer_cref);
    if (ret != 0)
        hm_error("pm forward msg to drv timer failed 0x%x\n", ret);

    ret = hm_driver_pm_return_to_ree(msg_id);
    if (ret != 0)
        return -1;

    hm_info("tee drv server handle PM msg 0x%x done\n", msg_id);

    return 0;
}
