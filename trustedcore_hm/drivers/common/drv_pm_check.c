/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: define drv suspend/resume msg check function
 * Create: 2021-07-12
 */
#include "drv_pm_check.h"
#include <ipclib.h>
#include <pm_msgtype.h>
#include <cs.h>
#include <tee_log.h>

static bool check_msg_id_invalid(uint16_t msg_id)
{
    if (msg_id != HM_MSG_ID_DRV_PWRMGR_SUSPEND_CPU && msg_id != HM_MSG_ID_DRV_PWRMGR_RESUME_CPU &&
        msg_id != HM_MSG_ID_DRV_PWRMGR_SUSPEND_S4 && msg_id != HM_MSG_ID_DRV_PWRMGR_RESUME_S4) {
        printf("driver pm handle get invalid msg id 0x%x\n", msg_id);
        return true;
    }

    return false;
}

static bool check_sender_invalid(const struct hmcap_message_info *info, pid_t auth_pid)
{
    pid_t sender_pid = (pid_t)info->src_cred.pid;
    if (sender_pid != auth_pid) {
        printf("suspend/resume cannot call by 0x%x auth_pid:0x%x\n", sender_pid, auth_pid);
        return true;
    }

    return false;
}

int32_t pm_msg_param_check(uint16_t msg_id, cref_t msg_hdl,
    hm_msg_header *msg, const struct hmcap_message_info *info, pid_t auth_pid)
{
    int32_t ret;

    if (msg == NULL || info == NULL) {
        printf("pm invalid msg\n");
        return -1;
    }

    if (check_msg_id_invalid(msg_id))
        goto err_reply;

    if (driver_pm_msg_validate(msg) == 0) {
        printf("error: Invalid message size\n");
        goto err_reply;
    }

    if (check_sender_invalid(info, auth_pid)) {
        printf("invalid caller in pm\n");
        goto err_reply;
    }

    return 0;

err_reply:
    ret = cs_server_reply_error(msg_hdl, -EINVAL);
    if (ret != 0)
        printf("reply to pm invalid msg error 0x%x\n", ret);
    return -1;
}
