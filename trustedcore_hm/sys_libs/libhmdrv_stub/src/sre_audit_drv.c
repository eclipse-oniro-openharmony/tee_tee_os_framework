/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: syscall and TA crash audit module
 * Create: 2019-05-10
 */

#ifdef SRE_AUDIT
#include "sre_audit_drv.h"
#include <stdio.h>
#include <msg_ops.h>
#include <sys/usrsyscall_new_ext.h>
#include "tee_log.h"
#include "ta_framework.h"

#define REET_SERVICE_NAME "teesmcmgr"

/*
 * CODEREVIEW CHECKLIST
 * CALLER: platdrv_handle_message
 * ARG: task_handle: from platdrv_handle_message, always valid
 * RIGHTS: N/A
 * BUFOVF: N/A
 * LOG: N/A
 * RET: N/A
 * RACING: N/A
 * LEAK: N/A
 * ARITHOVF: N/A
 */
void kill_audit_task(UINT32 task_handle, cref_t teesmc_hdlr)
{
    uint32_t global_task_handle;
    uint32_t reet_task_handle;
    uint32_t ret;

    ret = ipc_hunt_by_name(0, GLOBAL_SERVICE_NAME, &global_task_handle);
    if (ret != 0) {
        tloge("failed to get global handle\n");
        return;
    }

    ret = ipc_hunt_by_name(0, REET_SERVICE_NAME, &reet_task_handle);
    if (ret != 0) {
        tloge("failed to get reet handle\n");
        return;
    }

    if (task_handle != global_task_handle && task_handle != reet_task_handle) {
        /* send kill msg to global_task */
        ret = ipc_msg_snd(MSG_SRE_AUDIT_TRIGER, global_task_handle, &task_handle, sizeof(task_handle));
        if (ret != 0) {
            tloge("failed send msg to global task\n");
            return;
        }
    } else {
        int32_t rets = hmex_teesmc_switch_req(teesmc_hdlr, CAP_TEESMC_REQ_CRASH);
        if (rets != 0) {
            tloge("switch req failed in kill task\n");
            __builtin_trap();
        }
    }
}

#endif
