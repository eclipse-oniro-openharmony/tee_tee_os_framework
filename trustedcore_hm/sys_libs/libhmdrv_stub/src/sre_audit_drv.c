/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: syscall and TA crash audit module
 * Create: 2019-05-10
 */

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
    (void)task_handle;
    (void)teesmc_hdlr;
}

