/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:lBRwzWIfWflpkuvEPG9oHU2mxP0IzvCfvv+i+/xvfe6PT8VRR+8jz7b5YQbqzI49/C6xSBgi
2fFxGZUs+G3nkUIkBkfRerjPcgJTCLqrXspNkFCGTLklL/GZHRhiXBwGnNKhh0MAXEOVfrQU
iukZUWJ4vidruSf/U7e9gpUyQAooCWCSaeb3aIYEst5WD1qne8GcO+5QGB0g7/S8T09ixUGT
nR+osDAHaIEfyoPHfIFAJAQLD0ohh2OwUozrcXB/#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: interfaces for gtask to communicate with ssagent
 * Author: l00238133
 * Create: 2019-10-28
 */

#include "task_ssa_adaptor.h"
#include <securec.h>
#include "msg_ops.h"
#include "task_adaptor.h"
#include "tee_task_config.h"
#include "tee_ss_agent_api.h"
#include "gtask_inner.h"
#include "agent_manager.h"

#define TASK_PRIO_SSA (DEFAULT_TASK_PRIO - 1)
struct task_adaptor_info *register_task_ssa(void);

static void send_response_to_pending_ta(const struct task_caller_info *caller_info)
{
    if (caller_info->taskid != INVALID_TASK_ID) {
        struct ssa_agent_rsp rsp;

        errno_t rc = memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
        if (rc != EOK)
            tloge("memset ssa rsp msg failed\n");

        rsp.ret      = TEE_ERROR_STORAGE_NOT_AVAILABLE;
        uint32_t ret = ipc_msg_snd(caller_info->cmd, caller_info->taskid, &rsp, sizeof(rsp));
        if (ret != SRE_OK)
            tloge("send msg to ssa caller fail:%u\n", ret);
    }
}

static void task_ssa_crash_callback(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *config)
{
    (void)uuid;
    (void)task_name;
    (void)config;
    struct task_adaptor_info *task = register_task_ssa();
    if (task != NULL) {
        if (task->task_id != INVALID_TASK_ID)
            register_agent_buffer_to_task(task->agent_id, task->task_id);

        send_response_to_pending_ta(&task->caller_info);
    }
}

static void task_ssa_init_priv_info(struct task_adaptor_info *task)
{
    task->is_agent                      = true;
    task->agent_id                      = TEE_FS_AGENT_ID;
    task->task_crash_callback           = task_ssa_crash_callback;
    task->register_ta_to_task           = send_register_ta_to_task;
    task->unregister_ta_to_task         = send_unregister_ta_to_task;
    task->register_agent_buffer_to_task = register_agent_buffer_to_task;
}

struct task_adaptor_info *register_task_ssa(void)
{
    if (is_ssa_enable()) {
        TEE_UUID uuid = TEE_SERVICE_SSA;
        struct task_adaptor_info *task = register_task_proc(&uuid, TASK_PRIO_SSA,
            SSA_SERVICE_NAME, task_ssa_init_priv_info, NULL);
        if (task == NULL)
            tlogd("jump to reg task ssa\n");
        return task;
    }
    return NULL;
}

enum load_state {
    LOAD_STATE_NOT_READY,
    LOAD_STATE_READY,
};

void task_ssa_load_manage_info(void)
{
    return;
}
