/* $$$!!Warning: Huawei key information asset. No spread without permission.$$$ */
/* CODEMARK:G45B5tAhAurX3Fjv5w5YrnvEBsxawGU4sQTa6eXHOFkC1Mfvbai6ssLiuF4skCy23hW+xgyXJaVN
2jIjipr/cpauHINx1FQyMyereaY2ZKz1AEk16KBYT3zrrVcV/zYZa+SM7KtAIjQaXRQOuxkCVCHR
djsuW3qvWZbQ3ZjHygm+9Z7Zon2QkYjMt+j1ajp+5u25sy0tND3u8XRRTFLYIcPN3a00GwLwzcWQ
hFfZjUw=# */
/* $$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: register or unregister permission to ssa
 * Create: 2022-03-11
 */

#include "register_ssa_perm.h"
#include <securec.h>
#include <tee_log.h>
#include <ta_framework.h>
#include <target_type.h>

static uint32_t send_reg_msg_to_agent(uint32_t agent_task_id, uint32_t task_id, uint32_t msg_id)
{
    struct reg_ta_info reg_msg = { 0 };
    TEE_UUID uuid = TEE_SERVICE_PERM;

    reg_msg.taskid = task_id;
    reg_msg.userid = 0;

    reg_msg.uuid = uuid;
    uint32_t ret = ipc_msg_snd(msg_id, agent_task_id, &reg_msg, sizeof(reg_msg));
    if (ret != SRE_OK)
        tloge("perm service send reg msg to task 0x%x failed\n", agent_task_id);

    return ret;
}

void register_self_to_ssa(uint32_t task_id, uint32_t msg_id)
{
    uint32_t ssa_pid;

    uint32_t ret = ipc_hunt_by_name(0, SSA_SERVICE_NAME, &ssa_pid);
    if (ret != SRE_OK)
        tloge("get ssa pid failed, maybe ssa is not started\n");
    else
        (void)send_reg_msg_to_agent(ssa_pid, task_id, msg_id);
}
