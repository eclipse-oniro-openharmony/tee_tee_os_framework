/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
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
