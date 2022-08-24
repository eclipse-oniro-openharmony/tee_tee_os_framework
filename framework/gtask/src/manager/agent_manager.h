/* Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: used by agent_manager.
 * Author: yangboyu y30022050
 * Create: 2022-04-24
 */
#ifndef GTASK_AGENT_MANAGER_H
#define GTASK_AGENT_MANAGER_H

#include <dlist.h>
#include "gtask_core.h"

TEE_Result register_agent(const smc_cmd_t *cmd);
TEE_Result unregister_agent(const smc_cmd_t *cmd);
TEE_Result agent_late_init(const smc_cmd_t *cmd);
TEE_Result tee_get_agent_buffer(uint32_t agent_id, paddr_t *buffer, uint32_t *length);
void tee_unlock_agents(struct session_struct *session);
void agent_manager_init(void);
void register_agent_buffer_to_task(uint32_t agent_id, uint32_t dest_task_id);
TEE_Result set_service_thread_cmd(const smc_cmd_t *cmd, bool *async);
bool service_thread_request_dequeue(const smc_cmd_t *in, smc_cmd_t *out);

int32_t handle_agent_request(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);
int32_t handle_service_agent_back_cmd(const smc_cmd_t *cmd);
int32_t handle_ta_agent_back_cmd(smc_cmd_t *cmd);

#endif /* GTASK_AGENT_MANAGER_H */
