/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: process tee task exception, include TA & internal service
 * Author: lipeng
 * Create: 2020-09-30
 */

#ifndef TEE_TASK_EXCEPTION_H
#define TEE_TASK_EXCEPTION_H

#include <stddef.h>
#include "tee_defines.h"
#include "gtask_core.h"

enum TaStatus {
    TA_STATUS_NORMAL        = 0,
    TA_STATUS_SELF_DEAD     = 1,  /* TA self has exception */
    TA_STATUS_FATHER_DEAD   = 2,  /* TA's father TA has exception */
};

int32_t process_task_crash(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf,
                           uint32_t msg_size);
int32_t handle_kill_task(const smc_cmd_t *cmd);
void ta_exception_handle_ack(int32_t sess_status, uint32_t task_id, uint32_t father_task_id);
void ta_exception_handle_buildin_agent_ack(uint32_t task_id);
TEE_Result ta_exception_handle_agent_ack(const smc_cmd_t *cmd);
#endif
