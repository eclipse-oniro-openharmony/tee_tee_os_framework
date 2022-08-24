/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: interface declaration for gtask framework
 * Author: l00238133
 * Create: 2019-10-28
 */

#ifndef GTASK_TASK_ADAPTOR_PUB_H
#define GTASK_TASK_ADAPTOR_PUB_H

#include <stddef.h>

void task_adapt_init(void);
int32_t task_adapt_set_caller_info(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);
bool is_internal_task_by_task_id(uint32_t task_id);
bool is_internal_task_by_uuid(const TEE_UUID *uuid);
void task_adapt_crash_callback(uint32_t task_id);
void task_adapt_register_ta(uint32_t ta_task_id, uint32_t userid, bool ssa_enum_enable, const TEE_UUID *uuid);
void task_adapt_unregister_ta(uint32_t ta_task_id);
bool is_service_agent_request(uint32_t agent_task_id, uint32_t *caller_task_id, uint32_t **agent_status);
bool is_agent_response(uint32_t agent_id, uint32_t *agent_task_id, uint32_t *caller_task_id,
                       uint32_t **agent_status);
bool check_system_agent_permission(uint32_t task_id, uint32_t agent_id);
void task_adapt_register_agent(uint32_t agent_id);
void fs_agent_late_init(void);
void task_adapt_ta_create(uint32_t pid, const TEE_UUID *uuid);
void task_adapt_ta_release(const TEE_UUID *uuid);

#endif
