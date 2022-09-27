/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: tee agent function declaration.
 * Create: 2020-01-14
 */
#ifndef LIBAGENT_BASE_TEE_AGENT_H
#define LIBAGENT_BASE_TEE_AGENT_H

#include <stdint.h>
#include <tee_defines.h>

TEE_Result tee_agent_lock(uint32_t agent_id);
TEE_Result tee_agent_unlock(uint32_t agent_id);
TEE_Result tee_send_agent_cmd(uint32_t agent_id);
TEE_Result tee_get_agent_buffer(uint32_t agent_id, void **buffer, uint32_t *length);

#endif
