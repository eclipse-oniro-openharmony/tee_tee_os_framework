/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: secure storage agent implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
 */
#ifndef __SSAGENT_AGENT_H
#define __SSAGENT_AGENT_H

#include <tee_defines.h>
#include "tee_ss_agent_api.h"

bool is_client_register(uint32_t sender);
void ssa_send_agent_cmd(uint32_t id, uint32_t cmd, uint32_t *cmd_buff);
void ssa_obtain_agent_work_lock(uint32_t id);
void ssa_agent_work_unlock(uint32_t id);
TEE_Result ssa_get_msg(uint32_t *cmd, uint8_t *msg, uint32_t size, uint32_t *sender);
void register_uuid(uint32_t sender, TEE_UUID uuid, uint32_t user_id, bool ssa_enum_enable);
char pre_unregister_uuid(const union ssa_agent_msg *msg, uint32_t sndr);
void ssa_register_uuid(union ssa_agent_msg *msg, uint32_t sndr, struct ssa_agent_rsp *rsp);
TEE_Result set_caller_info_proc(uint32_t task_id, uint32_t cmd);
#define PERMSRV_SAVE_FILE ".rtosck.permsrv_save_file"
#endif
