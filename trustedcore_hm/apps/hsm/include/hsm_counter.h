/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm counter and algorithm check header file
* Author: huawei
* Create: 2020/3/15
*/
#ifndef HSM_COUNTER_H
#define HSM_COUNTER_H

#include <stdint.h>
#include <tee_service_public.h>

void hsm_counter_init(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_counter_create(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_counter_read(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_counter_delete(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_counter_inc(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_alg_check(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);

#endif
