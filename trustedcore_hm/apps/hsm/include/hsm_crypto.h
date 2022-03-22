/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm key managerment header file
* Author: huawei
* Create: 2020/1/8
*/

#ifndef HSM_CRYPTO_H
#define HSM_CRYPTO_H

#include <stdint.h>
#include <tee_service_public.h>

void hsm_mac_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_mac_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_mac_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_hash_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_hash_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_hash_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_sign_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_sign_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_sign_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_verify_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_verify_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_verify_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_gen_random(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_cipher_start(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_cipher_process(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void hsm_cipher_finish(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);

#endif
