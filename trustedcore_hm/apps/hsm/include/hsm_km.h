/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm crypto header file
* Author: huawei
* Create: 2020/1/18
*/
#ifndef HSM_KM_H
#define HSM_KM_H

#include <stdint.h>
#include <tee_service_public.h>

void hsm_produce_symmetric_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_produce_asymmetric_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_derive_huk(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_derive_external_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_produce_negotiation_pubkey(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_produce_negotiation_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_sh_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_update_guarding_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_update_authorize_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_delete_cipher(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_bbox_get(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_notify_prereset(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_import_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_export_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);

#endif
