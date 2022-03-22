/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
* Description: hsm service soc verify head file
* Author: huawei
* Create: 2020/5/21
*/
#ifndef HSM_VERIFY_H
#define HSM_VERIFY_H

#include <stdint.h>
#include <tee_service_public.h>

void hsm_soc_verify(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_hboot1a_transform(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);

#endif
