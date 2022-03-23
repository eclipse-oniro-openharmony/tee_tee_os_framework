/*
* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
* Description: hsm efuse rim and nv cnt update
* Author: huawei
* Create: 2020/6/20
*/
#ifndef HSM_EFUSE_H
#define HSM_EFUSE_H

#include <stdint.h>
#include <tee_service_public.h>

void hsm_rim_update(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_efuse_power_on(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);
void hsm_efuse_power_off(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);

#endif
