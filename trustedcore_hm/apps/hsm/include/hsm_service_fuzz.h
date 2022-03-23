/*
* Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
* Description: hsm service fuzz head file
* Author: huawei
* Create: 2021/6/17
*/
#ifndef HSM_SERVICE_FUZZ_H
#define HSM_SERVICE_FUZZ_H

#include <stdint.h>
#include <tee_service_public.h>

void hsm_service_fuzz(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);

#endif
