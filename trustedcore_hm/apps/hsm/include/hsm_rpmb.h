/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: rpmb head file
 * Author: huawei
 * Create: 2020/4/28
 */
#ifndef HSM_RPMB_H
#define HSM_RPMB_H

#include <stdint.h>
#include <tee_service_public.h>

void generate_rpmb_key(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp);
void generate_rpmb_wrapping_key(const tee_service_ipc_msg *msg, uint32_t task_id,
    tee_service_ipc_msg_rsp *rsp);

#endif
