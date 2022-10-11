/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk provision key
 * Create: 2022-10-08
 */
#ifndef HUK_PROVISION_KEY_H
#define HUK_PROVISION_KEY_H

#include <tee_defines.h>
#include "huk_service_msg.h"

TEE_Result huk_task_provision_key(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid);

#endif
