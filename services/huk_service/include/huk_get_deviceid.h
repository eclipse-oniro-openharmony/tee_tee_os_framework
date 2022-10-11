/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk get deviceid
 * Create: 2022-10-08
 */
#ifndef HUK_GET_DEVICEID_H
#define HUK_GET_DEVICEID_H

#include <tee_defines.h>
#include "huk_service_msg.h"

TEE_Result huk_task_get_deviceid(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid);

#endif
