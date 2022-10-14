/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk get deviceid
 * Create: 2022-10-08
 */
#include "huk_get_deviceid.h"

TEE_Result huk_task_get_deviceid(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t sndr_pid, const TEE_UUID *uuid)
{
    (void)msg;
    (void)rsp;
    (void)sndr_pid;
    (void)uuid;
    return TEE_ERROR_NOT_SUPPORTED;
}
