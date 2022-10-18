/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk derive takey
 * Create: 2022-10-08
 */
#ifndef HUK_DERIVE_TAKEY_H
#define HUK_DERIVE_TAKEY_H

#include <tee_defines.h>
#include "huk_service_msg.h"

struct huk_access_table {
    uint32_t cmd_id;
    TEE_UUID uuid;
};

TEE_Result huk_task_derive_takey(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t sndr_pid, const TEE_UUID *uuid);

#endif
