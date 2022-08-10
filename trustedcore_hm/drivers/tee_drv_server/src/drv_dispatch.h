/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: declare tee_drv_server dispatch function when receive cmd
 * Create: 2021-03-01
 */
#ifndef TEE_DRV_SERVER_SRC_DRV_DISPATCH_H
#define TEE_DRV_SERVER_SRC_DRV_DISPATCH_H

#include <hm_msg_type.h>
#include <tee_defines.h>
#include <cs.h>

struct tee_drv_param {
    uint64_t args;
    uint64_t data;
    struct tee_uuid uuid;
    uint32_t caller_pid;
};

#endif
