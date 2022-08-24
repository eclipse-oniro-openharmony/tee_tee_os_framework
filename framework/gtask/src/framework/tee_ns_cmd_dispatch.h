/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: dispatch cmd from ree
 * Author: lipeng
 * Create: 2020-12-15
 */

#ifndef TEE_NS_CMD_DISPATCH_H
#define TEE_NS_CMD_DISPATCH_H

#include "ta_framework.h"

typedef TEE_Result (*sync_func)(const smc_cmd_t *cmd);

struct ns_sync_cmd_t {
    uint32_t cmd_id;
    sync_func func;
};

TEE_Result dispatch_ns_cmd(smc_cmd_t *cmd);

#endif
