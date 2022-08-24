/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * Description: dispatch secure cmd from TA or tee service
 * Author: lipeng
 * Create: 2022-4-24
 */

#ifndef TEE_S_CMD_DISPATCH_H
#define TEE_S_CMD_DISPATCH_H

#include <stdint.h>

typedef int32_t (*proc_func)(uint32_t cmd_id, uint32_t task_id,
    const uint8_t *msg_buf, uint32_t msg_size);

struct s_cmd_proc_t {
    uint32_t cmd_id;
    proc_func func;
};

int32_t handle_s_cmd(uint32_t cmd_id, uint32_t task_id, const uint8_t *msg_buf, uint32_t msg_size);

#endif
