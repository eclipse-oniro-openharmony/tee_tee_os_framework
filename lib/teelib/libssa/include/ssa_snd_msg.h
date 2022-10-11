/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: ssa embedded msg
 * Create: 2021-01-09
 */
#ifndef SSA_MSG_H
#define SSA_MSG_H
#include "stdint.h"

#define SSA_SERVICE_PATH "ssa_service"
#define MSG_MAX_LEN 128

struct msg_st {
    uint32_t msg_id;
    char payload[MSG_MAX_LEN];
} __attribute__((__packed__));

uint32_t send_msg_to_ssa(uint32_t cmd_id, const void *msg, uint32_t msg_szie);
#endif
