/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for MSP core base driver.
 * Create: 2019/12/25
 */

#ifndef __MSPC_H__
#define __MSPC_H__

#include <tee_log.h>
#include <pthread.h>
#include <semaphore.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a)   (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef BIT
#define BIT(n)                    (1 << (n))
#endif

#define MSPC_DELAY_TIME            1

enum mspc_cmd_ack {
    MSPC_CMD_ACK_NULL  = 0x55,
    MSPC_CMD_ACK_OK    = 0xA3,
    MSPC_CMD_ACK_ERROR = 0xF7,
};

struct mspc_cmd_info {
    uint8_t cmd;
    uint8_t ack;
    uint8_t reserved1;
    uint8_t reserved2;
    uint32_t size;
    uint32_t block_size;
    uint32_t block_index;
    uint8_t *data;

};

enum mspc_ipc_cmd {
    MSPC_CMD_SEND_APDU    = 0xA3,
    MSPC_CMD_RECV_APDU    = 0xA4,
    MSPC_CMD_INIT_APDU    = 0xA5,
    MSPC_CMD_WRITELOCK    = 0xA6,
};

struct mspc_work_data {
    uint8_t *buffer;
    uint32_t buffer_size;
    uint32_t left_size;
    uint32_t recv_size;
    uint32_t status;
};

int32_t mspc_send_msg(struct mspc_cmd_info *cmd_data);

#endif /* __MSPC_H__ */

