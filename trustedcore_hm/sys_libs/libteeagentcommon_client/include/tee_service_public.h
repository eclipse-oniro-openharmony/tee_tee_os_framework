/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: tee service public function
 * Create: 2019-08-19
 */
#ifndef _TEE_SERVICE_PUBLIC_H_
#define _TEE_SERVICE_PUBLIC_H_

typedef void (*func_ptr)(void);

#include "tee_defines.h"

/* don't allow to edit these files */
#define TEE_SERVICE_MSG_QUEUE_SIZE 100
typedef struct {
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t arg5;
    uint64_t arg6;
    uint64_t arg7;
} args_t;

struct reg_ta_info {
    uint32_t taskid;
    TEE_UUID uuid;
    uint32_t userid;
    bool ssa_enum_enable; /* just for ssa, other tasks will ignore it */
};

typedef union {
    args_t args_data;
    struct reg_ta_info reg_ta;
} tee_service_ipc_msg;

struct tee_service_ipc_msg_req {
    uint32_t cmd;
    tee_service_ipc_msg msg;
};

typedef struct {
    TEE_Result ret;
    tee_service_ipc_msg msg;
} tee_service_ipc_msg_rsp;

typedef struct {
    uint32_t msg_id;
    uint32_t sender;
    tee_service_ipc_msg msg;
} tee_service_msg_t;
typedef struct {
    uint32_t in;
    uint32_t out;
    tee_service_msg_t msg[TEE_SERVICE_MSG_QUEUE_SIZE];
} tee_service_msg_queue_t;

void tee_common_ipc_proc_cmd(const char *task_name,
                             uint32_t snd_cmd, const tee_service_ipc_msg *snd_msg,
                             uint32_t ack_cmd, tee_service_ipc_msg_rsp *rsp_msg);
#endif
