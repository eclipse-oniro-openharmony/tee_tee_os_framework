/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2022. All rights reserved.
 * Description: public msg id and structure defination for tee internal task
 * Create: 2019-11-07
 */

#ifndef TEE_INTERNAL_TASK_PUB_H
#define TEE_INTERNAL_TASK_PUB_H

#include <stddef.h>
#include "types.h"
#include "tee_defines.h"
#include "ta_framework.h"
#include "tee_service_public.h"

/*
 * here 10 is based on experience, we need to ensure that
 * the number of clients accessing the service does not exceed this SRV_MAX_CLIENTS
 */
#define SRV_MAX_CLIENTS (10 * TA_SESSION_MAX)

/*
 * these pub cmd should be defined very carefully,
 * cannot conflict with cmd of internal tasks
 */
enum TEE_INTERNAL_TASK_MSG_CMD {
    TEE_TASK_MSG_BASE            = 0x1000,
    TEE_TASK_REGISTER_TA         = TEE_TASK_MSG_BASE + 1, /* gtask send TA open session msg to internal task */
    TEE_TASK_UNREGISTER_TA       = TEE_TASK_MSG_BASE + 2, /* gtask send TA close session msg to internal task */
    TEE_TASK_REGISTER_AGENT      = TEE_TASK_MSG_BASE + 3, /* only for ssa, gtask -> ssa */
    TEE_TASK_SET_CALLER_INFO     = TEE_TASK_MSG_BASE + 4, /* internal task send caller ta gtask */
    TEE_TASK_SET_CALLER_INFO_ACK = TEE_TASK_MSG_BASE + 5, /* gtask -> internal task */
    TEE_TASK_AGENT_SMC_CMD       = TEE_TASK_MSG_BASE + 6, /* system agent service -> gtask */
    TEE_TASK_AGENT_SMC_ACK       = TEE_TASK_MSG_BASE + 7, /* gtask -> system agent service */
    TEE_TASK_UNRESISTER_SERVICE  = TEE_TASK_MSG_BASE + 8, /* dynamic service to gtask */
    TEE_TASK_TA_CREATE           = TEE_TASK_MSG_BASE + 9, /* gtask send TA create service msg to internal task */
    TEE_TASK_TA_RELEASE          = TEE_TASK_MSG_BASE + 10, /* gtask send TA release service msg to internal task */
    TEE_TASK_MSG_END
};

struct reg_agent_buf {
    uint32_t agentid;
    paddr_t phys_addr;
    uint32_t size;
};

struct task_caller_info {
    uint32_t taskid;
    uint32_t cmd;
};

#endif
