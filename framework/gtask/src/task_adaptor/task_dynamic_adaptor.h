/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2022. All rights reserved.
 * Description: interface declaration for ssa task adaptor
 * Create: 2019-10-28
 */

#ifndef GTASK_TASK_DYNAMIC_ADAPTOR_H
#define GTASK_TASK_DYNAMIC_ADAPTOR_H

#include "task_adaptor.h"
#include "gtask_inner.h"

#define TASK_PRIO_ART_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_BIO_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_CRYPTO_AGENT_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_HSM_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_HUK_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_ROT_SERVICE (DEFAULT_TASK_PRIO - 1)
#define TASK_PRIO_VLTMM_SRV (DEFAULT_TASK_PRIO - 1)

void register_dynamic_task(const TEE_UUID *uuid, const char *task_name,
    const struct srv_adaptor_config_t *srv_config);

#endif
