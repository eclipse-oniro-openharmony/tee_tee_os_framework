/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: internal task enable flag for gtask
 * Create: 2019-10-28
 */

#ifndef TEE_TASK_CONFIG_H
#define TEE_TASK_CONFIG_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool is_ssa_enable(void);
bool is_se_service_enable(void);
#endif
