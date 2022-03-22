/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: cc power header file
 * Create: 2019-11-26
 */

#ifndef _CC_POWER_H
#define _CC_POWER_H
#include <ipc_call.h>

int32_t secs_power_on(void);
int32_t secs_power_down(void);
int32_t cc_power_on(void);
int32_t cc_power_down(void);
void set_secs_suspend_flag(void);

#endif
