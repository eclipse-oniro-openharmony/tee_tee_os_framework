/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of mspe power state manager
 * Author: Security Engine
 * Create: 2020/10/27
 */
#ifndef MSPE_POWER_STATE_MGR_H
#define MSPE_POWER_STATE_MGR_H

#include <pal_types.h>
#include <stdbool.h>
#include "mspe_power_ctrl.h"

void mspe_update_power_state(u32 id, struct mspe_power_state state);

bool mspe_power_is_low_temperature(void);

#endif
