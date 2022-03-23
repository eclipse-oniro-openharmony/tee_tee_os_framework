/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of mspe power
 * Author: Security Engine
 * Create: 2020/10/27
 */
#ifndef MSPE_POWER_MSPE_H
#define MSPE_POWER_MSPE_H

#include <pal_types.h>
#include "mspe_power_ctrl.h"

err_bsp_t mspe_power_on_mspe(u32 profile);
err_bsp_t mspe_power_off_mspe(void);
err_bsp_t mspe_power_mspe_ctrl(u32 id, struct mspe_power_state state);

#endif