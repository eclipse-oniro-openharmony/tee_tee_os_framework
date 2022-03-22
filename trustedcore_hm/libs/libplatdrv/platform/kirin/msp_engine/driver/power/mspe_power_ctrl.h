/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe power ctrl, top view of mspe power
 * Author: Security Engine
 * Create: 2020/10/27
 */
#ifndef MSPE_POWER_CTRL_H
#define MSPE_POWER_CTRL_H

#include <pal_types.h>
#include <mspe_power.h>

err_bsp_t mspe_power_ctrl(u32 id, struct mspe_power_state state);

#endif
