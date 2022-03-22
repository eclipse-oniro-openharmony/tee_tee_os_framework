/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of mspe clk
 * Author: Security Engine
 * Create: 2020/10/19
 */
#ifndef MSPE_POWER_CLK_VOLT_H
#define MSPE_POWER_CLK_VOLT_H

#include <pal_types.h>

err_bsp_t mspe_power_cfg_clk(u32 profile);
err_bsp_t mspe_power_cfg_volt(u32 profile);

#endif
