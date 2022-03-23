/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: declaration of mspe dvfs
 * Author: Security Engine
 * Create: 2020/10/27
 */
#ifndef MSPE_POWER_DVFS_H
#define MSPE_POWER_DVFS_H

#include <pal_types.h>

err_bsp_t mspe_power_dvfs_up(u32 profile);
err_bsp_t mspe_power_dvfs_down(u32 profile);

#endif