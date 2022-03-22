/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: compatible backward.
 * Author: Security Engine
 * Create: 2020/11/07
 */

#ifndef MSPE_POWER_COMPATIBLE_H
#define MSPE_POWER_COMPATIBLE_H

#include <pal_types.h>

#define HIEPS_POWEROFF_STATUS 0x55555555

u32 hieps_power_on(u32 id, u32 profile);
u32 hieps_power_off(u32 id, u32 profile);
u32 hieps_get_power_status(void);
u32 hieps_get_cur_profile(void);
enum sec_bool_e mspe_sm9_is_inited(void);
u32 hieps_get_voted_nums(void);

#endif
