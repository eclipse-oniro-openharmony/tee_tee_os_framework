/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: for adapt hal
 * Create: 2019.04.11
 */

#include <hieps_common.h>
#include <hieps_power.h>
#include <hieps_errno.h>

#define POWER_ON      1
#define POWER_OFF     2
#define POWER_ID      0
#define HIEPS_SUPPORT 0x7C

_Bool eps_support_cdrmenhance(void)
{
    uint32_t ret = is_support_hieps();
    if (ret == HIEPS_SUPPORT)
        return true;
    else
        return false;
}
uint32_t eps_ctrl(uint32_t type, uint32_t profile)
{
    uint32_t ret = HIEPS_PARAM_ERR;

    if (type == POWER_ON)
        ret = hieps_power_on(POWER_ID, profile);
    else if (type == POWER_OFF)
        ret = hieps_power_off(POWER_ID, profile);
    else
        tloge("type is invalid!");

    return ret;
}
