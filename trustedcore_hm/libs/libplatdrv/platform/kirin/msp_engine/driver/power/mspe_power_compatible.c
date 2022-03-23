/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: compatible backward
 * Author: Security Engine
 * Create: 2020/10/19
 */
#include <mspe_power_compatible.h>
#include <mspe_power.h>
#include <common_utils.h>
#include "mspe_power_state_mgr.h"
#include <pal_types.h>
#include <pal_errno.h>

#define BSP_THIS_MODULE       BSP_MODULE_POWER

u32 hieps_power_on(u32 id, u32 profile)
{
	u32 ret;

	ret = mspe_power_on(id, profile);

	return (ret == BSP_RET_OK) ? 0 : ret;
}

u32 hieps_power_off(u32 id, u32 profile)
{
	u32 ret;

	UNUSED(profile);
	ret = mspe_power_off(id);

	return (ret == BSP_RET_OK) ? 0 : ret;
}

u32 hieps_get_power_status(void)
{
	if (mspe_power_get_hw_state().onoff == MSPE_POWER_OFF)
		return HIEPS_POWEROFF_STATUS;

	return ~HIEPS_POWEROFF_STATUS;
}

u32 hieps_get_cur_profile(void)
{
	return mspe_power_get_hw_state().profile;
}

u32 hieps_get_voted_nums(void)
{
	u32 i;
	u32 cnt = 0;

	for (i = 0; i < MSPE_POWER_ID_MAX; i++) {
		if (mspe_power_get_usr_state(i).onoff == MSPE_POWER_ON)
			cnt++;
	}

	return cnt;
}
