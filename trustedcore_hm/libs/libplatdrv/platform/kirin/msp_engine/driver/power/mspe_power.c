/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe power
 * Author: Security Engine
 * Create: 2020/10/27
 */
#include <mspe_power.h>
#include "mspe_power_ctrl.h"
#include "mspe_power_state_mgr.h"
#include <common_utils.h>
#include <pal_log.h>
#include <pal_errno.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

err_bsp_t mspe_power_on(u32 id, u32 profile)
{
	struct mspe_power_state state = {
		.onoff = MSPE_POWER_ON,
		.profile = profile
	};

	if (PAL_CHECK(id >= MSPE_POWER_ID_MAX || profile >= MSPE_POWER_PROFILE_MAX))
		return ERR_DRV(ERRCODE_PARAMS);

	return mspe_power_ctrl(id, state);
}

err_bsp_t mspe_power_off(u32 id)
{
	struct mspe_power_state state = {
		.onoff = MSPE_POWER_OFF,
		.profile = MSPE_POWER_PROFILE_MAX /* unused */
	};

	if (PAL_CHECK(id >= MSPE_POWER_ID_MAX))
		return ERR_DRV(ERRCODE_PARAMS);

	return mspe_power_ctrl(id, state);
}

err_bsp_t mspe_power_suspend(void)
{
	u32 id;

	for (id = MSPE_POWER_ID_CDRM; id < MSPE_POWER_ID_MAX; id++)
		(void)mspe_power_off(id);

	return BSP_RET_OK;
}

