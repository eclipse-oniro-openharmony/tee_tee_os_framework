/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe power mspe, choose power on/power off/dvfs
 * Author: Security Engine
 * Create: 2020/10/27
 */
#include "mspe_power_mspe.h"
#include "mspe_power_dvfs.h"
#include "mspe_power_state_mgr.h"
#include <mspe_power.h>
#include <pal_errno.h>
#include <pal_log.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

static mspe_power_hook_t g_mspe_power_hook = (mspe_power_hook_t)0;

void mspe_power_register_hook(mspe_power_hook_t hook)
{
	g_mspe_power_hook = hook;
}

static err_bsp_t do_mspe_power_ctrl(struct mspe_power_state old_state, struct mspe_power_state new_state)
{
	if (old_state.onoff == MSPE_POWER_OFF &&
	    new_state.onoff == MSPE_POWER_ON)
		return mspe_power_on_mspe(new_state.profile);

	if (old_state.onoff == MSPE_POWER_ON &&
	    new_state.onoff == MSPE_POWER_OFF)
		return mspe_power_off_mspe();

	return ERR_DRV(ERRCODE_PARAMS);
}

static err_bsp_t do_mspe_dvfs_ctrl(struct mspe_power_state old_state, struct mspe_power_state new_state)
{
	/*
	 * both old state and new state is power on,
	 * we will do dvfs.
	 */
	if (!(old_state.onoff == MSPE_POWER_ON &&
	      new_state.onoff == MSPE_POWER_ON))
		return BSP_RET_OK;

	if (new_state.profile < old_state.profile)
		return mspe_power_dvfs_up(new_state.profile);

	if (new_state.profile > old_state.profile)
		return mspe_power_dvfs_down(new_state.profile);

	/* new profile is same to old profile, do nothing */
	return BSP_RET_OK;
}

err_bsp_t mspe_power_mspe_ctrl(u32 id, struct mspe_power_state state)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	struct mspe_power_state old_state;
	struct mspe_power_state new_state;

	old_state = mspe_power_get_hw_state();
	mspe_update_power_state(id, state);
	new_state = mspe_power_get_hw_state();

	if (new_state.onoff != old_state.onoff)
		ret = do_mspe_power_ctrl(old_state, new_state);
	else
		ret = do_mspe_dvfs_ctrl(old_state, new_state);
	if (PAL_CHECK(ret != BSP_RET_OK)) {
		state.onoff = MSPE_POWER_OFF;
		mspe_update_power_state(id, state);
		return ret;
	}

	if (g_mspe_power_hook) {
		ret = g_mspe_power_hook(id, old_state, new_state);
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
	}

	return ret;
}
