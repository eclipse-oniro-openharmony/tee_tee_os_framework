/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe power ctrl, top view of mspe power
 * Author: Security Engine
 * Create: 2020/10/27
 */
#include "mspe_power_ctrl.h"
#include "mspe_power_mspe.h"
#include "mspe_power_state_mgr.h"
#include <mspe_power.h>
#include <pal_errno.h>
#include <pal_log.h>
#include <sre_typedef.h>
#include <hieps_common.h> /* lock declaration */

#define BSP_THIS_MODULE BSP_MODULE_POWER

static void mspe_preprocess_profile_for_low_temperature(struct mspe_power_state *state)
{
	if (state->onoff != MSPE_POWER_ON)
		return;

	if (mspe_power_is_low_temperature())
		state->profile = MSPE_POWER_PROFILE_LOW_TEMP;
}

/* PROFILE_KEEP will follow current hardware profile */
static void mspe_preprocess_profile_for_keep(struct mspe_power_state *state)
{
	struct mspe_power_state hwstate;

	if (state->profile != MSPE_POWER_PROFILE_KEEP)
		return;

	hwstate = mspe_power_get_hw_state();
	if (hwstate.onoff == MSPE_POWER_ON)
		state->profile = hwstate.profile;
	else
		state->profile = MSPE_POWER_PROFILE0;
}

static void mspe_preprocess_profile(struct mspe_power_state *state)
{
	mspe_preprocess_profile_for_keep(state);
	mspe_preprocess_profile_for_low_temperature(state);
}

err_bsp_t mspe_power_ctrl(u32 id, struct mspe_power_state state)
{
	s32 sre_ret;
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	sre_ret = pthread_mutex_lock(&g_hieps_data.power_lock);
	if (PAL_CHECK(sre_ret != SRE_OK)) {
		PAL_ERROR("mspe power mutex lock fail\n");
		return ERR_DRV(ERRCODE_REQUEST);
	}

	mspe_preprocess_profile(&state);
	ret = mspe_power_mspe_ctrl(id, state);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto error;

error:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.power_lock);
	if (PAL_CHECK(sre_ret != SRE_OK))
		PAL_ERROR("mspe power mutex unlock fail\n");

	return ret;
}
