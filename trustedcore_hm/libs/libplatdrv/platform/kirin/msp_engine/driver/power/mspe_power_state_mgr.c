/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe power state manager
 * Author: Security Engine
 * Create: 2020/10/27
 */
#include "mspe_power_state_mgr.h"
#include <mspe_power.h>
#include <pal_memory.h>
#include <stdbool.h>
#include <soc_pmctrl_interface.h>
#include <soc_acpu_baseaddr_interface.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

struct mspe_power_state_mgr {
	struct mspe_power_state hwstate;
	struct mspe_power_state usrstate[MSPE_POWER_ID_MAX];
};

static struct mspe_power_state_mgr g_mspe_power_state_mgr = {
	{ MSPE_POWER_OFF, MSPE_POWER_PROFILE0 }, /* hardware state */
	{
		{ MSPE_POWER_OFF, MSPE_POWER_PROFILE0 },  /* CDRM */
		{ MSPE_POWER_OFF, MSPE_POWER_PROFILE0 },  /* HDCP */
		{ MSPE_POWER_OFF, MSPE_POWER_PROFILE0 },  /* SEC_BOOT */
		{ MSPE_POWER_OFF, MSPE_POWER_PROFILE0 },  /* DICE */
		{ MSPE_POWER_OFF, MSPE_POWER_PROFILE0 },  /* PRIP */
		{ MSPE_POWER_OFF, MSPE_POWER_PROFILE0 },  /* HIAI */
	}
};

static void mspe_power_update_usr_state(u32 id, struct mspe_power_state state)
{
	struct mspe_power_state old_state;

	old_state = mspe_power_get_usr_state(id);

	/* switch to on or switch to off */
	if ((old_state.onoff == MSPE_POWER_OFF && state.onoff == MSPE_POWER_ON) ||
	    state.onoff == MSPE_POWER_OFF) {
		g_mspe_power_state_mgr.usrstate[id] = state;
		return;
	}

	/* dvfs */
	if (old_state.onoff == MSPE_POWER_ON && state.onoff == MSPE_POWER_ON) {
		/* update usr profile */
		if (state.profile < old_state.profile)
			g_mspe_power_state_mgr.usrstate[id].profile = state.profile;
	}
}

static void mspe_power_update_hw_state(void)
{
	u32 i;
	struct mspe_power_state usr_state;
	struct mspe_power_state hw_state = { MSPE_POWER_OFF, MSPE_POWER_PROFILE_MAX };

	/* one or more id vote, then reminded POWER_ON, hardware will use the highest profile(freq) */
	for (i = 0; i < MSPE_POWER_ID_MAX; i++) {
		usr_state = mspe_power_get_usr_state(i);
		if (usr_state.onoff == MSPE_POWER_OFF)
			continue;

		/* find min profile */
		if (usr_state.profile < hw_state.profile)
			hw_state.profile = usr_state.profile;

		hw_state.onoff = MSPE_POWER_ON;
	}

	g_mspe_power_state_mgr.hwstate = hw_state;
}

struct mspe_power_state mspe_power_get_hw_state(void)
{
	return g_mspe_power_state_mgr.hwstate;
}

struct mspe_power_state mspe_power_get_usr_state(u32 id)
{
	if (id >= MSPE_POWER_ID_MAX)
		return g_mspe_power_state_mgr.usrstate[MSPE_POWER_ID_MAX - 1];

	return g_mspe_power_state_mgr.usrstate[id];
}

/* when new user called power on/off, state need updated */
void mspe_update_power_state(u32 id, struct mspe_power_state state)
{
	if (id >= MSPE_POWER_ID_MAX)
		return;

	mspe_power_update_usr_state(id, state);
	mspe_power_update_hw_state();
}

#define LOW_TEMPERATURE_MASK 0xC000000 /* bit 27:26 */
#define NORMAL_TEMPERATURE   0
bool mspe_power_is_low_temperature(void)
{
	u32 value;
	u32 addr = SOC_PMCTRL_PERI_CTRL4_ADDR(SOC_ACPU_PMC_BASE_ADDR);

	value = pal_read_u32(addr);
	value &= LOW_TEMPERATURE_MASK;

	return value != NORMAL_TEMPERATURE;
}

