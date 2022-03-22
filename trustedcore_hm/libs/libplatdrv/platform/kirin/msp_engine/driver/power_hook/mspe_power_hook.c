/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp power hook.
 * init: every time when hardware switch to power on, we will do init.
 * selftst:selftest will be done only once during the whole lifecycle.
 * sm9: only prip, we will do sm9_init and sm9 selftest.
 * Author: Security Engine
 * Create: 2020/11/04
 */
#include <mspe_power_hook.h>
#include <mspe_power.h>
#include <mspe_crypto_init.h>
#include <mspe_crypto_selftest.h>
#include <common_define.h>
#include <pal_log.h>
#include <pal_errno.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

struct mspe_power_hook_flag {
	u32 base_selftest;
	u32 sm9_init;
	u32 sm9_selftest;
};

static struct mspe_power_hook_flag g_mspe_power_hook_flag = { SEC_FALSE, SEC_FALSE, SEC_FALSE };

static err_bsp_t mspe_power_hook_crypto_init(u32 id, struct mspe_power_state old_state,
					     struct mspe_power_state new_state)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	/* every time hardware power on, base init will be done */
	if (old_state.onoff == MSPE_POWER_OFF &&
	    new_state.onoff == MSPE_POWER_ON) {
		ret = mspe_crypto_base_init();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
	}

	/* when prip, sm9 init will be done */
	if (id == MSPE_POWER_ID_PRIP && g_mspe_power_hook_flag.sm9_init == SEC_FALSE) {
		ret = mspe_crypto_sm9_init();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		g_mspe_power_hook_flag.sm9_init = SEC_TRUE;
	}

	/* every time hardware power down, clear sm9 init flag */
	if (old_state.onoff == MSPE_POWER_ON &&
	    new_state.onoff == MSPE_POWER_OFF) {
		g_mspe_power_hook_flag.sm9_init = SEC_FALSE;
	}

	return ret;
}

static err_bsp_t mspe_power_hook_crypto_selftest(u32 id)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	if (g_mspe_power_hook_flag.base_selftest == SEC_TRUE &&
	    g_mspe_power_hook_flag.sm9_selftest == SEC_TRUE)
		return BSP_RET_OK;

	/* selftest will be done only once during the whole lifecycle. */
	ret = mspe_crypto_base_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	g_mspe_power_hook_flag.base_selftest = SEC_TRUE;

	if (id == MSPE_POWER_ID_PRIP && g_mspe_power_hook_flag.sm9_selftest == SEC_FALSE) {
		ret = mspe_crypto_sm9_selftest();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		g_mspe_power_hook_flag.sm9_selftest = SEC_TRUE;
	}

	return ret;
}

static err_bsp_t mspe_power_hook(u32 id, struct mspe_power_state old_state,
				 struct mspe_power_state new_state)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	ret = mspe_power_hook_crypto_init(id, old_state, new_state);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	ret = mspe_power_hook_crypto_selftest(id);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return BSP_RET_OK;
}

void mspe_power_hook_init(void)
{
	mspe_power_register_hook(mspe_power_hook);
}

enum sec_bool_e mspe_sm9_is_inited(void)
{
	return g_mspe_power_hook_flag.sm9_selftest;
}

