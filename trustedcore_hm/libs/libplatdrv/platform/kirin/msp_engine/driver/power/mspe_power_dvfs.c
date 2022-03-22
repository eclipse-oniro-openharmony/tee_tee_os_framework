/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe dvfs
 * Author: Security Engine
 * Create: 2020/10/27
 */
#include "mspe_power_dvfs.h"
#include "mspe_power_clk_volt.h"
#include <pal_errno.h>
#include <pal_log.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

/* first volt up, then mspe freq up */
err_bsp_t mspe_power_dvfs_up(u32 profile)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	ret = mspe_power_cfg_volt(profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = mspe_power_cfg_clk(profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

/* first freq down, then vold down */
err_bsp_t mspe_power_dvfs_down(u32 profile)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	ret = mspe_power_cfg_clk(profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	mspe_power_cfg_volt(profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}
