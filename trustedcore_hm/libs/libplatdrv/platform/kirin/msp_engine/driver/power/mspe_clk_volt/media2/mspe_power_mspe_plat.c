/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe power, hardware level
 * Author: Security Engine
 * Create: 2020/10/27
 */
#include <mspe_power_mspe.h>
#include <mspe_power_msg_route.h>
#include <mspe_power_clk_volt.h>
#include <pal_errno.h>
#include <pal_log.h>
#include <pal_memory.h>
#include <pal_timer.h>
#include <soc_sctrl_interface.h>
#include <soc_acpu_baseaddr_interface.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

static void mspe_key_decompress(void)
{
	SOC_SCTRL_SCPERCTRL5_UNION ctrl5;
	u32 addr = SOC_SCTRL_SCPERCTRL5_ADDR(SOC_ACPU_SCTRL_BASE_ADDR);

	ctrl5.value = pal_read_u32(addr);
	ctrl5.reg.hieps_resume = 1;
	pal_write_u32(ctrl5.value, addr);
	pal_udelay(100);
	ctrl5.reg.hieps_resume = 0;
	pal_write_u32(ctrl5.value, addr);
}

err_bsp_t mspe_power_on_mspe(u32 profile)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	/* enable ppll2, power on media2/vcodec/mspe */
	ret = mspe_power_msg_route_to_bl31(MSPE_MSG_TYPE_POWER_ON_MSPE, profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = mspe_power_cfg_clk(profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	mspe_key_decompress();

	return ret;
}

err_bsp_t mspe_power_off_mspe(void)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	ret = mspe_power_msg_route_to_bl31(MSPE_MSG_TYPE_POWER_OFF_MSPE, 0);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}
