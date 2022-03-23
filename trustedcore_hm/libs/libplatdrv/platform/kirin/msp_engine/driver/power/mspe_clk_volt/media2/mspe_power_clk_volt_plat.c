/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp mspe clksrc/clkdiv config
 * Author: Security Engine
 * Create: 2020/10/19
 */
#include "mspe_power_clk_volt.h"
#include "mspe_power_state_mgr.h"
#include "mspe_power_msg_route.h"
#include <mspe_power.h>
#include <pal_types.h>
#include <pal_errno.h>
#include <pal_log.h>
#include <pal_memory.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_crgperiph_interface.h>
#include <register_ops.h>

#define BSP_THIS_MODULE BSP_MODULE_POWER

#ifndef NULL
#define NULL (void *)0
#endif
enum mspe_volt {
	MSPE_VOLT_08V = 0,
	MSPE_VOLT_07V,
	MSPE_VOLT_06V
};

enum mspe_freq {
	MSPE_FREQ_320M = 0,
	MSPE_FREQ_240M,
	MSPE_FREQ_192M,
	MSPE_FREQ_160M,
	MSPE_FREQ_138M,
};

enum mspe_clksrc {
	MSPE_CLKSRC_PPLL2 = 1,
};

enum mspe_clkdiv {
	MSPE_CLKDIV_6 = 5,
	MSPE_CLKDIV_8 = 7,
	MSPE_CLKDIV_10 = 9,
	MSPE_CLKDIV_14 = 13
};

struct mspe_profile_info {
	u32 volt;
	u32 freq;
	u32 clksrc;
	u32 clkdiv;
};

#ifdef CONFIG_ES_LOW_FREQ
static const struct mspe_profile_info g_mspe_power_profile_map_chip2[MSPE_POWER_PROFILE_MAX] = {
	[MSPE_POWER_PROFILE0] =         { MSPE_VOLT_08V, MSPE_FREQ_240M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_8 },
	[MSPE_POWER_PROFILE1] =         { MSPE_VOLT_07V, MSPE_FREQ_138M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_14 },
	[MSPE_POWER_PROFILE2] =         { MSPE_VOLT_06V, MSPE_FREQ_138M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_14 },
	[MSPE_POWER_PROFILE3] =         { MSPE_VOLT_06V, MSPE_FREQ_138M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_14 },
	[MSPE_POWER_PROFILE_LOW_TEMP] = { MSPE_VOLT_08V, MSPE_FREQ_240M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_8 }
};

static const struct mspe_profile_info *get_profile_map(u32 profile)
{
	if (profile >= MSPE_POWER_PROFILE_MAX)
		return NULL;

	return &g_mspe_power_profile_map_chip2[profile];
}
#else
static const struct mspe_profile_info g_mspe_power_profile_map[MSPE_POWER_PROFILE_MAX] = {
	[MSPE_POWER_PROFILE0] =         { MSPE_VOLT_08V, MSPE_FREQ_320M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_6 },
	[MSPE_POWER_PROFILE1] =         { MSPE_VOLT_07V, MSPE_FREQ_240M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_8 },
	[MSPE_POWER_PROFILE2] =         { MSPE_VOLT_06V, MSPE_FREQ_138M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_14 },
	[MSPE_POWER_PROFILE3] =         { MSPE_VOLT_06V, MSPE_FREQ_138M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_14 },
	[MSPE_POWER_PROFILE_LOW_TEMP] = { MSPE_VOLT_08V, MSPE_FREQ_240M, MSPE_CLKSRC_PPLL2, MSPE_CLKDIV_8 }
};

static const struct mspe_profile_info *get_profile_map(u32 profile)
{
	if (profile >= MSPE_POWER_PROFILE_MAX)
		return NULL;

	return &g_mspe_power_profile_map[profile];
}
#endif

#define MSPE_CLKSRC_READ_MASK  0xF0
#define MSPE_CLKSRC_WRITE_MASK (MSPE_CLKSRC_READ_MASK << 16)
static err_bsp_t mspe_power_cfg_clksrc(u32 profile)
{
	u32 addr = SOC_CRGPERIPH_CLKDIV1_HIFACE_SEC_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR);
	SOC_CRGPERIPH_CLKDIV1_HIFACE_SEC_UNION config;
	const struct mspe_profile_info *info = NULL;

	info = get_profile_map(profile);
	if (!info)
		return ERR_DRV(ERRCODE_NULL);
	config.value = pal_read_u32(addr);
	config.reg.sel_hieps_arc = info->clksrc;
	config.value |= MSPE_CLKSRC_WRITE_MASK;
	pal_write_u32(config.value, addr);

	if ((pal_read_u32(addr) & MSPE_CLKSRC_READ_MASK) !=
	    (config.value & MSPE_CLKSRC_READ_MASK))
		return ERR_DRV(ERRCODE_VERIFY);

	return BSP_RET_OK;
}

#define MSPE_CLKDIV_READ_MASK  0x03F0
#define MSPE_CLKDIV_WRITE_MASK (MSPE_CLKDIV_READ_MASK << 16)
static err_bsp_t mspe_power_cfg_clkdiv(u32 profile)
{
	u32 addr = SOC_CRGPERIPH_CLKDIV0_HIFACE_SEC_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR);
	SOC_CRGPERIPH_CLKDIV0_HIFACE_SEC_UNION config;
	const struct mspe_profile_info *info = NULL;

	info = get_profile_map(profile);
	if (!info)
		return ERR_DRV(ERRCODE_NULL);

	config.value = pal_read_u32(addr);
	config.reg.div_hieps_arc = info->clkdiv;
	config.value |= MSPE_CLKDIV_WRITE_MASK;
	pal_write_u32(config.value, addr);

	if ((pal_read_u32(addr) & MSPE_CLKDIV_READ_MASK) !=
	    (config.value & MSPE_CLKDIV_READ_MASK))
		return ERR_DRV(ERRCODE_VERIFY);

	return BSP_RET_OK;
}

err_bsp_t mspe_power_cfg_clk(u32 profile)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	ret = mspe_power_cfg_clksrc(profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = mspe_power_cfg_clkdiv(profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

err_bsp_t mspe_power_cfg_volt(u32 profile)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);

	ret = mspe_power_msg_route_to_bl31(MSPE_MSG_TYPE_POWER_DVFS, profile);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}
