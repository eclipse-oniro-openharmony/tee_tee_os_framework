/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hieps plat config.
 * Author : z00452790, zhaohaisheng@huawei.com
 * Create: 2019/09/12
 */

#include "hieps_powerctrl_plat.h"
#include <register_ops.h> /* read32 */
#include <soc_acpu_baseaddr_interface.h>
#include <soc_ioc_interface.h>
#include <soc_pctrl_interface.h>
#include <soc_media2_crg_interface.h>
#include <soc_crgperiph_interface.h>
#include <soc_eps_config_interface.h>
#include <hieps_common.h>
#include "hieps_power.h"
#include "hieps_smc.h"


#define HIEPS_CLK_VALUE_MASK               0xF0
#define HIEPS_CLK_SETTING_MASK             0x00F00000
#define HIEPS_CLK_DIV_MASK                 0x003F0000

/* hieps low tempreature flag */
uint32_t g_hieps_low_tempreature_flag;

/* The clock frequency and div of hieps for different profile. */
struct hieps_power_param_type g_hieps_power_attr_list[PROFILE_TYPE_MAX] = {
	{HIEPS_PROFILE0_320, HIEPS_CLK_DIV3},
	{HIEPS_PROFILE1_240, HIEPS_CLK_DIV4},
	{HIEPS_PROFILE2_138, HIEPS_CLK_DIV7},
};

struct hieps_power_param_type *get_hieps_clk_attr_list(uint32_t profile)
{
	if (profile >= PROFILE_TYPE_MAX) {
		tloge("%s:Invalid profile:0x%x\n", __func__, profile);
		return NULL;
	}

	return &g_hieps_power_attr_list[profile];
}

/*
 * @brief      : hieps_set_ppll_source : set hieps clock source.
 *
 * @param[in]  : clk_src : source of hieps clock.
 *
 * @return     : OK: successful, ERROR: failed.
 */
uint32_t hieps_select_clk_source(void)
{
	uint32_t value, addr;
	uint32_t base = SOC_ACPU_MEDIA2_CRG_BASE_ADDR;
	SOC_MEDIA2_CRG_CLKDIV0_SEC_HIEPS_UNION config;

	addr = SOC_MEDIA2_CRG_CLKDIV0_SEC_HIEPS_ADDR(base);
	config.value = read32(addr);
	config.reg.sel_hieps_ahb = HIEPS_PPLL2;
	config.value |= HIEPS_CLK_SETTING_MASK;
	write32(addr, config.value);
	/* Read back to check. */
	value = read32(addr);
	if ((value & HIEPS_CLK_VALUE_MASK) !=
	    (config.value & HIEPS_CLK_VALUE_MASK))
		return HIEPS_CFG_CLK_SRC_ERR;

	return HIEPS_OK;
}

/*
 * @brief      : hieps_set_clk_div : set hieps clock div.
 *
 * @param[in]  : clkdiv : clock div.
 *
 * @return     : OK: successful, ERROR: failed.
 */
uint32_t hieps_set_clk_div(uint32_t clkdiv)
{
	SOC_MEDIA2_CRG_CLKDIV2_SEC_HIEPS_UNION config, check;
	uint32_t base = SOC_ACPU_MEDIA2_CRG_BASE_ADDR;
	uint32_t addr;

	addr = SOC_MEDIA2_CRG_CLKDIV2_SEC_HIEPS_ADDR(base);
	config.value = read32(addr);
	config.reg.div_hieps_ahb = clkdiv;
	config.value |= HIEPS_CLK_DIV_MASK;
	write32(addr, config.value);
	/* Read back to check. */
	check.value = read32(addr);
	if (check.reg.div_hieps_ahb != clkdiv)
		return HIEPS_CFG_CLK_DIV_ERR;

	return HIEPS_OK;
}

/*
 * @brief      : hieps_set_low_temperature_flag : set low temperature flag.
 *
 * @param[in]  : flag : the flag to set.
 */
void hieps_set_low_temperature_flag(uint32_t flag)
{
	g_hieps_low_tempreature_flag = flag;
}

/*
 * @brief      : hieps_get_low_temperature_flag : get low temperature flag.
 *
 * @return     : low temperature flag.
 */
uint32_t hieps_get_low_temperature_flag(void)
{
	return g_hieps_low_tempreature_flag;
}

/*
 * @brief      : hieps_cfg_rom_clk : config hieps clock for rom.
 *
 * @param[in]  : profile: the profile of rom.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
uint32_t hieps_cfg_clk_div(const uint32_t profile)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t div = 0;
	struct hieps_power_param_type *power_config = NULL;

	if (profile >= MAX_PROFILE) {
		tloge("hieps:Invalid param! profile:0x%x\n", profile);
		return HIEPS_PARAM_ERR;
	}

	power_config = get_hieps_clk_attr_list(profile);
	if (!power_config) {
		tloge("%s:get clock failed!\n", __func__);
		return HIEPS_ERROR;
	}

	div = power_config->hieps_bsp_div;

#ifdef CONFIG_HIEPS_LOW_TEMPERATURE
	if (hieps_get_low_temperature_flag() == LOW_TEMPERATURE_FLAG)
		div = HIEPS_CLK_DIV4; /* 240M  0.8V */
#endif
	hieps_set_clk_frequency(power_config->hieps_bsp_clk);
	ret = hieps_set_clk_div(div);
	if (ret != HIEPS_OK)
		tloge("hieps:config hieps clock div failed! ret = 0x%x\n", ret);

	return ret;
}
