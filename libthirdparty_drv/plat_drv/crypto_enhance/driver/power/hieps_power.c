/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines hieps power control driver.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#include <register_ops.h>
#include <sre_typedef.h>
#include <pthread.h>
#include <tee_log.h>
#include <hieps_common.h>
#include <hieps_smc.h>
#include <hieps_errno.h>
#include <hieps_timer.h>
#include <hieps_power.h>
#include <soc_crgperiph_interface.h>
#include <soc_pctrl_interface.h>
#include <hieps_pm.h>
#include <hieps_ipc.h>




 /* Record the staus of hieps power */
hieps_power_vote_status g_hieps_power_status = { HIEPS_POWEROFF_STATUS };
 /* Back-up of power staus. */
hieps_power_vote_status g_hieps_power_status_backup = { HIEPS_POWEROFF_STATUS };

/* Record the current profile of hieps. */
hieps_profile_status g_hieps_profile_status =
	{ MAX_PROFILE, {MAX_PROFILE, MAX_PROFILE, MAX_PROFILE, MAX_PROFILE, MAX_PROFILE, MAX_PROFILE} };

/* hieps low tempreature flag */
uint32_t g_hieps_low_tempreature_flag;

/* The clock frequency of hieps rom and bsp for different profile. */
static const hieps_power_param_type g_hieps_power_attr_list[MAX_PROFILE] = {
	{HIEPS_CLK_FREQUENCY_480M, HIEPS_CLK_DIV4, HIEPS_CLK_FREQUENCY_640M, HIEPS_CLK_DIV3},
	{HIEPS_CLK_FREQUENCY_480M, HIEPS_CLK_DIV4, HIEPS_CLK_FREQUENCY_480M, HIEPS_CLK_DIV4},
	{HIEPS_CLK_FREQUENCY_384M, HIEPS_CLK_DIV5, HIEPS_CLK_FREQUENCY_384M, HIEPS_CLK_DIV5},
	{HIEPS_CLK_FREQUENCY_274M, HIEPS_CLK_DIV7, HIEPS_CLK_FREQUENCY_274M, HIEPS_CLK_DIV7},
};


/*
 * @brief      : hieps_clear_power_status : clear hieps power status.
 */
void hieps_clear_power_status(void)
{
	uint32_t i;

	g_hieps_power_status.value = HIEPS_POWEROFF_STATUS;
	g_hieps_profile_status.profile_status = MAX_PROFILE;
	for (i = 0; i < MAX_POWER_ID; i++) {
		g_hieps_profile_status.profile_vote[i] = MAX_PROFILE;
	}

	return;
}

/*
 * @brief      : hieps_get_power_status : get the status of hieps current power status.
 *
 * @return     : the status value.
 */
uint32_t hieps_get_power_status(void)
{
	return g_hieps_power_status.value;
}

/*
 * @brief      : hieps_set_power_status : set the power status of hieps.
 *
 * @param[in]  : id: the vote id.
 * @param[in]  : cmd: the vote command.
 */
static void hieps_set_power_status(uint32_t id, hieps_smc_cmd_type cmd)
{
	uint32_t value;

	if ((id >= MAX_POWER_ID) || ((cmd != HIEPS_POWER_ON_CMD) &&\
			(cmd != HIEPS_POWER_OFF_CMD))) {
		tloge("hieps:set hieps power status failed:id = 0x%x,\
				cmd = 0x%x!\n", id, cmd);
		return;
	}

	if (cmd == HIEPS_POWER_ON_CMD) {
		value = HIEPS_ON;
		hieps_set_status(HIEPS_ON);
	} else {
		value = HIEPS_OFF;
	}

	switch (id) {
	case CHINA_DRM:
		g_hieps_power_status.status.china_drm = value;
		break;
	case HDCP:
		g_hieps_power_status.status.hdcp = value;
		break;
	case SEC_BOOT:
		g_hieps_power_status.status.sec_boot = value;
		break;
	case DICE:
		g_hieps_power_status.status.dice = value;
		break;
	case PRIP:
		g_hieps_power_status.status.prip = value;
		break;
	case HIAI:
		g_hieps_power_status.status.hiai = value;
		break;
	default:
		tloge("hieps: power status set id error!\n");
	}

	return;
}

/*
 * @brief      : hieps_get_profile : get the hieps current profile.
 *
 * @return     : the profile value.
 */
hieps_profile_status hieps_get_profile(void)
{
	return g_hieps_profile_status;
}

/*
 * @brief      : hieps_update_profile : update hieps profile status.
 *
 * @param[in]  : id : vote id.
 * @param[in]  : profile : vote profile.
 * @param[in]  : cmd : vote command.
 */
static void hieps_update_profile(const uint32_t id, const uint32_t profile,\
	   const hieps_smc_cmd_type cmd)
{
	if ((id >= MAX_POWER_ID) || (profile >= MAX_PROFILE) ||\
		((cmd != HIEPS_POWER_ON_CMD) && (cmd != HIEPS_POWER_OFF_CMD))) {
		tloge("hieps:update hieps profile failed:id:0x%x, profile:0x%x, cmd:0x%x!\n",\
				  id, profile, cmd);
		return;
	}

	/* Update the profile of the specify id. */
	if (cmd == HIEPS_POWER_ON_CMD) {
		g_hieps_profile_status.profile_vote[id] = profile;
	} else {
		/* clear the profile status of the specify id. */
		g_hieps_profile_status.profile_vote[id] = MAX_PROFILE;
	}

	return;
}

/*
 * @brief      : hieps_set_current_profile : set hieps current profile.
 *
 * @param[in]  : profile
 */
static void hieps_set_current_profile(const uint32_t profile)
{
	if (profile > MAX_PROFILE) {
		tloge("hieps:Invalid param!\n");
	}
	g_hieps_profile_status.profile_status = profile;
}

/*
 * @brief      : hieps_set_low_temperature_flag : set low temperature flag.
 *
 * @param[in]  : flag : the flag to set.
 */
static void hieps_set_low_temperature_flag(uint32_t flag)
{
	g_hieps_low_tempreature_flag = flag;
}

/*
 * @brief      : hieps_get_low_temperature_flag : get low temperature flag.
 *
 * @return     : low temperature flag.
 */
static uint32_t hieps_get_low_temperature_flag(void)
{
	return g_hieps_low_tempreature_flag;
}

/*
 * @brief      : hieps_print_power_status : print hieps power status.
 */
static void hieps_print_power_status(void)
{
	uint32_t i = 0;
	uint32_t vote_status = 0;
	hieps_profile_status  profile_status = { 0 };

	vote_status = hieps_get_power_status();
	profile_status = hieps_get_profile();

	tloge("hieps:power status:0x%x\n", vote_status);
	tloge("hieps:current profile:0x%x\n", profile_status.profile_status);
	for (i = 0; i < MAX_POWER_ID; i++) {
		tloge("hieps:For id 0x%x, profile is 0x%x\n",\
			   i, profile_status.profile_vote[i]);
	}

	return;
}

/*
 * @brief      : hieps_select_clk_source : config the clock source of hieps.
 *
 * @return     : HIEPS_OK:successfly, HIEPS_CFG_CLK_SRC_ERR:failed.
 */
static uint32_t hieps_select_clk_source(void)
{
	SOC_CRGPERIPH_CLKDIV1_HIFACE_SEC_UNION cfg = { 0 };
	SOC_CRGPERIPH_CLKDIV1_HIFACE_SEC_UNION result = { 0 };
	uint32_t addr;

	addr = SOC_CRGPERIPH_CLKDIV1_HIFACE_SEC_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR);

	/* Select ppll2 as hiesp clk source. */
	cfg.reg.sel_hieps_arc = HIEPS_CLK_PPLL2; 
	cfg.value |= HIEPS_CLK_SRC_MASK;
	write32(addr, cfg.value);

	/* Read the result to check. */
	result.value = read32(addr);
	if (result.reg.sel_hieps_arc != HIEPS_CLK_PPLL2) {
		tloge("hieps: config hieps clk source register failed!\n");
		return HIEPS_CFG_CLK_SRC_ERR;
	}

	return HIEPS_OK;
}

/*
 * @brief      : hieps_set_clk_div : config the div of hieps clock.
 *
 * @param[in]  : div: the value to be set.
 *
 * @return     : HIEPS_OK:successfly, HIEPS_CFG_CLK_DIV_ERR:failed.
 */
static uint32_t hieps_set_clk_div(const uint32_t div)
{
	SOC_CRGPERIPH_CLKDIV0_HIFACE_SEC_UNION cfg;
	SOC_CRGPERIPH_CLKDIV0_HIFACE_SEC_UNION result;
	uint32_t addr;

	cfg.reg.div_hieps_arc = div;
	cfg.value |= HIEPS_CLK_DIV_MASK;
	addr = SOC_CRGPERIPH_CLKDIV0_HIFACE_SEC_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR);
	write32(addr, cfg.value);

	/* Read the result to check. */
	result.value = read32(addr);
	if (result.reg.div_hieps_arc != div) {
		tloge("hieps: config hieps clk div register failed!\n");
		return HIEPS_CFG_CLK_DIV_ERR;
	}

	return HIEPS_OK;
}


/*
 * @brief      : hieps_cfg_rom_clk : config hieps clock for rom.
 *
 * @param[in]  : profile: the profile of rom.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static uint32_t hieps_cfg_clk_div(const uint32_t profile, hieps_phase_type phase)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t div = 0;

	if ((profile >= MAX_PROFILE) || (phase != HIEPS_ROM_PHASE && phase != HIEPS_BSP_PHASE)) {
		tloge("hieps:Invalid param! profile:0x%x, phase:0x%x\n",\
				  profile, phase);
		return HIEPS_PARAM_ERR;
	}

	if (phase == HIEPS_ROM_PHASE) {
		div = g_hieps_power_attr_list[profile].hieps_rom_div;
	} else {
		div = g_hieps_power_attr_list[profile].hieps_bsp_div;
	}

	if (LOW_TEMPERATURE_FLAG == hieps_get_low_temperature_flag()) {
		div = HIEPS_CLK_DIV4; /* 480M */
	}

	ret = hieps_set_clk_div(div);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps clock div failed! ret = 0x%x, phase = 0x%x\n",\
				  ret, phase);
	}

	return ret;
}

/*
 * @brief      : hieps_cfg_clk : config the rom clock.
 *
 * @param[in]  : profile: the profile to set.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static uint32_t hieps_cfg_clk(const uint32_t profile)
{
	uint32_t ret;

	ret = hieps_select_clk_source();
	if (ret != HIEPS_OK) {
		tloge("hieps:select hieps clock source failed! ret = 0x%x\n", ret);
		return ret;
	}

	ret = hieps_cfg_clk_div(profile, HIEPS_ROM_PHASE);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps rom clock failed! ret = 0x%x\n", ret);
		return ret;
	}

	return ret;
}

/*
 * @brief      : hieps_power_process : poweron hieps by send command to kernel.
 *
 * @param[in]  : profile: the profile of hieps.
 * @param[in]  : cmd: the power command.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
uint32_t hieps_power_process(const uint32_t profile, const uint32_t cmd)
{
	uint32_t ret;
	uint32_t timeout = HIEPS_POWER_OFF_TIMEOUT;

	/* If command is power off, send message to hieps to
	 * check whether can power off now.
	 */
	if (cmd == HIEPS_POWER_OFF_CMD) {
		write32(HIEPS_POWER_OFF_READY_ADDR, ~HIEPS_POWER_OFF_READY);
		hieps_disable_ipc_irq();
		ret = hieps_send_power_msg();
		if (ret != HIEPS_OK) {
			tloge("hieps:send power msg failed! ret=0x%x\n", ret);
		} else {
			ret = hieps_wait_poweroff_ready(timeout);
			if (ret != HIEPS_OK) {
				tloge("hieps wait poweroff ready timeout!\n");
			} else {
				hieps_udelay(2); /* delay 2us to guarantee arc to sleep. */
			}
		}
	}

	ret = hieps_send_power_cmd(cmd, profile);

	/* Restore hieps ipc interrupt. */
	if (cmd == HIEPS_POWER_OFF_CMD) {
		hieps_enable_ipc_irq();
	}

	return ret;
}

/*
 * @brief      : hieps_rompatch_init : set the hieps rompatch if neccessary.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static uint32_t hieps_rompatch_init(void)
{
	/* Modify this func when a rompatch is needed.
	 * For now, donot enable rompatch. */
	write32(HIEPS_ROMPATCH_FLAG_ADDR, ~HIEPS_ROMPATCH_VALID_MAGIC);
	return HIEPS_OK;
}

/*
 * @brief      : hieps_cfg_boot_flag : config hieps boot flag.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static void hieps_cfg_boot_flag()
{
	/* Set boot type: sys or test. */
	write32(HIEPS_BOOT_TYPE_ADDR, HIEPS_BOOT_SYS_IMG);
	/* Set hieps image address. */
	write32(HIEPS_IMAGE_BASE_ADDR, HIEPS_IMG_BASE);
	/* Set hieps image size. */
	write32(HIEPS_IMAGE_SIZE_ADDR, HIEPS_IMG_SIZE);
	/* Set hieps running address. */
	write32(HIEPS_BOOT_START_ADDR, HIEPS_BOOT_START);
	/* Set hieps rom porcess flag. */
	write32(HIEPS_PROCESS_FLAG_ADDR, HIEPS_PROCESS_RUN);
}

/*
 * @brief      : hieps_cfg_rom_attribution : set the hieps boot flags and attribution. 
 *
 * @param[in]  : profile: the hieps profile.
 */
static uint32_t hieps_cfg_rom_attribution(const uint32_t profile)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t value;
	uint32_t result;

	/* Set clk flag to transfer the current clock to rom. */
	write32(HIEPS_BASE_CLK_ADDR, g_hieps_power_attr_list[profile].hieps_rom_clk);
	/* Clear the bsp clk sync flag. */
	write32(HIEPS_BSP_CLK_SYNC_ADDR, 0);
	/* Set hieps ddr base address to rom. */
	write32(HIEPS_BASE_DDR_ADDR, HIEPS_BASE_DDR);

	/* Config hieps access ddr without L3 cache. */
	value = read32(HIEPS_NOC_CTRL_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	value |= BIT(HIEPS_ARC2NOC_AXCACHE_MUX_BIT);
	write32(HIEPS_NOC_CTRL_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR), value);
	result = read32(HIEPS_NOC_CTRL_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	/* Read back to check. */
	if (result & BIT(HIEPS_CFG_ARC_WR_CACHE_MASK)) {
		tloge("hieps: config hieps access ddr without L3 cache failed!\n");	
		return HIEPS_CFG_DDR_L3_CACHE_ERR;
	}

	/* Config hieps access ddr without cahce. */
	value = read32(HIEPS_ARC_CTRL0_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	value &= ~HIEPS_CFG_ARC_WR_CACHE_MASK; /* bit[16:9] clear 0 */
	write32(HIEPS_ARC_CTRL0_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR), value);
	/* Read back to check. */
	result = read32(HIEPS_ARC_CTRL0_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	if (0 != (result & HIEPS_CFG_ARC_WR_CACHE_MASK)) {
		tloge("hieps: config hieps access ddr without cache failed!\n");
		return HIEPS_CFG_DDR_CACHE_ERR;
	}

	hieps_cfg_boot_flag();

	ret = HIEPS_OK;

	return ret;
}

/*
 * @brief      : hieps_wakeup_cpu : wakeup arc cpu.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static uint32_t hieps_wakeup_cpu(void)
{
	volatile uint32_t value;
	uint32_t timeout = HIEPS_WAIT_ARC_RUN_TIMEOUT;

	/* Clear bsp ready flag. */
	write32(HIEPS_BSP_READY_ADDR, 0);

	/* Config ARC cpu run requestment. */
	value = read32(SOC_PCTRL_PERI_CTRL87_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	value |= BIT(HIEPS_ARC_RUN_REQ_A_BIT);
	write32(SOC_PCTRL_PERI_CTRL87_ADDR(SOC_ACPU_PCTRL_BASE_ADDR), value);
	/* Read back to confirm. */
	value = read32(SOC_PCTRL_PERI_CTRL87_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	if (!(value & BIT(HIEPS_ARC_RUN_REQ_A_BIT))) {
		tloge("hieps:Wake up ARC cpu failed!\n");
		return HIEPS_ERROR;
	}

	/* Check whether ARC CPU is running. */
	value = read32(SOC_PCTRL_PERI_STAT65_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	while((timeout) && (!(value & BIT(HIEPS_ARC_RUN_ACK_BIT)))) {
		hieps_udelay(2); /* every loop delay 2us. */
		timeout--;
		value = read32(SOC_PCTRL_PERI_STAT65_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	}

	if (timeout == 0) {
		tloge("hieps:Query Wake up ARC cpu failed!\n");
		return HIEPS_ERROR;
	}

	/* Clear the run reqestment after arc cpu running. */
	value = read32(SOC_PCTRL_PERI_CTRL87_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	value &= ~(BIT(HIEPS_ARC_RUN_REQ_A_BIT));
	write32(SOC_PCTRL_PERI_CTRL87_ADDR(SOC_ACPU_PCTRL_BASE_ADDR), value);
	/* Read back to confirm. */
	value = read32(SOC_PCTRL_PERI_CTRL87_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	if (value & BIT(HIEPS_ARC_RUN_REQ_A_BIT)) {
		tloge("hieps:Clear Wake up ARC cpu failed!\n");
		return HIEPS_ERROR;
	}

	return HIEPS_OK;

}

/*
 * @brief      : hieps_cfg_kdr_key : config the hieps kdr key to specify address.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static uint32_t hieps_cfg_kdr_key()
{
	uint32_t ret = HIEPS_ERROR;

	/* Clear kdr ready flag. */
	write32(HIEPS_KDR_READY_FLAG_ADDR, ~HIEPS_KDR_READY);

	/* Send smc to ATF to read the efuse to get the kdr. */
	ret = hieps_smc_send_process(HIEPS_KDR_SET_CMD, 0, 0, 0); /* arg1-arg3 donnot used. */
	if (ret != HIEPS_OK){
		tloge("hieps:send smc failed! ret = %x\n",\
			  ret);
		return ret;
	}

	/* Set kdr ready flag. */
	write32(HIEPS_KDR_READY_FLAG_ADDR, HIEPS_KDR_READY);
	ret = HIEPS_OK;

	return ret;
}

/*
 * @brief      : hieps_cfg_bsp_attribution : config the attibution of hieps bsp.
 *
 * @param[in]  : profile : the profile to set.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static uint32_t hieps_cfg_bsp_attribution(const uint32_t profile)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t value;
	uint32_t timeout = HIEPS_BSP_CLK_SYNC_TIMEOUT;

	/* Wait for bsp running and setting clk sync flag. */
	value = read32(HIEPS_BSP_CLK_SYNC_ADDR);
	while ((timeout) && (value != HIEPS_BSP_CLS_SYNC_BEGIN)) {
		timeout--;
		value = read32(HIEPS_BSP_CLK_SYNC_ADDR);
		hieps_udelay(5); /* every loop delay 5us. */
	}

	if (timeout == 0) {
		tloge("hieps:Wait bsp timeout!\n");
		return HIEPS_WAIT_BSP_ERR;
	}

	ret = hieps_cfg_clk_div(profile, HIEPS_BSP_PHASE);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps bsp clock failed! ret = 0x%x\n", ret);
		return ret;
	}

	/* Set clk flag and value to transfer the current clock to bsp. */
	/* low tempreature match 0.8V 480M */
	if (hieps_get_low_temperature_flag() == LOW_TEMPERATURE_FLAG) {
		write32(HIEPS_BASE_CLK_ADDR, HIEPS_CLK_FREQUENCY_480M);
	} else {
		write32(HIEPS_BASE_CLK_ADDR,
			g_hieps_power_attr_list[profile].hieps_bsp_clk);
	}
	write32(HIEPS_BSP_CLK_SYNC_ADDR, HIEPS_BSP_CLS_SYNC_DONE);

	/* Initialize hieps kdr key. */
	ret = hieps_cfg_kdr_key();
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps kdr failed! ret = 0x%x\n", ret);
		return ret;
	}

	return ret;
}

/*
 * @brief      : hieps_wait_for_ready : wait for hieps ready.
 *
 * @return     : HIEPS_OK : ready, HIEPS_ERROR: not ready. 
 */
static uint32_t hieps_wait_for_ready()
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t timeout = HIEPS_BSP_READY_TIMEOUT;
	volatile uint32_t value = 0;

	value = read32(HIEPS_BSP_READY_ADDR);
	while ((timeout) && (value != HIEPS_BSP_READY)) {
		hieps_udelay(2); /* every loop delay 2 us. */
		timeout--;
		value = read32(HIEPS_BSP_READY_ADDR);
	}

	/* 500000 x 2us = 1s. */
	if (timeout == 0) {
		tloge("hieps: wait for bsp ready timeout!\n");
		ret = HIEPS_ERROR;
	} else {
		ret = HIEPS_OK;
	}

	return ret;
}

/*
 * @brief      : hieps_set_cold_boot_flag : set hieps cold boot flag.
 */
static void hieps_set_cold_boot_flag(void)
{
	u32 addr;
	SOC_CRGPERIPH_GENERAL_SEC_CTRL0_UNION  config = { 0 };

	addr = SOC_CRGPERIPH_GENERAL_SEC_CTRL0_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR);
	config.value = read32(addr);
	config.reg.peri_powerup_cnt = HIEPS_NON_COLD_BOOT;
	config.value |= HIEPS_NON_COLD_BOOT_MASK;
	write32(addr, config.value);
}

/*
 * @brief      : hieps_poweron_process : the whole process of power on.
 *
 * @param[in]  : profile : the profile to power.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
uint32_t hieps_poweron_process(const uint32_t profile)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t ret1 = HIEPS_ERROR;

	/* Select clock source and set clock div for hieps rom. */
	ret = hieps_cfg_clk(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps clock failed! ret = 0x%x\n", ret);
		return ret;
	}

	/* Send smc command to REE(TEE->ATF->Kernel) to power on hieps. */
	ret = hieps_power_process(profile, HIEPS_POWER_ON_CMD);
	if (ret != HIEPS_OK) {
		tloge("hieps:hieps smc process failed! ret = 0x%x\n", ret);
		return ret;
	}

	/* Initialize hieps rompatch. */
	ret = hieps_rompatch_init();
	if (ret != HIEPS_OK) {
		tloge("hieps:set hieps rompatch failed! ret = 0x%x\n", ret);
		goto error;
	}

	/* Config the attribution of rom, for example, boot flags.... */
	ret = hieps_cfg_rom_attribution(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps rom attribution failed!\
			   ret = 0x%x\n", ret);
		goto error;
	}

	/* Wakeup ARC cpu to run. */
	ret = hieps_wakeup_cpu();
	if (ret != HIEPS_OK) {
		tloge("hieps:wakeup arc cpu failed! ret=0x%x\n", ret);
		goto error;
	}

	/* Config the attribution of bsp, for example, clk frequency, kdr.... */
	ret = hieps_cfg_bsp_attribution(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps bsp clk failed! ret=0x%x\n", ret);
		goto error;
	}

	/* Wait for bsp ready. */
	ret = hieps_wait_for_ready();
	if (ret != HIEPS_OK) {
		tloge("hieps:wait for bsp ready failed! ret=0x%x\n", ret);
		goto error;
	} else {
		/* Set non-cold boot flag to ARC. */
		hieps_set_cold_boot_flag();
		goto exit;
	}

error:
	ret1 = hieps_power_process(profile, HIEPS_POWER_OFF_CMD);
	if (ret1 != HIEPS_OK) {
		tloge("hieps:power down hieps failed! ret = 0x%x\n", ret1);
	}

exit:
	return ret;
}

/*
 * @brief      : hieps_change_voltage : change hieps voltage.
 *
 * @param[in]  : profile : profile id.
 *
 * @return     : HIEPS_OK: successful, Others: failed.
 */
static uint32_t hieps_change_voltage(const uint32_t profile)
{
	return hieps_send_power_cmd(HIEPS_DVFS_CMD, profile);
}

/*
 * @brief      : hieps_dvfs_up : up hieps voltage and clock.
 *
 * @param[in]  : profile : profile id.
 *
 * @return     : HIEPS_OK: successful, Others: failed.
 */
static uint32_t hieps_dvfs_up(const uint32_t profile)
{
	uint32_t ret = HIEPS_ERROR;

	tloge("hieps dvfs up!\n");
	/* Increase voltage firstly. */
	ret = hieps_change_voltage(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:Increase voltage failed!ret=0x%x\n", ret);
		goto exit;
	}

	/* Increase hieps clock frequency. */
	ret = hieps_cfg_clk_div(profile, HIEPS_BSP_PHASE);
	if (ret != HIEPS_OK) {
		tloge("hieps:change hieps clock failed! ret=0x%x\n", ret);
		goto exit;
	}

	/* Sync the clock to hieps bsp. */
	ret = hieps_update_sys_clk(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:sync clock failed! ret=0x%x\n", ret);
		goto exit;
	}

	/* When increase voltage successful, but increase clock failed.
	 * It will return error to caller, and power operation will be
	 * failed. Then caller will call power off and the voltage will
	 * be recovery.
	 */

exit:
	return ret;
}

/*
 * @brief      : hieps_dvfs_down : down hieps voltage and clock.
 *
 * @param[in]  : profile : profile id.
 *
 * @return     : HIEPS_OK: successful, Others: failed.
 */
static uint32_t hieps_dvfs_down(const uint32_t profile)
{
	uint32_t ret = HIEPS_ERROR;

	tloge("hieps dvfs down!\n");
	/* Decrease hieps clock frequency firstly. */
	ret = hieps_cfg_clk_div(profile, HIEPS_BSP_PHASE);
	if (ret != HIEPS_OK) {
		tloge("hieps:change hieps clock failed! ret=0x%x\n", ret);
		goto exit;
	}

	/* Sync the clock to hieps bsp. */
	ret = hieps_update_sys_clk(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:sync clock failed! ret=0x%x\n", ret);
		goto exit;
	}

	/* Decrease voltage. */
	ret = hieps_change_voltage(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:Increase voltage failed!ret=0x%x\n", ret);
		/* It is no matter when decrease voltage failed. */
	}

	ret = HIEPS_OK;
exit:
	return ret;
}

/*
 * @brief      : hieps_profile_adjust : Check whether need to do DVFS.
 *
 * @param[in]  : id : vote id.
 * @param[in]  : profile : vote profile.
 * @param[in]  : cmd : vote command.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
static uint32_t hieps_profile_adjust(const uint32_t id, const uint32_t profile,\
	   const hieps_smc_cmd_type cmd)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t max_profile = MAX_PROFILE;
	uint32_t i = 0;
	hieps_profile_status old_status = { 0 };
	hieps_profile_status new_status = { 0 };

	if ((id >= MAX_POWER_ID) || (profile >= MAX_PROFILE) ||\
		((cmd != HIEPS_POWER_ON_CMD) && (cmd != HIEPS_POWER_OFF_CMD))) {
		tloge("hieps:adjust hieps profile failed:id:0x%x, profile:0x%x, cmd:0x%x!\n",\
				  id, profile, cmd);
		return HIEPS_PARAM_ERR;
	}

	/* Save old profile status. */
	old_status = hieps_get_profile();
	/* Update the profile of the specify id firstly. */
	hieps_update_profile(id, profile, cmd);
	/* Get new profile status. */
	new_status = hieps_get_profile();

	/* Caculate the maximum voltage for all id. */
	for (i = 0; i < MAX_POWER_ID; i++) {
		if (new_status.profile_vote[i] < max_profile) {
			max_profile = new_status.profile_vote[i];
		}
	}
	tloge("hieps:maxprofile:0x%x\n", max_profile);

	/* Do dvfs. */
	if (max_profile < new_status.profile_status) {
		/* Increase voltage and clock. */
		ret = hieps_dvfs_up(max_profile);
		if (ret != HIEPS_OK) {
			tloge("hieps: dvfs up failed!ret=0x%x!", ret);
			/* Recovery the profile of the specify id. */
			hieps_update_profile(id, old_status.profile_vote[id], HIEPS_POWER_ON_CMD);
			goto exit;
		}
	} else if (max_profile > new_status.profile_status) {
		/* Decrease voltage and clock. */
		ret = hieps_dvfs_down(max_profile);
		if (ret != HIEPS_OK) {
			tloge("hieps: dvfs down failed!ret=0x%x!", ret);
			/* Recovery the profile of the specify id. */
			hieps_update_profile(id, old_status.profile_vote[id], HIEPS_POWER_ON_CMD);
			goto exit;
		}
	} else {
		tloge("hieps: donot need dvfs.\n");
		ret = HIEPS_OK;
	}
	hieps_set_current_profile(max_profile);

exit:
	return ret;
}

/*
 * @brief      : hieps_low_temperature_process : process low temperature.
 *
 * @param[in]  : profile_id : profile id.
 */
static void hieps_low_temperature_process(uint32_t *profile_id)
{
	volatile uint32_t value;

	value = read32(LOW_TEMPERATURE_FLAG_ADDR);
	value &= LOW_TEMPERATURE_MASK;

	if (value != NORMAL_TEMPERATURE) {
		tloge("hieps: Low temperature!\n");
		hieps_set_low_temperature_flag(LOW_TEMPERATURE_FLAG);
		*profile_id = PROFILE_080V;
	} else {
		hieps_set_low_temperature_flag(~LOW_TEMPERATURE_FLAG);
	}
}

/*
 * @brief      : hieps_power_on : power on hieps with specify vote id and profile id.
 *
 * @param[in]  : id : the vote id.
 * @param[in]  : profile_id : the profile to use.
 *
 * @return     : HIEPS_OK: successfuly, others : failed (with specify error number).
 */
uint32_t hieps_power_on(uint32_t id, uint32_t profile_id)
{
	uint32_t ret = HIEPS_ERROR;
	int32_t sre_ret;

	/* Check paramters. */
	if (id >= MAX_POWER_ID || profile_id >= MAX_PROFILE) {
		tloge("hieps:Invalid para: id is 0x%x, profile id is 0x%x!\n",\
				id, profile_id);
		ret = HIEPS_PARAM_ERR;
		goto exit;
	}

	/* Wait for mutex lock. */
	sre_ret = pthread_mutex_lock(&g_hieps_data.power_lock);
	if (SRE_OK != sre_ret) {
		tloge("hieps:wait hieps_power_lock failed: 0x%x!\n", sre_ret);
		ret = HIEPS_MUTEX_ERR;
		goto exit;
	}

	/* Process low temperature if necessary. */
	hieps_low_temperature_process(&profile_id);

	/* Judge the power status before on. */
	if (HIEPS_POWEROFF_STATUS == hieps_get_power_status()) {

		/* power on in 0.8v when profile is CUSTOM profile */
		if (profile_id == PROFILE_KEEP) {
			profile_id = PROFILE_080V;
		}

		/* If hieps is off, do the whole power on process. */
		ret = hieps_poweron_process(profile_id);
		if (ret != HIEPS_OK) {
			tloge("hieps:poweron hieps failed! ret=0x%x\n", ret);
			goto error;
		}

		/* Update the hieps status when power on successful.*/
		hieps_update_profile(id, profile_id, HIEPS_POWER_ON_CMD);
		hieps_set_current_profile(profile_id);
		hieps_set_status(HIEPS_ON);
	} else {

		/* needn't do dvfs when profile is CUSTOM profile */
		if (profile_id == PROFILE_KEEP) {
			profile_id = g_hieps_profile_status.profile_status;
		}

		/* Check whether need to do dvfs. */
		ret = hieps_profile_adjust(id, profile_id, HIEPS_POWER_ON_CMD);
		if (ret != HIEPS_OK) {
			tloge("hieps: adjust profile failed! ret=0x%x\n", ret);
			goto error;
		}
	}

	/* Update power status. */
	hieps_set_power_status(id, HIEPS_POWER_ON_CMD);
	tloge("hieps poweron successful!\n");
	hieps_print_power_status();
	ret = HIEPS_OK;

error:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.power_lock);
	if (SRE_OK != sre_ret) {
		tloge("hieps:hieps_power_lock failed: 0x%x!\n", sre_ret);
		goto exit;
	}

exit:
	return ret;
}

/*
 * @brief      : hieps_power_off : power off hieps with specify vote id and profile id.
 *
 * @param[in]  : id : the vote id.
 * @param[in]  : profile_id : the profile to use.
 *
 * @return     : HIEPS_OK: successfuly, others : failed (with specify error number).
 */
uint32_t hieps_power_off(uint32_t id, uint32_t profile_id)
{
	uint32_t ret = HIEPS_ERROR;
	int32_t sre_ret;

	/* Check paramters. */
	if (id >= MAX_POWER_ID || profile_id >= MAX_PROFILE || profile_id == PROFILE_KEEP) {
		tloge("hieps:Invalid para: id is 0x%x, profile id is 0x%x!\n",\
				  id, profile_id);
		return HIEPS_PARAM_ERR;
	}

	/* Wait for mutex lock. */
	sre_ret = pthread_mutex_lock(&g_hieps_data.power_lock);
	if (SRE_OK != sre_ret) {
		tloge("hieps:wait hieps_power_lock failed: 0x%x!\n", sre_ret);
		return HIEPS_MUTEX_ERR;
	}

	/* Check whether hieps is already off. */
	if (HIEPS_POWEROFF_STATUS == hieps_get_power_status()) {
		tloge("hieps:hieps is already power off!\n");
		ret = HIEPS_OK;
		goto exit;
	}

	hieps_set_power_status(id, HIEPS_POWER_OFF_CMD);
	/* Check the power status to judge whether need to poweroff. */
	if (HIEPS_POWEROFF_STATUS == hieps_get_power_status()) {
		/* If hieps is off, do the whole power on process. */
		ret = hieps_power_process(profile_id, HIEPS_POWER_OFF_CMD);
		if (ret != HIEPS_OK) {
			tloge("hieps:poweroff hieps failed! ret = 0x%x\n", ret);
			/* Recovery power status. */
			hieps_set_power_status(id, HIEPS_POWER_ON_CMD);
		} else {
			/* Update the hieps profile status when power off successfuly. */
			hieps_update_profile(id, profile_id, HIEPS_POWER_OFF_CMD);
			hieps_set_current_profile(MAX_PROFILE);
		}
	} else {  /* hieps status is also on. */
		/* Check whether need to do dvfs. */
		ret = hieps_profile_adjust(id, profile_id, HIEPS_POWER_OFF_CMD);
		if (ret != HIEPS_OK) {
			tloge("hieps: adjust profile failed! ret=0x%x\n", ret);
			/* Recovery power status. */
			hieps_set_power_status(id, HIEPS_POWER_ON_CMD);
		}
	}

	tloge("hieps power off successful!\n");
	hieps_print_power_status();
exit:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.power_lock);
	if (SRE_OK != sre_ret) {
		tloge("hieps:hieps_power_lock failed: 0x%x!\n", sre_ret);
		return HIEPS_MUTEX_ERR;
	}
	return ret;
}
