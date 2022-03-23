/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines hieps power control driver.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#include <sre_typedef.h>
#include <pthread.h>
#include <tee_log.h>
#include <register_ops.h> /* read32 */
#include <hieps_common.h>
#include <hieps_smc.h>
#include <hieps_errno.h>
#include <hieps_timer.h>
#include <hieps_power.h>
#include <soc_crgperiph_interface.h>
#include <soc_pctrl_interface.h>
#include <hieps_powerctrl_plat.h>



 /* Record the staus of hieps power */
union hieps_power_vote_status g_hieps_power_status = { HIEPS_POWEROFF_STATUS };
 /* Back-up of power staus. */
union hieps_power_vote_status g_hieps_power_status_backup = { HIEPS_POWEROFF_STATUS };

/* Record the current profile of hieps. */
struct hieps_profile_status g_hieps_profile_status =
	{ MAX_PROFILE, {MAX_PROFILE, MAX_PROFILE, MAX_PROFILE, MAX_PROFILE, MAX_PROFILE, MAX_PROFILE} };

/* Record the current tcu power status */
static uint32_t g_tcu_power_status = HIEPS_OFF;
static uint32_t g_tcu_power_cmd = HIEPS_CMD_END;

void hieps_set_tcu_power_status(uint32_t data)
{
	g_tcu_power_status = data;
}

static uint32_t hieps_get_tcu_power_status(void)
{
	return g_tcu_power_status;
}

void hieps_set_tcu_power_cmd(uint32_t data)
{
	g_tcu_power_cmd = data;
}

static uint32_t hieps_get_tcu_power_cmd(void)
{
	return g_tcu_power_cmd;
}


/*
 * @brief      : hieps_clear_power_status : clear hieps power status.
 */
void hieps_clear_power_status(void)
{
	uint32_t i;

	g_hieps_power_status.value = HIEPS_POWEROFF_STATUS;
	g_hieps_profile_status.profile_status = MAX_PROFILE;
	for (i = 0; i < MAX_POWER_ID; i++)
		g_hieps_profile_status.profile_vote[i] = MAX_PROFILE;
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
static void hieps_set_power_status(uint32_t id, enum hieps_smc_cmd_type cmd)
{
	uint32_t value;

	if ((id >= MAX_POWER_ID) || ((cmd != HIEPS_POWER_ON_CMD) &&
			(cmd != HIEPS_POWER_OFF_CMD))) {
		tloge("hieps:set hieps power status failed:id = 0x%x, cmd = 0x%x!\n",
			id, cmd);
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
}

/*
 * @brief      : hieps_get_profile : get the hieps current profile.
 *
 * @return     : the profile value.
 */
struct hieps_profile_status hieps_get_profile(void)
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
static void hieps_update_profile(const uint32_t id, const uint32_t profile,
	   const enum hieps_smc_cmd_type cmd)
{
	if ((id >= MAX_POWER_ID) || (profile >= MAX_PROFILE) ||
		((cmd != HIEPS_POWER_ON_CMD) && (cmd != HIEPS_POWER_OFF_CMD))) {
		tloge("hieps:update hieps profile failed:id:0x%x, profile:0x%x, cmd:0x%x!\n",
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
}

/*
 * @brief      : hieps_set_current_profile : set hieps current profile.
 *
 * @param[in]  : profile
 */
static void hieps_set_current_profile(const uint32_t profile)
{
	if (profile > MAX_PROFILE)
		tloge("hieps:Invalid param!\n");
	g_hieps_profile_status.profile_status = profile;
}

/*
 * @brief      : hieps_print_power_status : print hieps power status.
 */
static void hieps_print_power_status(int cmd)
{
	uint32_t i = 0;
	uint32_t vote_status = 0;
	uint32_t prof_status = (MAX_PROFILE << (MAX_POWER_ID * 4)); /* 4bit each profile */
	struct hieps_profile_status  profile_status = { 0 };

	vote_status = hieps_get_power_status();
	profile_status = hieps_get_profile();

	for (i = 0; i < MAX_POWER_ID; i++)
		prof_status |= ((profile_status.profile_vote[i] & 0xF) << (i * 4)); /* 0xF is 4bits mask */

	printf("hieps:power %s = 0x%x, profile cur = 0x%x, st = 0x%x\n",
	       (cmd == HIEPS_POWER_ON_CMD) ? "on" : "off",
	       vote_status, profile_status.profile_status, prof_status);
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

	ret = hieps_cfg_clk_div(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps clock failed! ret = 0x%x\n", ret);
		return ret;
	}

	return ret;
}

/*
 * @brief      : hieps_send_power_cmd : send power command to kernel.
 *
 * @param[in]  : cmd : power command.
 * @param[in]  : profile : profile id.
 *
 * @return     : HIEPS_OK : succesful, Others: failed.
 */
static uint32_t hieps_send_power_cmd(uint32_t cmd, uint32_t profile)
{
	uint32_t ret;
	uint32_t tcu_cmd;

	if (hieps_get_tcu_power_cmd() == HIEPS_TCU_POWER_ON_CMD &&
		hieps_get_tcu_power_status() == HIEPS_OFF)
		tcu_cmd = HIEPS_TCU_POWER_ON_CMD;
	else if (hieps_get_tcu_power_cmd() == HIEPS_TCU_POWER_OFF_CMD &&
		     hieps_get_tcu_power_status() == HIEPS_ON)
		tcu_cmd = HIEPS_TCU_POWER_OFF_CMD;
	else
		tcu_cmd = HIEPS_CMD_END;

	/* Clear result flag. */
	write32(HIEPS_POWER_RESULT_ADDR, HIEPS_POWER_FAILED);
	ret = hieps_smc_send_process(cmd, profile, tcu_cmd, 0);
	if (ret != HIEPS_OK) {
		tloge("hieps:send smc failed! ret = 0x%x\n", ret);
		return ret;
	}

	ret = read32(HIEPS_POWER_RESULT_ADDR);
	if (ret != HIEPS_POWER_SUCCESS) {
		tloge("hieps: hieps power operation failed! cmd:0x%x, ret:0x%x\n",
			cmd, ret);
		ret = HIEPS_ERROR;
	} else {
		ret = HIEPS_OK;
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
	return hieps_send_power_cmd(cmd, profile);
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

	/* Select clock source and set clock div for hieps rom. */

	/* Send smc command to REE(TEE->ATF->Kernel) to power on hieps. */
	ret = hieps_power_process(profile, HIEPS_POWER_ON_CMD);
	if (ret != HIEPS_OK) {
		tloge("hieps:hieps smc process failed! ret = 0x%x\n", ret);
		return ret;
	}
	ret = hieps_cfg_clk(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:config hieps clock failed! ret = 0x%x\n", ret);
		return ret;
	}

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
	ret = hieps_cfg_clk_div(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:change hieps clock failed! ret=0x%x\n", ret);
		goto exit;
	}

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
	ret = hieps_cfg_clk_div(profile);
	if (ret != HIEPS_OK) {
		tloge("hieps:change hieps clock failed! ret=0x%x\n", ret);
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
static uint32_t hieps_profile_adjust(const uint32_t id, const uint32_t profile,
	   const enum hieps_smc_cmd_type cmd)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t max_profile = MAX_PROFILE;
	uint32_t i = 0;
	struct hieps_profile_status old_status = { 0 };
	struct hieps_profile_status new_status = { 0 };

	if ((id >= MAX_POWER_ID) || (profile >= MAX_PROFILE) ||
		((cmd != HIEPS_POWER_ON_CMD) && (cmd != HIEPS_POWER_OFF_CMD))) {
		tloge("hieps:adjust hieps profile failed:id:0x%x, profile:0x%x, cmd:0x%x!\n",
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
		if (new_status.profile_vote[i] < max_profile)
			max_profile = new_status.profile_vote[i];
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
		if (hieps_get_tcu_power_cmd() == HIEPS_TCU_POWER_ON_CMD &&
			hieps_get_tcu_power_status() == HIEPS_OFF)
			ret = hieps_send_power_cmd(HIEPS_TCU_POWER_ON_CMD, 0);
		else if (hieps_get_tcu_power_cmd() == HIEPS_TCU_POWER_OFF_CMD &&
		         hieps_get_tcu_power_status() == HIEPS_ON)
			ret = hieps_send_power_cmd(HIEPS_TCU_POWER_ON_CMD, 0);
		else
			ret = HIEPS_OK;
	}
	hieps_set_current_profile(max_profile);

exit:
	return ret;
}

#ifdef CONFIG_HIEPS_LOW_TEMPERATURE
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
	tloge("hieps low_temperature value = 0x%x\n", value);
	if (value != NORMAL_TEMPERATURE) {
		tloge("hieps: Low temperature!\n");
		hieps_set_low_temperature_flag(LOW_TEMPERATURE_FLAG);
		*profile_id = PROFILE_080V;
	} else {
		hieps_set_low_temperature_flag(~LOW_TEMPERATURE_FLAG);
	}
}
#endif

/*
 * @brief      : hieps_power_on : power on hieps with specify vote id and profile id.
 *
 * @param[in]  : id : the vote id.
 * @param[in]  : profile_id : the profile to use.
 *
 * @return     : HIEPS_OK: successfuly, others : failed (with specify error number).
 */
uint32_t hieps_do_power_on(uint32_t id, uint32_t profile_id)
{
	uint32_t ret = HIEPS_ERROR;
	int32_t sre_ret;

	/* Check paramters. */
	if (id >= MAX_POWER_ID || profile_id >= MAX_PROFILE) {
		tloge("hieps:Invalid para: id is 0x%x, profile id is 0x%x!\n",
				id, profile_id);
		ret = HIEPS_PARAM_ERR;
		return ret;
	}

	/* Wait for mutex lock. */
	sre_ret = pthread_mutex_lock(&g_hieps_data.power_lock);
	if (sre_ret != SRE_OK) {
		tloge("hieps:wait hieps_power_lock failed: 0x%x!\n", sre_ret);
		ret = HIEPS_MUTEX_ERR;
		return ret;/*lint !e454 */
	}

	if (id == CHINA_DRM)
		hieps_set_tcu_power_cmd(HIEPS_TCU_POWER_ON_CMD);

#ifdef CONFIG_HIEPS_LOW_TEMPERATURE
	/* Process low temperature if necessary. */
	hieps_low_temperature_process(&profile_id);
#endif
	/* Judge the power status before on. */
	if (hieps_get_power_status() == HIEPS_POWEROFF_STATUS) {
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
		/* Check whether need to do dvfs. */
		ret = hieps_profile_adjust(id, profile_id, HIEPS_POWER_ON_CMD);
		if (ret != HIEPS_OK) {
			tloge("hieps: adjust profile failed! ret=0x%x\n", ret);
			goto error;
		}
	}

	/* Update power status. */
	hieps_set_power_status(id, HIEPS_POWER_ON_CMD);
	hieps_print_power_status(HIEPS_POWER_ON_CMD);
	if (id == CHINA_DRM)
		hieps_set_tcu_power_status(HIEPS_ON);
	ret = HIEPS_OK;

error:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.power_lock);
	if (sre_ret != SRE_OK)
		tloge("hieps:hieps_power_lock failed: 0x%x!\n", sre_ret);

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
uint32_t hieps_do_power_off(uint32_t id, uint32_t profile_id)
{
	uint32_t ret = HIEPS_ERROR;
	int32_t sre_ret;

	/* Check paramters. */
	if (id >= MAX_POWER_ID || profile_id >= MAX_PROFILE) {
		tloge("hieps:Invalid para: id is 0x%x, profile id is 0x%x!\n", id, profile_id);
		return HIEPS_PARAM_ERR;
	}

	/* Wait for mutex lock. */
	sre_ret = pthread_mutex_lock(&g_hieps_data.power_lock);
	if (sre_ret != SRE_OK) {
		tloge("hieps:wait hieps_power_lock failed: 0x%x!\n", sre_ret);
		return HIEPS_MUTEX_ERR;/*lint !e454 */
	}

	if (id == CHINA_DRM)
		hieps_set_tcu_power_cmd(HIEPS_TCU_POWER_OFF_CMD);

	/* Check whether hieps is already off. */
	if (hieps_get_power_status() == HIEPS_POWEROFF_STATUS) {
		tloge("hieps:hieps is already power off!\n");
		ret = HIEPS_OK;
		goto exit;
	}

	hieps_set_power_status(id, HIEPS_POWER_OFF_CMD);
	/* Check the power status to judge whether need to poweroff. */
	if (hieps_get_power_status() == HIEPS_POWEROFF_STATUS) {
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

	hieps_print_power_status(HIEPS_POWER_OFF_CMD);
	if (id == CHINA_DRM)
		hieps_set_tcu_power_status(HIEPS_OFF);
exit:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.power_lock);
	if (sre_ret != SRE_OK) {
		tloge("hieps:hieps_power_lock failed: 0x%x!\n", sre_ret);
		return HIEPS_MUTEX_ERR;
	}
	return ret;
}

/*
 * set hieps current clk frequency
 */

void hieps_set_clk_frequency(uint32_t frq)
{
	g_hieps_data.current_frq = frq;
}

/*
 * get hieps current clk frequency
 */
uint32_t hieps_get_clk_frequency(void)
{
	return g_hieps_data.current_frq;
}

/*
 * get the number of IDs that have been voted power on
 */
uint32_t hieps_get_voted_nums(void)
{
	uint32_t cnt = 0;
	uint32_t i;
	uint32_t status;

	for (i = 0; i < MAX_POWER_ID; i++) {
		status = g_hieps_power_status.value >> (i * 4); /* 4bit per id */
		if ((status & 0xF) == HIEPS_ON) /* 0xF is 4bit mask value */
			cnt++;
	}

	return cnt;
}

/*
 * get current profile, return MAX_PROFILE when powered off 
 */
uint32_t hieps_get_cur_profile(void)
{
	return g_hieps_profile_status.profile_status;
}

