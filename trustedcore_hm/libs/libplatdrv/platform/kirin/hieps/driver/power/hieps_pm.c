/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines hieps power management driver.
 * Create: 2019-01-31
 */


#include <register_ops.h>
#include <sre_typedef.h>
#include <pthread.h>
#include <tee_log.h>
#include <tee_log.h>
#include <securec.h>
#include <../seccfg/hwspinlock.h>
#include <hieps_errno.h>
#include <hieps_ipc.h>
#include <hieps_common.h>
#include <hieps_pm.h>
#include <hieps_power.h>
#include <hieps_smc.h>
#include <hieps_timer.h>

/* Store hieps status which used before access ipc.  */
static uint32_t g_hieps_status = HIEPS_STATUS_DOWN;


/*
 * @brief      : hieps_set_status : set hieps status.
 *
 * @param[in]  : status : the status to set.
 */
void hieps_set_status(uint32_t status)
{
	if (status == HIEPS_ON) {
		g_hieps_status = HIEPS_STATUS_UP;
	} else if (status == HIEPS_OFF) {
		g_hieps_status = HIEPS_STATUS_DOWN;
	} else {
		tloge("hieps: Invalid status param! status=0x%x\n", status);
		g_hieps_status = HIEPS_STATUS_DOWN;
	}

	return;
}

/*
 * @brief      : hieps_get_status : get hieps status.
 *
 * @return     : hieps status. 
 */
uint32_t hieps_get_status(void)
{
	return g_hieps_status;
}

/*
 * @brief      : hieps_update_sys_clk : syn hieps clock.
 *
 * @param[in]  : profile : profile id.
 *
 * @return     : HIEPS_OK : succesful, Others: failed.
 */
uint32_t hieps_update_sys_clk(uint32_t profile)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t clock = HIEPS_CLK_FREQUENCY_640M;
	ipc_msg_t msg;

	(void)memset_s(&msg, sizeof(msg), 0x0, sizeof(msg));
	switch (profile) {
		case (PROFILE_080V):
			clock = HIEPS_CLK_FREQUENCY_640M;
			break;
		case (PROFILE_070V):
			clock = HIEPS_CLK_FREQUENCY_480M;
			break;
		case (PROFILE_065V):
			clock = HIEPS_CLK_FREQUENCY_384M;
			break;
		case (PROFILE_060V):
			clock = HIEPS_CLK_FREQUENCY_274M;
			break;
		default:
			tloge("hieps: Invalid profile:0x%x\n", profile);
			return ret;
	}

	msg.data[0] = IPC_CMD_PACK(OBJ_AP0, OBJ_AP0, CMD_UPDATE_CLK, IPC_CMD_VERSION);
	msg.data[2] = clock;

	ret = hieps_ipc_send(OBJ_HIEPS, &msg, SYNC_MODE);
	if (ret != HIEPS_OK) {
		tloge("hieps:send ipc msg failed! ret=0x%x\n", ret);
	}

	return ret;

}

/*
 * @brief      : hieps_send_power_msg : send power command to hieps.
 *
 * @return     : HIEPS_OK : succesful, Others: failed.
 */
uint32_t hieps_send_power_msg(void)
{
	uint32_t ret = HIEPS_ERROR;
	ipc_msg_t msg;

	(void)memset_s(&msg, sizeof(msg), 0x0, sizeof(msg));
	msg.data[0] = IPC_CMD_PACK(OBJ_AP0, OBJ_AP0, CMD_POWER, IPC_CMD_VERSION);

	ret = hieps_ipc_send(OBJ_HIEPS, &msg, SYNC_MODE);
	if (ret != HIEPS_OK) {
		tloge("hieps:send ipc msg failed! ret=0x%x\n", ret);
	}

	return ret;
}

/*
 * @brief      : hieps_wait_poweroff_ready : wait hieps being ready to poweroff.
 *
 * @param[in]  : timeout : wait time.
 *
 * @return     : HIEPS_OK : succesful, Others: failed.
 */
uint32_t hieps_wait_poweroff_ready(uint32_t timeout)
{
	volatile uint32_t value, flag;

	/* Set hieps status to be down in case of accessing by ipc. */
	hieps_set_status(HIEPS_OFF);

	/* wait poweroff ready flag and accessing flag. */
	value = read32(HIEPS_POWER_OFF_READY_ADDR);
	flag = hieps_get_access_flag();
	while ((timeout) && ((value != HIEPS_POWER_OFF_READY) ||\
		(flag))) {
		hieps_udelay(2); /* every loop delay 2us. */
		timeout--;
		value = read32(HIEPS_POWER_OFF_READY_ADDR);
		flag = hieps_get_access_flag();
	}

	if (timeout == 0) {
		tloge("hieps:(ready:0x7B3F9846) value:0x%x, flag:0x%x\n", value, flag);
		tloge("hieps: wait hieps power off timeout!\n");
		tloge("hieps cpu may be lock up!\n");
		tloge("Power off hieps directly and this may be affect SOC bus.\n");
		return HIEPS_TIMEOUT_ERR;
	}

	return HIEPS_OK;
}

/*
 * @brief      : hieps_exception_reset : reset hieps for exception.
 *
 * @param[in]  : type : exception type.
 * @param[in]  : strategy : reset strategy.
 */
void hieps_exception_reset(uint32_t type, hieps_reset_strategy strategy)
{
	uint32_t ret, profile;
	int32_t sre_ret;
	hieps_profile_status current_profile_status;
	uint32_t timeout = HIEPS_EXCPT_WAIT_OFF_TIMEOUT;

	current_profile_status = hieps_get_profile();
	profile = current_profile_status.profile_status;

	/* Wait for mutex lock. */
	sre_ret = pthread_mutex_lock(&g_hieps_data.power_lock);
	if (SRE_OK != sre_ret) {
		tloge("hieps:wait hieps_power_lock failed: 0x%x!\n", sre_ret);
		return;
	}

	/* If exception is soft exception or alarm, must wait for ready flag
	 * before powering off. Otherwise(watchdog), power off hieps directly.
	 */
	if ((HIEPS_SOFT_EXCEPTION == type) ||\
			(HIEPS_ALARM_EXCEPTION == type)) {
		ret = hieps_wait_poweroff_ready(timeout);
		if (ret != HIEPS_OK) {
			tloge("hieps wait poweroff ready timeout!\n");
		} else {
			hieps_udelay(2); /* delay 2us to guarantee arc to sleep. */
		}
	}

	/* Clear result flag. */
	write32(HIEPS_POWER_RESULT_ADDR, HIEPS_POWER_FAILED);
	ret = hieps_smc_send_process(HIEPS_POWER_OFF_CMD, profile, 0, 0);
	if (ret != HIEPS_OK){
		tloge("hieps exception:send power off smc failed!ret=0x%x\n", ret);
		goto exit;
	}

	ret = read32(HIEPS_POWER_RESULT_ADDR);
	if (ret != HIEPS_POWER_SUCCESS){
		tloge("hieps exception: power off failed!ret=0x%x\n", ret);
		goto exit;
	} else {
		tloge("hieps exception: power off successful!\n");
	}

	if (strategy == HIEPS_EXCPT_RESET) {
		ret = hieps_poweron_process(profile);
		if (ret != HIEPS_OK){
			tloge("hieps exception: power on failed!ret=0x%x\n", ret);
			goto exit;
		} else {
			/* Set hieps status to be up. */
			hieps_set_status(HIEPS_ON);
			tloge("hieps exception: power on successful!\n");
		}
	}

exit:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.power_lock);
	if (SRE_OK != sre_ret) {
		tloge("hieps:hieps_power_lock failed: 0x%x!\n", sre_ret);
	}

	return;
}

/*
 * @brief      : hieps_send_power_cmd : send power command to kernel.
 *
 * @param[in]  : cmd : power command.
 * @param[in]  : profile : profile id.
 *
 * @return     : HIEPS_OK : succesful, Others: failed.
 */
uint32_t hieps_send_power_cmd(uint32_t cmd, uint32_t profile)
{
	uint32_t ret;

	/* Clear result flag. */
	write32(HIEPS_POWER_RESULT_ADDR, HIEPS_POWER_FAILED);
	ret = hieps_smc_send_process(cmd, profile, 0, 0);
	if (ret != HIEPS_OK){
		tloge("hieps:send smc failed! ret = 0x%x\n", ret);
		return ret;
	}

	ret = read32(HIEPS_POWER_RESULT_ADDR);
	if (ret != HIEPS_POWER_SUCCESS){
		tloge("hieps: hieps power operation failed!\
				cmd:0x%x, ret:0x%x\n", cmd, ret);
		ret = HIEPS_ERROR;
	} else {
		ret = HIEPS_OK;
	}
	return ret;
}

/*
 * @brief      : hieps_set_access_flag : set hieps access flag.
 *
 * @param[in]  : type : access type.
 *
 * @return     : HIEPS_OK: successful, HIEPS_ERROR: failed. 
 */
uint32_t hieps_set_access_flag(hieps_access_type type)
{
	int32_t ret;
	hieps_access_master config;

        ret = hwspin_lock_timeout(HIEPS_HWLOCK_ID, WAITTIME_MAX);
	if (ret != HS_OK) {
		tloge("hieps: wait hwspin lock failed!ret=%d\n", ret);
		return HIEPS_ERROR;
	}

	config.value = read32(HIEPS_ACCESS_ADDR);
	config.master.teeos = type;
	write32(HIEPS_ACCESS_ADDR, config.value);

	ret = hwspin_unlock(HIEPS_HWLOCK_ID);
	if (ret != HS_OK) {
		tloge("hieps: hwspin unlock failed!ret=%d\n", ret);
		return HIEPS_ERROR;
	}

	return HIEPS_OK;
}

/*
 * @brief      : hieps_get_access_flag : get hieps access flag.
 *
 * @return     : access flag.
 */
uint32_t hieps_get_access_flag(void)
{
	return read32(HIEPS_ACCESS_ADDR);
}

/*
 * @brief      : hieps_clear_access_flag : clear hieps access flag.
 */
void hieps_clear_access_flag(void)
{
	write32(HIEPS_ACCESS_ADDR, 0);
}
