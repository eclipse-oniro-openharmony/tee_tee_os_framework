/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines the smc interface for hieps.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#include <sre_errno.h>
#include <sre_typedef.h>
#include <sre_sys.h>
#include <sre_syscall.h>
#include <pthread.h>
#include <ipc_call.h> /* __smc_switch_to_atf */
#include <register_ops.h> /* read32 */
#include <hieps_common.h>
#include <hieps_timer.h>
#include <hieps_smc.h>
#include <tee_common.h>



/*
 * @brief: hieps_smc_send_process : hieps smc to kernel process.
		Wait for result in shared ddr.
		It is used for send command to kernel usually.
 *
 * @param[in]  : arg0 : smc data to send.
 * @param[in]  : arg1 : smc data to send.
 * @param[in]  : arg2 : smc data to send.
 * @param[in]  : arg3 : smc data to send.
 *
 * @return     : HIEPS_OK:successful, others:failed.
 */
uint32_t hieps_smc_send_process(uint64_t arg0, uint64_t arg1,
				uint64_t arg2, uint64_t arg3)
{
	uint32_t ret = HIEPS_ERROR;
	uint32_t smc_ret;
	uint32_t sre_ret;
	uint32_t count = 0;
	kcall_tee_smc_atf_t hieps_smc_data = {
		.x1 = arg0,
		.x2 = arg1,
		.x3 = arg2,
		.x4 = arg3,
	};

	/* Wait for mutex lock. */
	sre_ret = pthread_mutex_lock(&g_hieps_data.smc_lock);
	if (sre_ret != SRE_OK) {
		tloge("hieps smc:wait hieps_smc_lock failed: 0x%x!\n", sre_ret);
		ret = HIEPS_MUTEX_ERR;
		return ret;/*lint !e454 */
	}
	/* Clear the result flag before send. */
	write32(HIEPS_SMC_RET_FLAG_ADDR, HIEPS_SMC_RUNNING);
	ret = __smc_switch_to_atf(HIEPS_SMC_FID, &hieps_smc_data);
	if (ret != HIEPS_OK) {
		tloge("hieps smc:teeos to atf smc failed! ret=0x%x\n", ret);
		goto err_free_mutex;
	}
	smc_ret = read32(HIEPS_SMC_RET_FLAG_ADDR);
	while ((count < HIEPS_SMC_WAIT_TIME) && (smc_ret != HIEPS_SMC_DONE)) {
		count++;
		hieps_udelay(5);    /* every loop delay 5us. */
		smc_ret = read32(HIEPS_SMC_RET_FLAG_ADDR);
	}
	/* Timeout: 1s */
	if (count == HIEPS_SMC_WAIT_TIME) {
		tloge("hieps smc: wait for smc result timeout!\n");
		ret = HIEPS_WAIT_SMC_ERR;
	} else {
		ret = HIEPS_OK;
	}

err_free_mutex:
	sre_ret = pthread_mutex_unlock(&g_hieps_data.smc_lock);
	if (sre_ret != SRE_OK) {
		tloge("hieps smc:hieps_power_lock failed:0x%x!\n", sre_ret);
		ret = HIEPS_MUTEX_ERR;
	}

	return ret;
}

