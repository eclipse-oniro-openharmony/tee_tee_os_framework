/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines the hieps module driver.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#include <sre_sys.h>
#include <sre_typedef.h>
#include <sre_hwi.h>
#include <secure_gic_common.h>
#include <tee_log.h>
#include <hieps_errno.h>
#include <hieps_wdg.h>
#include <hieps_ipc.h>
#include <hieps_common.h>
#include <hieps_pm.h>
#include <hieps_timer.h>
#include <hieps_power.h>

/* Store hieps watchdog count. */
static uint32_t g_hieps_wdg_cnt;


/*
 * @brief      : hieps_get_wdg_cnt : get watchdog count.
 *
 * @return     : watchdog count.
 */
static uint32_t hieps_get_wdg_cnt()
{
	return g_hieps_wdg_cnt;
}

/*
 * @brief      : hieps_update_wdg_cnt : update hieps watchdog count.
 */
static void hieps_update_wdg_cnt()
{
	g_hieps_wdg_cnt++;
}

/*
 * @brief      : hieps_clear_wdg_cnt : clear hieps watchdog count.
 */
static void hieps_clear_wdg_cnt()
{
	g_hieps_wdg_cnt = 0;
}

/*
 * @brief      : hieps_wdg_interrupt : process hieps watchdog exception.
 *
 * @param[in]  : irq : hieps watchdog interrupt number.
 */
static void hieps_wdg_interrupt(uint32_t irq)
{
	(void)irq;
	static uint64_t start_time = 0;
	static uint64_t end_time = 0;
	uint64_t max_time_cnt = 0;
	hieps_reset_strategy strategy = HIEPS_EXCPT_RESET;

	tloge("hieps watchdog!\n");
	if (!start_time) {
		start_time = hieps_get_timer_value();
	}

	max_time_cnt  = US2TICK((uint64_t)HIEPS_WDG_TIME);
	end_time = hieps_get_timer_value();
	if ((end_time - start_time) < max_time_cnt) {
		hieps_update_wdg_cnt();
	} else {
		start_time = 0;
		hieps_clear_wdg_cnt();
	}

	if (hieps_get_wdg_cnt() >= HIEPS_MAX_WDG_CNT) {
		hieps_clear_power_status();
		strategy = HIEPS_EXCPT_OFF;
		tloge("hieps watchdog: receive too much watchdog!\n");
	}

	hieps_exception_reset(HIEPS_WDG_EXCEPTION, strategy);

	return;
}

/*
 * @brief      : hieps_wdg_init : initialize hieps watchdog modul.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
int32_t hieps_wdg_init(void)
{
	int32_t ret;
	uint32_t irq = HIEPS_WDG_IRQ;

	/* Request hieps watchdog interrupt handler. */
	ret = SRE_HwiCreate((HWI_HANDLE_T)(irq), HIEPS_IRQ_PRIO, INT_SECURE,\
		(HWI_PROC_FUNC)hieps_wdg_interrupt, (HWI_ARG_T)irq);
	if (ret != SRE_OK) {
		tloge("%s-%d:SRE_HwiCreate irq %d errorNO 0x%x\n",\
				__func__, __LINE__, irq, ret);
		return ret;
	}

	ret = SRE_HwiEnable((HWI_HANDLE_T)irq);
	if (ret != SRE_OK) {
		tloge("%s-%d:SRE_HwiEnable irq %d errorNO 0x%x\n",\
				__func__, __LINE__, irq, ret);
		return ret;
	}

	ret = HIEPS_OK;
	return ret;
}

/*
 * @brief      : hieps_wdg_resume : resume the hieps watchdog module.
 *
 * @return     : HIEPS_OK:successfly, others:failed.
 */
int32_t hieps_wdg_resume(void)
{
	int32_t ret;
	uint32_t irq = HIEPS_WDG_IRQ;

	/* Resume hieps watchdog interrupt requestment. */
	ret = SRE_HwiResume((HWI_HANDLE_T)(irq), HIEPS_IRQ_PRIO, INT_SECURE);
	if (ret != SRE_OK) {
		tloge("%s-%d:SRE_HwiResume irq %d errorNO 0x%x\n",\
				__func__, __LINE__, irq, ret);
		return ret;
	}

	ret = SRE_HwiEnable((HWI_HANDLE_T)irq);
	if (ret != SRE_OK) {
		tloge("%s-%d:SRE_HwiEnable irq %d errorNO 0x%x\n",\
				__func__, __LINE__, irq, ret);
		return ret;
	}

	ret = HIEPS_OK;
	tloge("hieps wdg resume!\n");
	return ret;
}

