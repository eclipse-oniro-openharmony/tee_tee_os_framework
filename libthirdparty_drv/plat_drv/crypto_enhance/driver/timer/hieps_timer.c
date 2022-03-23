/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines the hieps delay driver,
 *              which use syscounter(1.92MHZ).
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#include <register_ops.h>
#include <sre_typedef.h>
#include <tee_log.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_syscounter_interface.h>
#include <hieps_timer.h>

/*
 * @brief      : hieps_get_timer_value : get the syscounter value.
 *
 * @return     : Current syscounter value.
 */
uint64_t hieps_get_timer_value(void)
{
	uint64_t value;
	uint64_t value_h;
	uint32_t value_l;

	value_h = (uint64_t)read32(SOC_SYSCOUNTER_CNTCV_H32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
	value_l = read32(SOC_SYSCOUNTER_CNTCV_L32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));

	value = (value_h << 32) | (value_l);

	return value;
}

/**
 * @brief      : hieps_udelay : delay us.
 *
 * @param[in]  : us : the time to delay.
 */
void hieps_udelay(uint32_t us)
{
	uint64_t timer_begin, timer_end;
	uint64_t delay_ticks = 0;

	if (us > MAX_US_DELAY) {
		tloge("hieps:Invalid delay param:%d!\n", us);
		return;
	}

	delay_ticks = US2TICK(us);

	timer_begin = hieps_get_timer_value();
	do {
		timer_end = hieps_get_timer_value();
	} while ((timer_end - timer_begin) < delay_ticks);

	return;
}
