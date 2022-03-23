/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: timer adapter
 * Author     : m00475438
 * Create     : 2019/08/25
 */
#include <pal_timer.h>
#include <soc_syscounter_interface.h>
#include <pal_cpu.h>
#include <pal_memory.h>
#include <common_utils.h>

#define DELAY_CYCLES_PER_INS  2

/* For FPGA, timer freq is 32KHz; ASIC we use 9.6MHz
 * Max timer value is 429496729.5us.
 */

/* For 9.6MHz, 1 us = 9.6 tick = 48 / 5 tick */
#define TIMER_US2TICK_NUMERATOR_ASIC         48
#define TIMER_US2TICK_DENOMINATOR_ASIC       25

/* 32KHz for FPGA */
/* For 32KHz, 1 us = 32 / 1000 tick = 4 / 125 tick */
#define TIMER_US2TICK_NUMERATOR_FPGA         (TIMER_US2TICK_NUMERATOR_ASIC)
#define TIMER_US2TICK_DENOMINATOR_FPGA       (TIMER_US2TICK_DENOMINATOR_ASIC)

u64 pal_us2tick(u32 us)
{
	u32 multiplicator;
	u32 divisor;
	u64 tick;

	if (PAL_ISFPGA) {
		multiplicator = TIMER_US2TICK_NUMERATOR_FPGA;
		divisor = TIMER_US2TICK_DENOMINATOR_FPGA;
	} else {
		multiplicator = TIMER_US2TICK_NUMERATOR_ASIC;
		divisor = TIMER_US2TICK_DENOMINATOR_ASIC;
	}

	tick = us / divisor;
	tick *= multiplicator;
	us   %= divisor;
	us   *= multiplicator;
	tick += us / divisor;
	return tick;
}

u32 pal_tick2us(u32 tick)
{
	u32 multiplicator;
	u32 divisor;
	u64 us;

	if (PAL_ISFPGA) {
		multiplicator = TIMER_US2TICK_NUMERATOR_FPGA;
		divisor = TIMER_US2TICK_DENOMINATOR_FPGA;
	} else {
		multiplicator = TIMER_US2TICK_NUMERATOR_ASIC;
		divisor = TIMER_US2TICK_DENOMINATOR_ASIC;
	}

	us = tick / multiplicator;
	us *= divisor;
	tick %= multiplicator;
	tick *= divisor;
	us += tick / multiplicator;
	if (us > U32_MAX)
		PAL_ERROR("us = 0x%x greater than U32_MAX\n", us);
	return (u32)us;
}

u64 pal_timer_value(void)
{
	return pal_read_u32(
		SOC_SYSCOUNTER_CNTCV_L32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
}

void pal_delay_cycles(u32 cycles)
{
	cycles = (cycles + DELAY_CYCLES_PER_INS - 1) / DELAY_CYCLES_PER_INS;
	while (cycles > 0) {
		PAL_ASM_NOP();
		cycles--;
	}
}
