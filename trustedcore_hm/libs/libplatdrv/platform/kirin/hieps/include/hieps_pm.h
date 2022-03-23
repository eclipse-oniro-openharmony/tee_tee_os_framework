/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for power manager module.
 * Create: 2019-01-31
 */

#ifndef __HIEPS_PM_H__
#define __HIEPS_PM_H__
#include <eps_ddr_layout_define.h>


/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
#define HIEPS_EXCPT_WAIT_OFF_TIMEOUT      (200000) /* 200000 x 2us = 400ms */

#define HIEPS_ACCESS_ADDR                 EPS_ACCESS_FLAG_ADDR(HIEPS_DDR_SPACE_BASE_ADDR)
#define HIEPS_HWLOCK_ID                   (34)

#define HIEPS_STATUS_DOWN                 0xC97F38B6
#define HIEPS_STATUS_UP                   ~HIEPS_STATUS_DOWN

typedef enum {
	HIEPS_EXCPT_RESET   = 0xC6,
	HIEPS_EXCPT_OFF     = 0x6C,
} hieps_reset_strategy;

typedef enum {
	HIEPS_DONOT_ACCESS  = 0,
	HIEPS_ACCESS        = 1,
} hieps_access_type;

typedef enum {
	HIEPS_SOFT_EXCEPTION  = 0x51,
	HIEPS_ALARM_EXCEPTION = 0x52,
	HIEPS_WDG_EXCEPTION   = 0x53,
} hieps_exception_type;

typedef union {
	uint32_t value;
	struct {
		uint32_t teeos:1;
		uint32_t ap:1;
		uint32_t iom7:1;
		uint32_t lpmcu:1;
		uint32_t modem:1;
		uint32_t isp:1;
		uint32_t hifi:1;
		uint32_t reserved:25;
	} master;
} hieps_access_master;

/*===============================================================================
 *                                global objects                               *
===============================================================================*/


/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
uint32_t hieps_send_power_msg(void);
uint32_t hieps_update_sys_clk(uint32_t clock);
void hieps_exception_reset(uint32_t type, hieps_reset_strategy strategy);
void hieps_set_status(uint32_t status);
uint32_t hieps_get_status(void);
uint32_t hieps_get_access_flag(void);
uint32_t hieps_set_access_flag(hieps_access_type type);
void hieps_clear_access_flag(void);
uint32_t hieps_wait_poweroff_ready(uint32_t timeout);
uint32_t hieps_send_power_cmd(uint32_t cmd, uint32_t profile);

#endif /*  __HIEPS_PM_H__ */
