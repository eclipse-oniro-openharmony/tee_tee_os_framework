/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This is header file for timer module.
 * Create: 2019-01-31
 */


#ifndef __HIEPS_TIMER_H__
#define __HIEPS_TIMER_H__
#include <sre_typedef.h>
#include <register_ops.h>
#include <tee_log.h>

/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
#define MAX_US_DELAY                 (1000000) /* 1s */
#define US2TICK(us)                  ((((uint64_t)us) * (192)) / (100))  /* 1.92M */
#define TICK2US(val)                  ((((uint64_t)val) /(192)) * (100))  /* 1.92M */


/*===============================================================================
 *                                global objects                               *
===============================================================================*/


/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
uint64_t hieps_get_timer_value(void);
void hieps_udelay(uint32_t us);

#endif /* __HIEPS_TIMER_H__ */
