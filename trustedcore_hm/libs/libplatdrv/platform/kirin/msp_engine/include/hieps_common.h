/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines the hieps module driver.
 * Author: w00371137, wangyuzhu4@@huawei.com
 * Create: 2019-01-31
 */


#ifndef __HIEPS_COMMON_H__
#define __HIEPS_COMMON_H__

#include <tee_log.h>
#include <pthread.h>
#include <semaphore.h>
#include <hieps_errno.h>
#include <eps_ddr_layout_define.h>
#include <soc_acpu_baseaddr_interface.h>

#define HIEPS_MODULE_READY           0xC74B367F
#define HIEPS_KDR_READY              0x6328C3F9

#define HIEPS_STATUS_DOWN            0xC97F38B6
#define HIEPS_STATUS_UP              ~HIEPS_STATUS_DOWN


/* The priority of interrupt is decided by hardware,
 * so this parameter is unused. And set it to be 0.
 */
#define HIEPS_IRQ_PRIO               0

enum hieps_support_type {
	HIEPS_SUPPORT    = 0x7C,
	HIEPS_UNSUPPORT  = 0x83,
};

struct hieps_dev_data_t {
	pthread_mutex_t seceng_lock;
	pthread_mutex_t power_lock;
	pthread_mutex_t smc_lock;
	pthread_t thread_id;
	bool thread_exit;
	uint32_t thread_rc;
	sem_t exception_sem;
	uint32_t current_frq;
};

extern struct hieps_dev_data_t g_hieps_data;

uint32_t hieps_get_module_ready_flag(void);
uint32_t is_support_hieps(void);
void hieps_set_status(uint32_t status);
uint32_t hieps_get_status(void);

#endif /* __HIEPS_COMMON_H__ */
