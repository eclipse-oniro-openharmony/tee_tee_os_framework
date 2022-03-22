/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: This file defines the hieps module driver.
 * Create: 2019-01-31
 */


#ifndef __HIEPS_COMMON_H__
#define __HIEPS_COMMON_H__

#include <tee_log.h>
#include <pthread.h>
#include <semaphore.h>
#include <hieps_errno.h>
#include <eps_ddr_layout_define.h>
#include <soc_eps_ipc_interface.h>
#include <soc_acpu_baseaddr_interface.h>

/*===============================================================================
 *                                types/macros                                 *
===============================================================================*/
#define HIEPS_DEBUG                 (1) /* Just for debug. */
#define HIEPS_DEBUG_PRINT do {\
	if (HIEPS_DEBUG) {\
		tloge("%s-%d!\n", __func__, __LINE__);\
	}\
} while (0);



#ifndef BIT
#define BIT(x)                       (0x01U << ((uint32_t)(x) % 32))  /*lint -e(835)*/
#endif

#define HIEPS_MODULE_READY           (0xC74B367F)
#define HIEPS_KDR_READY              (0x6328C3F9)

/* The priority of interrupt is decided by hardware,
 * so this parameter is unused. And set it to be 0.
 */
#define HIEPS_IRQ_PRIO               (0)

enum hieps_exception_status_t {
	HIEPS_EXCEPTION_DOING = 0x4B6D39C1,
	HIEPS_EXCEPTION_DONE  = 0xB492C63E,
};

enum hieps_support_type {
	HIEPS_SUPPORT    = 0x7C,
	HIEPS_UNSUPPORT  = 0x83,
};

struct hieps_dev_data_t {
	pthread_mutex_t ipc_lock;
	pthread_mutex_t power_lock;
	pthread_mutex_t smc_lock;
	pthread_t thread_id;
	bool thread_exit;
	uint32_t thread_rc;
	sem_t exception_sem;
};
/*===============================================================================
 *                                global objects                               *
===============================================================================*/
extern struct hieps_dev_data_t g_hieps_data;

/*===============================================================================
 *                                  functions                                  *
===============================================================================*/
uint32_t hieps_get_module_ready_flag(void);
uint32_t is_support_hieps(void);
void hieps_irq_lock(void);
void hieps_irq_unlock(void);
#endif /* __HIEPS_COMMON_H__ */
