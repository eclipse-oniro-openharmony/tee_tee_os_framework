/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu semaphore
 */

#include "npu_semaphore.h"

#include <stdio.h>
#include <semaphore.h>
#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>        /* For mode constants */
#include "drv_log.h"
// must equal with HIAI TA definition
#define NPU_CALC_CQ_SEM_NAME  "npu_hiai_ta_platdrv_ta_calc_cq_sem"
#define NPU_TS_MBX_SEM_NAME  "npu_hiai_ta_platdrv_ta_ts_mbx_sem"

static sem_t *s_npu_platdrv_ta_calc_cq_sem = SEM_FAILED;
static sem_t *s_npu_platdrv_ta_ts_mbx_sem = SEM_FAILED;

int npu_create_named_sem(void)
{
	// sem create at platdrv TA,HIAI TA just use it
	s_npu_platdrv_ta_calc_cq_sem = sem_open(NPU_CALC_CQ_SEM_NAME, O_CREAT | O_EXCL, 0, 0);
	if (s_npu_platdrv_ta_calc_cq_sem == SEM_FAILED) {
		NPU_ERR("npu_hiai_ta_platdrv_ta_calc_cq_sem create failed\n");
		return -1;
	}

	// sem create at platdrv TA,HIAI TA just use it
	s_npu_platdrv_ta_ts_mbx_sem = sem_open(NPU_TS_MBX_SEM_NAME, O_CREAT | O_EXCL, 0, 0);
	if (s_npu_platdrv_ta_ts_mbx_sem == SEM_FAILED) {
		NPU_ERR("npu_hiai_ta_platdrv_ta_calc_cq_sem create failed\n");
		goto recycle_sem;
	}
	return 0;

recycle_sem:
	sem_destroy(s_npu_platdrv_ta_calc_cq_sem);
	return -1;
}

void npu_sem_post(npu_sem_t sem_type)
{
	if (sem_type == TS_MBX_SEM) {
		sem_post(s_npu_platdrv_ta_ts_mbx_sem);
	}

	if (sem_type == CALC_CQ_SEM) {
		sem_post(s_npu_platdrv_ta_calc_cq_sem);
	}
}

void npu_sem_wait(npu_sem_t sem_type)
{
	if (sem_type != TS_MBX_SEM) {
		NPU_ERR("npu plat drv only allow waiting mailbox semaphore currently");
		return;
	}

	NPU_DEBUG("mailbox sem_wait start");
	sem_wait(s_npu_platdrv_ta_ts_mbx_sem);
	NPU_DEBUG("mailbox sem_wait end");
}

// hm not support now
int npu_sem_wait_timeout(int timeout_ms)
{
	UNUSED(timeout_ms);
	int ret = -1;
	return ret;
}

void npu_destroy_named_sem(void)
{
	if (s_npu_platdrv_ta_calc_cq_sem != SEM_FAILED) {
		sem_destroy(s_npu_platdrv_ta_calc_cq_sem);
	}

	if (s_npu_platdrv_ta_ts_mbx_sem != SEM_FAILED) {
		sem_destroy(s_npu_platdrv_ta_ts_mbx_sem);
	}
}
