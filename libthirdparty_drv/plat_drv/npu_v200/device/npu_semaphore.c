/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu semaphore
 */

#include "npu_semaphore.h"

#include <stdio.h>
#include <semaphore.h>
#include <fcntl.h>           /* For O_* constants */
#include <sys/stat.h>        /* For mode constants */
#include "npu_log.h"
#include "npu_base_define.h"

/* must equal with npu TA definition */
#define HWTS_SEM_NAME  "npu_platdrv_ta_hwts_sem"

static sem_t *s_npu_platdrv_ta_hwts_sem = SEM_FAILED;

int npu_create_named_sem(void)
{
	/* sem create at platdrv TA */
	s_npu_platdrv_ta_hwts_sem = sem_open(HWTS_SEM_NAME, O_CREAT | O_EXCL, 0, 0);
	if (s_npu_platdrv_ta_hwts_sem == SEM_FAILED) {
		NPU_DRV_ERR("npu_platdrv_ta_hwts_sem create failed\n");
		return -1;
	}
	return 0;
}

int npu_sem_post(npu_sem_t sem_type)
{
	if (sem_type != NPU_HWTS_SEM)
		return 0;
	return sem_post(s_npu_platdrv_ta_hwts_sem);
}

int npu_destroy_named_sem(void)
{
	if (s_npu_platdrv_ta_hwts_sem == SEM_FAILED)
		return -1;
	return sem_close(s_npu_platdrv_ta_hwts_sem);
}
