/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
 * Description:about npu semaphore
 */
#ifndef __NPU_SEMAPHORE_H
#define __NPU_SEMAPHORE_H

typedef enum {
	CALC_CQ_SEM,
	TS_MBX_SEM,
	NPU_SEM_END,
} npu_sem_t;

int npu_create_named_sem(void);

void npu_sem_post(npu_sem_t sem_type);

void npu_sem_wait(npu_sem_t sem_type);

void npu_destroy_named_sem(void);

#endif

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif /* UNUSED */
