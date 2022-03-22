/*
 * npu_semaphore.h
 *
 * Copyright (c) 2012-2020 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#ifndef __NPU_SEMAPHORE_H
#define __NPU_SEMAPHORE_H

typedef enum {
	NPU_HWTS_SEM,
	NPU_SEM_END,
} npu_sem_t;

int npu_create_named_sem(void);

int npu_sem_post(npu_sem_t sem_type);

int npu_destroy_named_sem(void);

#endif
