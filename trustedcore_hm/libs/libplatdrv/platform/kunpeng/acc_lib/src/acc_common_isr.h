/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __ACC_COMMON_ISR_H__
#define __ACC_COMMON_ISR_H__

#ifndef CONFIG_QM_USE_THREADED_IRQ
/*void qm_cq_work_process(struct work_struct *work);*/
#endif
#ifdef CONFIG_EQ_POLL_MODE
int qm_task_proc_thread_start(struct qm_function *qm_func);
#else
/*int qm_msi_int_init(struct qm_function *qm_func);*/
/*void qm_msi_int_free(struct qm_function *qm_func);*/
#endif
int qm_eq_process(struct qm_function *qm_func);

#endif
