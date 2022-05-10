/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_TIMER_CALL_H
#define LIBTIMER_TIMER_CALL_H

cref_t timer_tcb_cref_get(void);
uint32_t tick_timer_fiq_num_get(void);
int tee_renew_hmtimer_job_handler(void);
int tee_hm_timer_init(void);
uint32_t hmtimer_call(uint16_t id, uint64_t *args, int nr);
#endif