/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: rtc timer function
 * Create: 2022-04-22
 */
#ifndef LIBTIMER_TIMER_SLEEP_H
#define LIBTIMER_TIMER_SLEEP_H

void delay_us(uint32_t microseconds);
void delay_ms(uint32_t msec);
uint32_t tee_msleep(uint32_t msec);

#endif