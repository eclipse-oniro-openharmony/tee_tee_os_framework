/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file for timer_irq
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_TIMER_IRQ_H
#define RTC_TIMER_DRIVER_TIMER_IRQ_H

#include <hm_msg_type.h>
#include <cs.h>

intptr_t irq_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);

#endif /* RTC_TIMER_DRIVER_TIMER_IRQ_H */
