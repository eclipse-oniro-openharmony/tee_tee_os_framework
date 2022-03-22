/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer_irq
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_SRC_TIMER_IRQ_H
#define DRV_TIMER_SRC_TIMER_IRQ_H

#include <hm_msg_type.h>
#include <cs.h>

intptr_t irq_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);

#endif /* DRV_TIMER_SRC_TIMER_IRQ_H */
