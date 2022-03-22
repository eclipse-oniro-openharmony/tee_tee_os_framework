/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file for timer_desc
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_SRC_TIMER_DESC_H
#define DRV_TIMER_SRC_TIMER_DESC_H

#include <stdint.h>

int32_t tc_drv_init(void);
void tc_drv_sp(uint32_t flag);
void tc_drv_sr(uint32_t flag);

#endif /* DRV_TIMER_SRC_TIMER_DESC_H */
