/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file about timer
 * Create: 2021-08-20
 */

#ifndef DRV_TIMER_PLATFORM_TIMER_H
#define DRV_TIMER_PLATFORM_TIMER_H

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_HI1981)
#include <timer_reg_hi1981.h>
#else
#include <timer_reg_hi1951.h>
#endif

#endif /* DRV_TIMER_PLATFORM_TIMER_H */
