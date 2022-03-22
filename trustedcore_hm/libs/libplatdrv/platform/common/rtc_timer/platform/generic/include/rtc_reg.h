/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Header file about rtc
 * Create: 2021-05-27
 */

#ifndef RTC_TIMER_DRIVER_RTC_REG_H
#define RTC_TIMER_DRIVER_RTC_REG_H

#include "soc_acpu_baseaddr_interface.h"

#define RTC_BASE_ADDR SOC_ACPU_RTC1_BASE_ADDR

#define RTC_DATA_REG        (RTC_BASE_ADDR + 0x000)
#define RTC_MATCH_REG       (RTC_BASE_ADDR + 0x004)
#define RTC_LOAD_REG        (RTC_BASE_ADDR + 0x008)
#define RTC_CONTROL_REG     (RTC_BASE_ADDR + 0x00C)
#define RTC_IMSC            (RTC_BASE_ADDR + 0x010)
#define RTC_RIS             (RTC_BASE_ADDR + 0x014)
#define RTC_MIS             (RTC_BASE_ADDR + 0x018)
#define RTC_ICR             (RTC_BASE_ADDR + 0x01C)

#define RTC_CTL_ENABLE      1
#define RTC_INT_DISABLE     0
#define RTC_INT_ENABLE      1
#define RTC_INT_CLEAR       1

#define SECURE_RTC_FIQ_NUMBLER 79

#define DEFAULT_HWI_PRI 0
#endif /* RTC_TIMER_DRIVER_RTC_REG_H */
