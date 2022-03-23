/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Header file about rtc
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_RTC_H
#define DRV_TIMER_PLATFORM_RTC_H

#include "soc_acpu_baseaddr_interface.h"

#define RTC_BASE_ADDR SOC_ACPU_RTC1_BASE_ADDR

#ifdef HI_TIMER_V500
#define RTC_CONTROL_REG     (RTC_BASE_ADDR + 0x000)
#define RTC_LOAD_REG        (RTC_BASE_ADDR + 0x004)
#define RTC_MATCH_REG       (RTC_BASE_ADDR + 0x008)
#define RTC_ICR             (RTC_BASE_ADDR + 0x010)
#define RTC_IMSC            (RTC_BASE_ADDR + 0x014)
#define RTC_RIS             (RTC_BASE_ADDR + 0x018)
#define RTC_MIS             (RTC_BASE_ADDR + 0x01c)
#define RTC_DATA_REG        (RTC_BASE_ADDR + 0x020)
#else
#define RTC_DATA_REG        (RTC_BASE_ADDR + 0x000)
#define RTC_MATCH_REG       (RTC_BASE_ADDR + 0x004)
#define RTC_LOAD_REG        (RTC_BASE_ADDR + 0x008)
#define RTC_CONTROL_REG     (RTC_BASE_ADDR + 0x00C)
#define RTC_IMSC            (RTC_BASE_ADDR + 0x010)
#define RTC_RIS             (RTC_BASE_ADDR + 0x014)
#define RTC_MIS             (RTC_BASE_ADDR + 0x018)
#define RTC_ICR             (RTC_BASE_ADDR + 0x01C)
#endif

#endif
