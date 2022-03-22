/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Header file about rtc
 * Author: hepengfei hepengfei7@huawei.com
 * Create: 2019-08-20
 */

#ifndef DRV_TIMER_PLATFORM_RTC_H
#define DRV_TIMER_PLATFORM_RTC_H

#define RTC_BASE_ADDR       0xedf06000
#define RTC_DATA_REG        (RTC_BASE_ADDR + 0x000)
#define RTC_MATCH_REG       (RTC_BASE_ADDR + 0x004)
#define RTC_LOAD_REG        (RTC_BASE_ADDR + 0x008)
#define RTC_CONTROL_REG     (RTC_BASE_ADDR + 0x00C)
#define RTC_IMSC            (RTC_BASE_ADDR + 0x010)
#define RTC_RIS             (RTC_BASE_ADDR + 0x014)
#define RTC_MIS             (RTC_BASE_ADDR + 0x018)
#define RTC_ICR             (RTC_BASE_ADDR + 0x01C)

#endif /* DRV_TIMER_PLATFORM_RTC_H */
