/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Rtc timer functions
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-09-07
 */
#include "timer_rtc.h"
#include <hmlog.h>
#include "mtee_rtc.h"
#include "timer_sys.h"

void timer_rtc_init(void)
{
#ifdef SOFT_RTC_TICK
    rtc_init();
#endif
}

uint64_t timer_rtc_value_get(void)
{
#ifdef SOFT_RTC_TICK
    struct rtc_time tm = { 0 };
    int32_t ret;

    ret = rtc_read_time(&tm);
    if (ret < 0) {
        hm_error("get rtc time failed!\n");
        return 0;
    }

    return rtc_tm_to_time64(&tm);
#else
    struct tee_time_t time = {0};
    get_sys_rtc_time_kernel(&time);
    return time.seconds;
#endif
}

void timer_rtc_reset(uint32_t value)
{
    (void)value;
}
