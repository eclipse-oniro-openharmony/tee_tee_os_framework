/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Driver to test mspc transmission performance.
 * Author : w00371137
 * Create: 2020/04/03
 */

#include <mspc_test_performance.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_syscounter_interface.h>
#include <tee_log.h>
#include <register_ops.h>

#ifdef MSPC_TEST_PERFORMANCE
static uint64_t g_start_time;
static uint64_t g_end_time;

static uint64_t mspc_get_timer_value(void)
{
    uint64_t value;
    uint64_t value_h;
    uint32_t value_l;

    value_h = (uint64_t)read32(SOC_SYSCOUNTER_CNTCV_H32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));
    value_l = read32(SOC_SYSCOUNTER_CNTCV_L32_ADDR(SOC_ACPU_SYS_CNT_BASE_ADDR));

    value = (value_h << 32U) | (value_l); /* 32: register has 32bits. */

    return value;
}

void mspc_record_start_time(void)
{
    g_start_time = mspc_get_timer_value();
}

void mspc_record_end_time(uint32_t type)
{
    g_end_time = mspc_get_timer_value();
    tloge("func:%d:cost %lld ticks!\n", type, g_end_time - g_start_time);
}

#endif

