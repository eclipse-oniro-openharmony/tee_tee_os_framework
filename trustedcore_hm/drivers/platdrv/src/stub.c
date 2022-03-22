/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: stub file for sched
 * Create: 2019-09-18
 */

#include <stdint.h>
#include <sys/hmapi_ext.h>
__attribute__((weak)) uint32_t sched_yield(void)
{
    hmapi_yield();

    return 0;
}
