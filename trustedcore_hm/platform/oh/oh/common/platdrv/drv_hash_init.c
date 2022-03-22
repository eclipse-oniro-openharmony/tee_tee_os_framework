/* Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: define array of syscall id for oh.
 * Create: 2022-01-04
 */
#include <stdint.h>

static uint32_t g_drv_module_size;

void drv_module_init(void)
{
    return;
}

uint32_t get_drv_module_size(void)
{
    return g_drv_module_size;
}
