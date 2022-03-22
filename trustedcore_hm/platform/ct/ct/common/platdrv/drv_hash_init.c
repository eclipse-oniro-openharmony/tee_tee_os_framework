/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: define array of syscall id for ct.
 * Author: hemuyang1@huawei.com
 * Create: 2021-03-09
 */
#include <stdint.h>
static uint32_t g_drv_module_size;

void drv_module_init(void)
{
}

uint32_t get_drv_module_size(void)
{
    return g_drv_module_size;
}
