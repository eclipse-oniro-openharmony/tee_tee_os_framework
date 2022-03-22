/* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define array of syscall id for qemu.
 * Author: fugengsheng fugengsheng@huawei.com
 * Create: 2020-06-25
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
