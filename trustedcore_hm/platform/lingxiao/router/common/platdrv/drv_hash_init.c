/* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define array of syscall id for lingxiao.
 * Author: fugengsheng fugengsheng@huawei.com
 * Create: 2020-06-25
 */
#include <sre_syscalls_id.h>
#include "platdrv_hash.h"

static uint32_t g_drv_module_size;

static uint16_t g_secdriver_init_id[] = {
    SW_SYSCALL_SEC_DERIVEKEY,
    SW_SYSCALL_SEC_RND_GENERATEVECTOR,
};

uint16_t g_sharedmem_addr_id[] = {
    SW_SYSCALL_GET_TEESHAREDMEM,
};

void drv_module_init(void)
{
    struct module_info *init_info = get_g_module_info();

    register_drv_module(secdriver_init)
    register_drv_module(sharedmem_addr)
}

uint32_t get_drv_module_size(void)
{
    return g_drv_module_size;
}
