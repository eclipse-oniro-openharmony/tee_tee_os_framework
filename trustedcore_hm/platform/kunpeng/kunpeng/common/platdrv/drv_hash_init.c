/* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define array of syscall id for kungpeng.
 * Author: fugengsheng fugengsheng@huawei.com
 * Create: 2020-06-25
 */
#include "platdrv_hash.h"
#include "sre_syscalls_id.h"

static uint32_t g_drv_module_size;

static uint16_t g_task_exit_driver_id[] = {
    SW_SYSCALL_SYS_OSTSKEXIT,
};

static uint16_t g_hwi_register_driver_id[] = {
    SW_SYSCALL_HWI_IPCREGISTER,
    SW_SYSCALL_HWI_IPCDEREGISTER,
};

#ifdef TRNG_ENABLE
static uint16_t g_trng_syscall_init_id[] = {
    SW_SYSCALL_TRNG_GENERATE_RANDOM,
};
#endif

static uint16_t g_secboot_driver_id[] = {
    SW_SYSCALL_GET_PROVISION_KEY,
    SW_SYSCALL_GET_CERT,
};

uint16_t g_sharedmem_addr_id[] = {
    SW_SYSCALL_GET_TEESHAREDMEM,
};

void drv_module_init(void)
{
    struct module_info *init_info = get_g_module_info();

    register_drv_module(task_exit_driver)
    register_drv_module(hwi_register_driver)

#ifdef TRNG_ENABLE
    register_drv_module(trng_syscall_init)
#endif
    register_drv_module(secboot_driver)
    register_drv_module(sharedmem_addr)
}

uint32_t get_drv_module_size(void)
{
    return g_drv_module_size;
}
