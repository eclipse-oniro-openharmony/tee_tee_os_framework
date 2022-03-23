/* Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define array of syscall id for phone.
 * Create: 2020-06-25
 */
#include <sre_syscalls_id_ext.h>
#include "platdrv_hash.h"

static uint32_t g_drv_module_size;

static uint16_t g_eSE_id[] = {
    SW_SYSCALL_SCARD_SEND,
    SW_SYSCALL_SCARD_RECEIVE,
#ifdef CONFIG_FEATURE_SEPLAT
    SW_SYSCALL_SCARD_TRANSMIT,
#endif
};

static uint16_t g_mspc_driver_id[] = {
    SW_SYSCALL_MSPC_FACOTRY_CMD,
    };

#ifdef CONFIG_FEATURE_SEPLAT
static uint16_t g_msp_ta_channel_id[] = {
    SW_EPS_CDRM,
};
#endif

void drv_module_init()
{
    struct module_info *init_info = get_g_module_info();
    register_drv_module(eSE)
    register_drv_module(mspc_driver)
#ifdef CONFIG_FEATURE_SEPLAT
    register_drv_module(msp_ta_channel)
#endif
}

uint32_t get_drv_module_size(void)
{
    return g_drv_module_size;
}
