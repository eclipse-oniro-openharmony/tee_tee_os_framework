/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: the hal api for itrustee
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "module_mgr.h"
#include "tee_drv_os_hal.h"
#include "hi_tee_module_id.h"

struct hi_drv_syscall_table {
    unsigned int module;
    hi_tee_hal_syscall fn;
};

static struct hi_drv_syscall_table g_drv_tables[HI_ID_MAX];

int tee_hisilicon_ioctl(const unsigned int module, const unsigned int cmd, void *args, const size_t size)
{
    if (module >= HI_ID_MAX) {
        os_hal_error("Invalid module[0x%x]\n", module);
        return -1;
    }

    if (g_drv_tables[module].fn == NULL || g_drv_tables[module].module != module) {
        os_hal_error("Module[0x%x] has not registered\n", module);
        return -1;
    }

    return g_drv_tables[module].fn(cmd, args, size);
}

int tee_drv_module_register(const unsigned int module, hi_tee_hal_syscall fn)
{
    if (module >= HI_ID_MAX || fn == NULL) {
        os_hal_error("Register module[0x%x] failed\n", module);
        return -1;
    }

    if (g_drv_tables[module].fn != NULL) {
        os_hal_error("Module[0x%x] has been registered\n", module);
        return -1;
    }

    g_drv_tables[module].module = module;
    g_drv_tables[module].fn = fn;

    return 0;
}
