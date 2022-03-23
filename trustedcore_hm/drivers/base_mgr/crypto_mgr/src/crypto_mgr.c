/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: define drv main function
 * Create: 2022-01-13
 */
#include <stdio.h>
#include <inttypes.h>
#include <procmgr_ext.h>
#include <sys/hmapi_ext.h>
#include <sys/hm_priorities.h>
#include <sys/fileio.h>
#include <sys/usrsyscall_ext.h>
#include <ac.h>
#include "tee_driver_module.h"
#include "crypto_mgr_syscall.h"
#include <sre_log.h>
#include "drv_random.h"
#include "ccmgr_hm.h"

const char *g_debug_prefix = "crypto_mgr";

int32_t crypto_mgr_init(void)
{
    return 0;
}

int64_t crypto_mgr_ioctl(struct drv_data *drv, uint32_t cmd, unsigned long args, uint32_t args_len)
{
    if (drv == NULL) {
        hm_error("ioctl invalid drv\n");
        return -1;
    }

    int32_t ret = crypto_ioctl_func(drv, cmd, args, args_len);
    if (ret != 0)
        hm_error("crypto mgr ioctl fail cmd 0x%x, ret0x%x\n", cmd, ret);

    hm_info("mgr ioctl load 0x%x ret 0x%x\n", cmd, ret);

    return ret;
}

int64_t crypto_mgr_open(struct drv_data *drv, unsigned long args, uint32_t args_len)
{
    if (drv == NULL) {
        hm_error("open invalid drv\n");
        return -1;
    }

    if (args == 0 && args_len == 0) {
        hm_error("input NULL param\n");
        return 0;
    }

    if (args_len < sizeof(uint32_t) || args == 0) {
        hm_error("open invalid drv\n");
        return -1;
    }
    return 0;
}

int64_t crypto_mgr_close(struct drv_data *drv)
{
    if (drv == NULL) {
        hm_error("close invalid drv\n");
        return -1;
    }

    if (drv->private_data != NULL) {
        hm_error("free private data in close\n");
        free(drv->private_data);
    }

    return 0;
}

int32_t crypto_mgr_suspend(void)
{
    return 0;
}

int32_t crypto_mgr_resume(void)
{
    return 0;
}

tee_driver_declare(crypto_mgr, crypto_mgr_init, crypto_mgr_open, crypto_mgr_ioctl, crypto_mgr_close, \
                   crypto_mgr_suspend, crypto_mgr_resume, NULL, NULL);
