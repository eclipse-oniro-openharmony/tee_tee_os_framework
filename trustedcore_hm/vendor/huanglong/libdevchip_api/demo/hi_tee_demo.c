/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * File Name: tee_api_demo.c
 * Description: api demo
 * Author: Hisilicon
 * Created: 2019-07-08
 */

#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_module_id.h"

int hi_tee_demo_hello(int data, void *addr)
{
    if (addr == NULL) {
        hi_tee_printf("[ERROR] %s err args.\n", __func__);
        return -1;
    }

    unsigned int args[] = {
        (unsigned int)data,
        (unsigned int)(uintptr_t)addr
    };
    return hm_drv_call(HI_TEE_SYSCALL_DEMO_HELLO, args, ARRAY_SIZE(args));
}

int hi_tee_demo_ioctl(int data, void *addr, unsigned int size)
{
    hi_tee_ioctl_args args;
    errno_t ret;

    if (addr == NULL) {
        hi_tee_printf("[ERROR] %s err args.\n", __func__);
        return -1;
    }

    ret = memset_s(&args, sizeof(hi_tee_ioctl_args), 0, sizeof(hi_tee_ioctl_args));
    if (ret != EOK) {
        hi_tee_printf("[ERROR] %s memset_s failed.\n", __func__);
        return ret;
    }

    args.arg0 = (unsigned long long)data;
    args.arg1 = (unsigned long long)(uintptr_t)addr;
    args.arg2 = (unsigned long long)size;
    return hi_tee_hisilicon_ioctl(HI_ID_DEMO, TEE_DEMO_IOCTL_HELLO, (void *)&args, sizeof(hi_tee_ioctl_args));
}

int hi_tee_demo_test(unsigned int cmd, void *addr, size_t size)
{
    unsigned int args[] = {
        (unsigned int)cmd,
        (unsigned int)(uintptr_t)addr,
        (unsigned int)size
    };
    return hm_drv_call(HI_TEE_SYSCALL_DEMO_FUNC_TEST, args, ARRAY_SIZE(args));
}
