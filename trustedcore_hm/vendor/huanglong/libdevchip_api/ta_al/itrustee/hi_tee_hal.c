/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee api hal
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#include "hi_tee_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_mem_mgmt_api.h"

int hi_tee_mutex_init(const char *name, unsigned int size, void **handle)
{
    return 0; // __tee_mutex_init(name, size, handle);
}

int hi_tee_mutex_lock(void * const handle)
{
    return 0; // __tee_mutex_lock(handle);
}

int hi_tee_mutex_unlock(void * const handle)
{
    return 0; // __tee_mutex_unlock(handle);
}

int hi_tee_mutex_lock_wait(void * const handle)
{
    return 0; // __tee_mutex_lock_wait(handle);
}

void hi_tee_mutex_release(void * const handle)
{
    return; // __tee_mutex_release(handle);
}

void hi_tee_printf(const char *fmt, ...)
{
#ifdef CFG_HI_TEE_LOG_SUPPORT
#define CONFIG_SYS_PBSIZE   2048
    va_list args;
    char *buf = NULL;
    char *buf_put = NULL;
    int ret;

    if (fmt == NULL) {
        return;
    }

    buf = (char *)TEE_Malloc(CONFIG_SYS_PBSIZE, 0);
    if (buf == NULL) {
        return;
    }

    va_start(args, fmt);

    /* For this to work, buf must be larger than anything we ever want to print. */
    ret = vsnprintf_s(buf, CONFIG_SYS_PBSIZE, CONFIG_SYS_PBSIZE - 1, fmt, args);
    if (ret < 0 || ret > CONFIG_SYS_PBSIZE) {
        va_end(args);
        TEE_Free(buf);
        return;
    }

    va_end(args);

    /* Print the string */
    buf_put = buf;
    while (*buf_put) {
        putchar (*buf_put++);
    }

    TEE_Free(buf);
#endif
}

int hi_tee_hisilicon_ioctl(const unsigned int module, const unsigned int cmd,
                           void * const ioctl_args, const size_t size)
{
    unsigned int args[] = {
        (unsigned int)module,
        (unsigned int)cmd,
        (unsigned int)(uintptr_t)ioctl_args,
        (unsigned int)size
    };
    return hm_drv_call(HI_TEE_SYSCALL_HISILICON_IOCTL, args, ARRAY_SIZE(args));
}

