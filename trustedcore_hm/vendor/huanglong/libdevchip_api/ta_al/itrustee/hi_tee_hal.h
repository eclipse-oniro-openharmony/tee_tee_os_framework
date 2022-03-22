/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee api hal
 * Author: Hisilicon
 * Create: 2017-06-17
 */

#ifndef __HI_TEE_HAL_H
#define __HI_TEE_HAL_H

#include "tee_log.h"
#include "tee_time_api.h"
#include "tee_ext_api.h"
#include "securec.h"
#include "hmdrv.h"
#include "hm_msg_type.h"
#include "sre_syscall.h"
#include "tee_crypto_api.h"
#include "tee_internal_api.h"

#define __DEFAULT    __attribute__((visibility("default")))

/**
 * hi_tee_mutex_init() - init mutex lock
 * @param name      The mutex name
 * @param size      The length of name
 * @param handle    The lock handle
 *
 * @return 0            success
 * @return other value  fail
 */
int hi_tee_mutex_init(const char *name, unsigned int size, void **handle);

/**
 * hi_tee_mutex_lock() - add mutex lock.
 * @param handle    The lock handle
 *
 * @return 0            success
 * @return other value  fail
 */
int hi_tee_mutex_lock(void * const handle);

/**
 * hi_tee_mutex_lock_wait() - add mutex lock.If the resource will to be locked was
 *                                locked before, then wait here until the lock is unlocked.
 * @param handle    The lock handle
 *
 * @return 0            success
 * @return other value  fail
 */
int hi_tee_mutex_lock_wait(void * const handle);

/**
 * hi_tee_mutex_unlock() - unlock the mutex lock
 * @param handle    The lock handle
 *
 * @return 0            success
 * @return other value  fail
 */
int hi_tee_mutex_unlock(void * const handle);

/**
 * hi_tee_mutex_release() - release the mutex lock
 * @param handle    The lock handle
 *
 * @return  NULL
 */
void hi_tee_mutex_release(void * const handle);

/**
 * hi_tee_printf() - ta print function
 * @param fmt    the str that need print
 *
 * @return  NULL
 */
void hi_tee_printf(const char *fmt, ...);

/**
 * hi_tee_hisilicon_ioctl() - api/TA common syscall
 * @param module      module id
 * @param cmd         ioctl cmd id
 * @param ioctl_args  parameters send to drv by syscall
 * @param size        size of parameters
 *
 * @return 0            success
 * @return other value  fail
 */
int hi_tee_hisilicon_ioctl(const unsigned int module, const unsigned int cmd,
                           void * const ioctl_args, const size_t size);

#endif /* __HI_TEE_HAL_H */
