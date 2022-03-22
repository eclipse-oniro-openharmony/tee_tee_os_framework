/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Define public macros for klad drivers.
 * Author: Linux SDK team
 * Create: 2019/08/12
 */

#ifndef __API_KLAD_TYPE_H__
#define __API_KLAD_TYPE_H__

#include "semaphore.h"
#include "pthread.h"
#include "tee_time_api.h"
#include "hi_type_dev.h"
#include "hi_log.h"
#include "hi_tee_hal.h"
#include "hi_tee_errcode.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

#define TIME_MS2US 1000
#define TIME_MS2NS 1000000
#define TIME_S2MS  1000
#define TIME_S2US  1000000
#define TIME_S2NS  1000000000

#if TMP_LOG_OUT
#define hi_dbg_klad(fmt...)                   hi_tee_printf(fmt)
#define hi_fatal_klad(fmt...)                 hi_tee_printf(fmt)
#define hi_err_klad(fmt...)                   hi_tee_printf(fmt)
#define hi_warn_klad(fmt...)                  hi_tee_printf(fmt)
#define hi_info_klad(fmt...)                  hi_tee_printf(fmt)
#else

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_USR
#define hi_dbg_klad(fmt...)                   hi_log_dbg(fmt)
#define hi_fatal_klad(fmt...)                 hi_log_fatal(fmt)
#define hi_err_klad(fmt...)                   hi_log_err(fmt)
#define hi_warn_klad(fmt...)                  hi_log_warn(fmt)
#define hi_info_klad(fmt...)                  hi_log_info(fmt)
#endif

#define klad_func_enter()                hi_dbg_klad("[ENTER]:%s\n", __FUNCTION__)
#define klad_func_exit()                 hi_dbg_klad("[EXIT] :%s\n", __FUNCTION__)

#define print_err(val)                   hi_err_klad("%s\n", val)

#define dbg_print_dbg_hex(val)           hi_dbg_klad("%s = 0x%08x\n", #val, val)

#define print_dbg_hex(val)               hi_dbg_klad("%s = 0x%08x\n", #val, val)
#define print_dbg_hex2(x, y)             hi_dbg_klad("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_dbg_hex3(x, y, z)          hi_dbg_klad("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)

#define print_err_hex(val)               hi_err_klad("%s = 0x%08x\n", #val, val)
#define print_err_hex2(x, y)             hi_err_klad("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_err_hex3(x, y, z)          hi_err_klad("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)
#define print_err_hex4(w, x, y, z)       hi_err_klad("%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #w, \
                                                    w, #x, x, #y, y, #z, z)

#define print_err_val(val)               hi_err_klad("%s = %d\n", #val, val)
#define print_err_point(val)             hi_err_klad("%s = %p\n", #val, val)
#define print_err_code(err_code)         hi_err_klad("return [0x%08x]\n", err_code)
#define print_warn_code(err_code)        hi_warn_klad("return [0x%08x]\n", err_code)
#define print_err_func(func, err_code)   hi_err_klad("call [%s] return [0x%08x]\n", #func, err_code)

hi_void hi_klad_dump_buffer(const hi_char *buf, hi_u32 len);
#define klad_print_param(val, len)             hi_klad_dump_buffer(val, len)
#define dbg_klad_print_param(val, len)  klad_print_param(val, len)

#define warn_on(condition) \
do { \
    if (condition) { \
        hi_fatal_klad("KLAD FATAL ERROR: %s\n", # condition); \
    } \
} while (0)

#define hi_malloc(x) (0 < (x) ? TEE_Malloc(x, 0) : HI_NULL)
#define hi_free(x) {if (HI_NULL != (x)) TEE_Free(x);}
#define msleep(x) TEE_Wait(x)

typedef hi_s64 atomic64_t;
typedef hi_s32 atomic_t;

#define atomic_inc(x) \
    do { \
        hi_dbg_klad("[USR]%s[%d] %s %d inc\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_add_and_fetch((x), 1); \
        hi_dbg_klad("[USR]%s[%d] %s %d\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic_dec(x) \
    do { \
        hi_dbg_klad("[USR]%s[%d] %s %d dec\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_sub_and_fetch((x), 1); \
        hi_dbg_klad("[USR]%s[%d] %s %d\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic_add(x, y) __sync_add_and_fetch((x), (y))
#define atomic_sub(x, y) __sync_sub_and_fetch((x), (y))
#define atomic_set(x, y) __sync_lock_test_and_set((x), (y))
#define atomic_read(x)   __sync_add_and_fetch((x), 0)

#define atomic64_inc(x) \
    do { \
        hi_dbg_klad("%s[%d] %s %lld inc\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_add_and_fetch((x), 1); \
        hi_dbg_klad("[USR]%s[%d] %s %lld\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic64_dec(x) \
    do { \
        hi_dbg_klad("%s[%d] %s %lld dec\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_sub_and_fetch((x), 1); \
        hi_dbg_klad("[USR]%s[%d] %s %lld\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic64_add(x, y) __sync_add_and_fetch((x), (y))
#define atomic64_sub(x, y) __sync_sub_and_fetch((x), (y))
#define atomic64_set(x, y) __sync_lock_test_and_set((x), (y))
#define atomic64_read(x)  __sync_add_and_fetch((x), 0)

#define atomic_dec_and_test(x) (__sync_sub_and_fetch((x), 1) == 0)
#define atomic_inc_and_test(x) (__sync_add_and_fetch((x), 1) == 0)
#define atomic_inc_not_zero(x) (__sync_add_and_fetch((x), 1) != 0)

#define spin_lock(lock) while (__sync_lock_test_and_set(&(lock), 1)) {}
#define spin_unlock(lock) __sync_lock_release(&(lock));

#define mutex_lock(lock) \
    do { \
        hi_dbg_klad("[USR]%s[%d] %s lock\n", __FUNCTION__, __LINE__, #lock); \
        pthread_mutex_lock(lock); \
    } while (0)
#define mutex_unlock(lock) \
    do { \
        hi_dbg_klad("[USR]%s[%d] %s unlock\n", __FUNCTION__, __LINE__, #lock); \
        pthread_mutex_unlock(lock); \
    } while (0)
#define mutex_init(lock) pthread_mutex_init(lock, HI_NULL)
#define mutex_deinit(lock) pthread_mutex_destroy(lock)

#define unlikely(x) __builtin_expect(!!(x), 0)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __API_KLAD_TYPE_H__ */
