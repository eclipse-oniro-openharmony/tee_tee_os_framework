/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define public macros for klad drivers.
 * Author: Linux SDK team
 * Create: 2019-06-22
 */
#ifndef __DRV_KLAD_COM_H__
#define __DRV_KLAD_COM_H__

#include <string.h>
#include <semaphore.h>
#include "securec.h"
#include "hi_type_dev.h"
#include "hi_log.h"
#include "hi_tee_errcode.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_os_hal.h"
#include "drv_klad_list.h"
#include "drv_klad_bitmap.h"
#include "hi_tee_drv_keyslot.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_KLAD

#define hi_dbg_klad(fmt...)                   hi_log_dbg(fmt)
#define hi_fatal_klad(fmt...)                 hi_log_fatal(fmt)
#define hi_err_klad(fmt...)                   hi_log_err(fmt)
#define hi_warn_klad(fmt...)                  hi_log_warn(fmt)
#define hi_info_klad(fmt...)                  hi_log_info(fmt)

#define HI_PRINT hi_tee_drv_hal_printf

#define klad_func_enter()                hi_dbg_klad("[ENTER]:%s\n", __FUNCTION__)
#define klad_func_exit()                 hi_dbg_klad("[EXIT] :%s\n", __FUNCTION__)

#define print_err(val)                   hi_err_klad("%s\n", val)

#define print_dbg_hex(val)               hi_dbg_klad("%s = 0x%08x\n", #val, val)
#define print_dbg_hex2(x, y)             hi_dbg_klad("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_dbg_hex3(x, y, z)          hi_dbg_klad("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)
#define print_dbg_hex4(w, x, y, z)       hi_dbg_klad("%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #w, \
                                                     w, #x, x, #y, y, #z, z)

#define print_err_hex(val)               hi_err_klad("%s = 0x%08x\n", #val, val)
#define print_err_hex2(x, y)             hi_err_klad("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_err_hex3(x, y, z)          hi_err_klad("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)
#define print_err_hex4(w, x, y, z)       hi_err_klad("%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #w, \
                                                     w, #x, x, #y, y, #z, z)

#define print_dbg_func_hex(func, val)    hi_dbg_klad("call [%s]%s = 0x%08x\n", #func, #val, val)
#define print_dbg_func_hex2(func, x, y)  hi_dbg_klad("call [%s]%s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y)
#define print_dbg_func_hex3(func, x, y, z) \
    hi_dbg_klad("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y, #z, z)
#define print_dbg_func_hex4(func, w, x, y, z) \
    hi_dbg_klad("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #w,  w, #x, x, #y, y, #z, z)

#define print_err_func_hex(func, val)    hi_err_klad("call [%s]%s = 0x%08x\n", #func, #val, val)
#define print_err_func_hex2(func, x, y)  hi_err_klad("call [%s]%s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y)
#define print_err_func_hex3(func, x, y, z) \
    hi_err_klad("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y, #z, z)
#define print_err_func_hex4(func, w, x, y, z) \
    hi_err_klad("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #w,  w, #x, x, #y, y, #z, z)

#define dbg_print_dbg_hex(val)           hi_dbg_klad("%s = 0x%08x\n", #val, val)
#define print_err_val(val)               hi_err_klad("%s = %d\n", #val, val)
#define print_err_point(val)             hi_err_klad("%s = %p\n", #val, val)
#define print_err_code(err_code)         hi_err_klad("return [0x%08x]\n", err_code)
#define print_warn_code(err_code)        hi_warn_klad("return [0x%08x]\n", err_code)
#define print_err_func(func, err_code)   hi_err_klad("call [%s] return [0x%08x]\n", #func, err_code)

/* Register read and write */
#define reg_read(addr, result)  ((result) = *(volatile unsigned int *)(uintptr_t)(addr))
#define reg_write(addr, result)  (*(volatile unsigned int *)(uintptr_t)(addr) = (result))

#define hi_malloc(x)                        (0 < (x) ? hi_tee_drv_hal_malloc(x) : HI_NULL)
#define hi_free(x)                          { if (HI_NULL != (x))  hi_tee_drv_hal_free(x); }

/*
 * interrupt register
 */
#define hi_request_irq(irq, handler, dev)   hi_tee_drv_hal_request_irq((irq), (void *)(handler), 0, (void*)(dev))
#define hi_free_irq(irq, name, dev)         hi_tee_drv_hal_unregister_irq(irq)
#define IRQ_HANDLED HI_TEE_HAL_IRQ_HANDLED
typedef hi_u32 irqreturn_t;

/*
 * spin lock
 */
typedef struct hi_tee_hal_spinlock spinlock_t;
#define spin_lock(x)                        hi_tee_drv_hal_spin_lock(x)
#define spin_unlock(x)                      hi_tee_drv_hal_spin_unlock(x)

/*
 * atomic operation.
 */
typedef hi_s64 atomic64_t;
typedef hi_s32 atomic_t;

#define atomic_inc(x) \
    do { \
        hi_dbg_klad("[DRV]%s[%d] %s %d inc\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_add_and_fetch((x), 1); \
        hi_dbg_klad("[DRV]%s[%d] %s %d\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic_dec(x) \
    do { \
        hi_dbg_klad("[DRV]%s[%d] %s %d dec\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_sub_and_fetch((x), 1); \
        hi_dbg_klad("[DRV]%s[%d] %s %d\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic_add(x, y)       __sync_add_and_fetch((x), (y))
#define atomic_sub(x, y)       __sync_sub_and_fetch((x), (y))
#define atomic_set(x, y)       __sync_lock_test_and_set((x), (y))
#define atomic_read(x)         __sync_add_and_fetch((x), 0)
#define atomic_dec_return(x)   __sync_sub_and_fetch((x), 1)

#define atomic64_inc(x) \
    do { \
        hi_dbg_klad("%s[%d] %s %lld inc\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_add_and_fetch((x), 1); \
        hi_dbg_klad("[DRV]%s[%d] %s %lld\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic64_dec(x) \
    do { \
        hi_dbg_klad("%s[%d] %s %lld dec\n", __FUNCTION__, __LINE__, #x, *(x)); \
        __sync_sub_and_fetch((x), 1); \
        hi_dbg_klad("[DRV]%s[%d] %s %lld\n", __FUNCTION__, __LINE__, #x, *(x)); \
    } while (0)
#define atomic64_add(x, y)     __sync_add_and_fetch((x), (y))
#define atomic64_sub(x, y)     __sync_sub_and_fetch((x), (y))
#define atomic64_set(x, y)     __sync_lock_test_and_set((x), (y))
#define atomic64_read(x)       __sync_add_and_fetch((x), 0)

#define atomic_dec_and_test(x) (__sync_sub_and_fetch((x), 1) == 0)
#define atomic_inc_and_test(x) (__sync_add_and_fetch((x), 1) == 0)
#define atomic_inc_not_zero(x) (__sync_add_and_fetch((x), 1) != 0)
#define hi_atomic_init(x)  (x)

/*
 * MUTEX
 */
typedef pthread_mutex_t         hi_mutex;
#define mutex_lock(lock)        pthread_mutex_lock(lock)
#define mutex_unlock(lock)      pthread_mutex_unlock(lock)
#define mutex_init(lock)        pthread_mutex_init(lock, HI_NULL)
#define mutex_deinit(lock)      pthread_mutex_destroy(lock)
#define __mutex_initializer(x)  PTHREAD_MUTEX_INITIALIZER
#define __mutex_lock(lock) \
    do { \
        hi_dbg_klad("[DRV]%s[%d] %s lock\n", __FUNCTION__, __LINE__, #lock); \
        mutex_lock(lock); \
    } while (0)
#define __mutex_unlock(lock) \
    do { \
        hi_dbg_klad("[DRV]%s[%d] %s unlock\n", __FUNCTION__, __LINE__, #lock); \
        mutex_unlock(lock); \
    } while (0)

/*
 * OTHERS
 */
#define export_symbol(x)

#define msleep(x) hi_tee_drv_hal_msleep(x)
#define udelay(x) hi_tee_drv_hal_udelay(x)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define TIME_S2MS  1000
#define TIME_S2US  1000000
#define TIME_S2NS  1000000000
#define TIME_MS2US 1000
#define TIME_MS2NS 1000000
#define TIME_US2NS 1000

#define MODULE_ID_CNT         0x04

#define handle_2_id(handle)   HI_HANDLE_GET_CHNID(handle)
#define handle_2_mod(handle)  HI_HANDLE_GET_MODID(handle)

static inline hi_u8 handle_2_type(hi_handle handle)
{
    hi_keyslot_priv_attr _pri_data;

    _pri_data.u8 = HI_HANDLE_GET_PriDATA(handle);

    return _pri_data.bits.type;
}

static inline hi_bool is_invalid_ks_handle(hi_handle handle)
{
    hi_bool flag = HI_FALSE;

    if (handle_2_mod(handle) != HI_ID_KEYSLOT) {
        flag = HI_TRUE;
    }

    return flag;
}

static inline hi_bool is_invalid_klad_handle(hi_handle handle)
{
    hi_bool flag = HI_FALSE;

    if (handle_2_mod(handle) != HI_ID_KLAD) {
        flag = HI_TRUE;
    }

    return flag;
}

static inline hi_bool is_tscipher_ks_handle(hi_handle handle)
{
    hi_bool flag = HI_FALSE;
    if (handle_2_type(handle) == HI_KEYSLOT_TYPE_TSCIPHER) {
        flag = HI_TRUE;
    }

    return flag;
}

static inline hi_bool is_mcipher_ks_handle(hi_handle handle)
{
    hi_bool flag = HI_FALSE;

    if (handle_2_type(handle) == HI_KEYSLOT_TYPE_MCIPHER) {
        flag = HI_TRUE;
    }

    return flag;
}

#define warn_on(condition) \
do { \
    if (condition) { \
        hi_fatal_klad("KLAD FATAL ERROR: %s\n", # condition); \
    } \
} while (0)

#define unused(x) (x) = (x)

#define RKP_ERR 0x9 /* RKP error return 0x9x000000 */
#define KL_ERR  0xa /* Keyladder error return 0xax000000 */
#define KC_ERR  0xb /* Key ctrl error return 0xax000000 */

/*
* record logic err code.
* bit 31~28: error module type
* bit 27~24: error bit number, only record 6 bit at most.
* bit 23~0: record error bit position.
*           1):position in bit0~bit15, record the real position.
*           2):position in bit16~bit31, record the position is real position minus 16.
*  eg:  RKP error register is 0b0000 0000 0000 0001 0100 0001 0000 1010, return 0x9500e831.
*/
static inline hi_s32 err_code_gen(hi_u8 mod, hi_u32 reg)
{
    hi_s32 i, cnt;
    hi_u32 err_code = mod << 28; /* bit 31~28 indicate module type */

    for (i = 0, cnt = 0; (i < 0x20) && (cnt < 0x07); i++) {
        if ((reg & (1 << i)) == 0) continue;
        err_code |= ((i % 0x10) << ((cnt++) * 0x04));
    }
    err_code |= (cnt << 24); /* bit 27~24 indicate err bit number, record 6 bit at most. */
    return (hi_s32)err_code;
}

struct time_ns {
    hi_ulong tv_sec;
    hi_ulong tv_nsec;
};

hi_void timestamp(struct time_ns *time);
hi_void get_cost(const hi_char *str, const struct time_ns *time_b, const struct time_ns *time_e);
hi_void get_curr_cost(const hi_char *str, const struct time_ns *time_b);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __DRV_KLAD_COM_H__ */
