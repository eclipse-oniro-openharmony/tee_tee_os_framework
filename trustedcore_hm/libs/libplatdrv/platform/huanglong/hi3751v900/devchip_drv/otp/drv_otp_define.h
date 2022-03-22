/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Define public macros for OTP drivers.
 * Author: Linux SDK team
 * Create: 2019/06/20
 */
#ifndef __DRV_OTP_DEFINE_H__
#define __DRV_OTP_DEFINE_H__

#include "securec.h"
#include "hmdrv.h"
#include "hi_log.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_errcode.h"

#include "hi_tee_drv_otp.h"
#include "tee_drv_ioctl_otp.h"
#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

#ifndef BITS_PER_BYTE
#define BITS_PER_BYTE 8
#endif

#define TIME_S2MS  1000
#define TIME_S2US  1000000
#define TIME_S2NS  1000000000
#define TIME_MS2US 1000
#define TIME_MS2NS 1000000
#define TIME_US2NS 1000

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_OTP

#if TMP_LOG_OUT
#define hi_debug_otp(fmt...)                 hi_tee_drv_hal_printf(fmt)
#define hi_fatal_otp(fmt...)                 hi_tee_drv_hal_printf(fmt)
#define hi_err_otp(fmt...)                   hi_tee_drv_hal_printf(fmt)
#define hi_warn_otp(fmt...)                  hi_tee_drv_hal_printf(fmt)
#define hi_info_otp(fmt...)                  hi_tee_drv_hal_printf(fmt)
#else
#define hi_debug_otp(fmt...)                 hi_log_dbg(fmt)
#define hi_fatal_otp(fmt...)                 hi_log_fatal(fmt)
#define hi_err_otp(fmt...)                   hi_log_err(fmt)
#define hi_warn_otp(fmt...)                  hi_log_warn(fmt)
#define hi_info_otp(fmt...)                  hi_log_info(fmt)
#endif
#define otp_func_enter()                     hi_debug_otp("[ENTER]:%s\n", __FUNCTION__)
#define otp_func_exit()                      hi_debug_otp("[EXIT] :%s\n", __FUNCTION__)

#define print_dbg_hex(val)                  hi_debug_otp("%s = 0x%08x\n", #val, val)
#define print_dbg_hex2(x, y)                hi_debug_otp("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_dbg_hex3(x, y, z)             hi_debug_otp("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)

#define print_err_hex(val)                  hi_err_otp("%s = 0x%08x\n", #val, val)
#define print_err_hex2(x, y)                hi_err_otp("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_err_hex3(x, y, z)             hi_err_otp("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)
#define print_err_hex4(w, x, y, z)          hi_err_otp("%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #w, \
                                            w, #x, x, #y, y, #z, z)

#define print_dbg_func_hex(func, val)    hi_info_otp("call [%s]%s = 0x%08x\n", #func, #val, val)
#define print_dbg_func_hex2(func, x, y)  hi_info_otp("call [%s]%s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y)
#define print_dbg_func_hex3(func, x, y, z) \
    hi_info_otp("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y, #z, z)
#define print_dbg_func_hex4(func, w, x, y, z) \
    hi_info_otp("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #w,  w, #x, x, #y, y, #z, z)

#define print_err_func_hex(func, val)    hi_err_otp("call [%s]%s = 0x%08x\n", #func, #val, val)
#define print_err_func_hex2(func, x, y)  hi_err_otp("call [%s]%s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y)
#define print_err_func_hex3(func, x, y, z) \
    hi_err_otp("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y, #z, z)
#define print_err_func_hex4(func, w, x, y, z) \
    hi_err_otp("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #w,  w, #x, x, #y, y, #z, z)

#define print_err_val(val)                  hi_err_otp("%s = %d\n", #val, val)
#define print_err_point(val)                hi_err_otp("%s = %p\n", #val, val)
#define print_err_code(err_code)            hi_err_otp("return [0x%08x]\n", err_code)
#define print_warn_code(err_code)           hi_warn_otp("return [0x%08x]\n", err_code)
#define print_err_func(func, err_code)      hi_err_otp("call [%s] return [0x%08x]\n", #func, err_code)

/* it depends on how many pages can be maped, 0:one page, 1:two pages, 2:four pages, 3: eight pages */
#define PAGE_NUM_SHIFT    0
#define OTP_MAP_PAGE_NUM  (1ULL << PAGE_NUM_SHIFT)
#define OTP_MAP_MASK      (((OTP_MAP_PAGE_NUM) << PAGE_SHIFT) - 1)
#define OTP_MAP_SIZE      0x10000

/*
 * Bit map
 * GENMASKREV(05, 00)=0xffffffc0 GENMASK(05, 00)=0x0000003f
 * GENMASKREV(32, 05)=0x0000001f GENMASK(32, 05)=0xffffffe0
 * GENMASKREV(00, 01)=0xffffffff GENMASK(00, 01)=0x00000000
 */
#define BITS_PER_INT 32
#define gen_mask(h, l) \
    (((~0U) << (l)) & (~0U >> (BITS_PER_INT - 1 - (h))))
#define gen_mask_rev(h, l) \
    ~(((~0U) << (l)) & (~0U >> (BITS_PER_INT - 1 - (h))))

/* Byte alignment */
#define is_word_align(addr) (((addr) & 0x03) != 0)
#define word_align(addr) ((addr) & (~0x3))
#define byte_den(v, addr) (((v) >> (((addr) & 0x3) * 8)) & 0xff)

/* Register read and write */
#define reg_read(addr, result)  ((result) = *(volatile unsigned int *)(uintptr_t)(addr))
#define reg_write(addr, result)  (*(volatile unsigned int *)(uintptr_t)(addr) = (result))

#define UDELAY               hi_tee_drv_hal_udelay
#define MUTEX                hi_tee_hal_mutex
#define mutex_lock(lock)     hi_tee_drv_hal_mutex_lock(lock);
#define mutex_unlock(lock)   hi_tee_drv_hal_mutex_unlock(lock);
#define mutex_init(lock)     hi_tee_drv_hal_mutex_init("ks_lock", lock);
#define mutex_destroy(lock)  hi_tee_drv_hal_mutex_destroy(lock);
#define define_semaphore(x)  static struct hi_tee_hal_mutex x

#define __mutex_initializer(lock) {0}

#define export_symbol(x)
#define unused(x) (x) = (x)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* end of #ifdef __cplusplus */

#endif /* end of #ifndef __DRV_OTP_H__ */
