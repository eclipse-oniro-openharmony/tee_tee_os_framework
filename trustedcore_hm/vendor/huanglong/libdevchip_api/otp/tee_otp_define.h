/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Define public macros for OTP drivers.
 * Author: Hisilicon hisecurity team
 * Create: 2019-07-23
 */
#ifndef __TEE_OTP_DEFINE_H__
#define __TEE_OTP_DEFINE_H__

#include "hi_log.h"
#include "hmdrv.h"
#include "hm_msg_type.h"
#include "hi_tee_hal.h"
#include "hi_tee_errcode.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_OTP

#if TMP_LOG_OUT
#define hi_debug_otp(fmt...)                 hi_tee_printf(fmt)
#define hi_fatal_otp(fmt...)                 hi_tee_printf(fmt)
#define hi_err_otp(fmt...)                   hi_tee_printf(fmt)
#define hi_warn_otp(fmt...)                  hi_tee_printf(fmt)
#define hi_info_otp(fmt...)                  hi_tee_printf(fmt)
#else
#define hi_debug_otp(fmt...)                 hi_log_dbg(fmt)
#define hi_fatal_otp(fmt...)                 hi_log_fatal(fmt)
#define hi_err_otp(fmt...)                   hi_log_err(fmt)
#define hi_warn_otp(fmt...)                  hi_log_warn(fmt)
#define hi_info_otp(fmt...)                  hi_log_info(fmt)
#endif
#define otp_func_enter()                     hi_debug_otp("[ENTER]:%s\n", __FUNCTION__)
#define otp_func_exit()                      hi_debug_otp("[EXIT] :%s\n", __FUNCTION__)

#define print_dbg_hex(val)                   hi_debug_otp("%s = 0x%x\n", #val, val)
#define print_dbg_hex2(x, y)                 hi_debug_otp("%s = 0x%x %s = 0x%x\n", #x, x, #y, y)
#define print_dbg_hex3(x, y, z)              hi_debug_otp("%s = 0x%x %s = 0x%x %s = 0x%x\n", #x, x, #y, y, #z, z)

#define print_err_hex(val)                   hi_err_otp("%s = 0x%x\n", #val, val)
#define print_err_hex2(x, y)                 hi_err_otp("%s = 0x%x %s = 0x%x\n", #x, x, #y, y)
#define print_err_hex3(x, y, z)              hi_err_otp("%s = 0x%x %s = 0x%x %s = 0x%x\n", #x, x, #y, y, #z, z)
#define print_err_hex4(w, x, y, z)           hi_err_otp("%s = 0x%x %s = 0x%x %s = 0x%x %s = 0x%x\n", #w, \
                                                        w, #x, x, #y, y, #z, z)

#define print_err_func_hex(func, val)        hi_err_otp("call [%s]%s = 0x%08x\n", #func, #val, val)
#define print_err_func_hex2(func, x, y)      hi_err_otp("call [%s]%s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y)
#define print_err_func_hex3(func, x, y, z) \
    hi_err_otp("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #x, x, #y, y, #z, z)
#define print_err_func_hex4(func, w, x, y, z) \
    hi_err_otp("call [%s]%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #func, #w,  w, #x, x, #y, y, #z, z)

#define print_err_val(val)                  hi_err_otp("%s = %d\n", #val, val)
#define print_err_point(val)                hi_err_otp("%s = %p\n", #val, val)
#define print_err_code(err_code)            hi_err_otp("return [0x%x]\n", err_code)
#define print_warn_code(err_code)           hi_warn_otp("return [0x%x]\n", err_code)
#define print_err_func(func, err_code)      hi_err_otp("call [%s] return [0x%x]\n", #func, err_code)

hi_void otp_hex_dump(const hi_u8 *buf, hi_u32 len);
#define print_err_string(val, len)             otp_hex_dump(val, len)

#define with_locker(attibute) ((attibute) & 0x01)
#define with_crc(attibute)    ((attibute) & 0x02)
#define with_bak(attibute)    ((attibute) & 0x04)
#define need_reset(attibute)  ((attibute) & 0x08)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __HI_MPI_SLOT_H__ */
