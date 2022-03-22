/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:
 * Author: Hisilicon hisecurity team
 * Create: 2019-07-23
 */
#ifndef __TEE_KEYSLOT_H__
#define __TEE_KEYSLOT_H__

#include "hi_tee_hal.h"
#include "hi_log.h"
#include "hi_tee_errcode.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#if TMP_LOG_OUT
#define hi_debug_ks(fmt...)                 hi_tee_printf(fmt)
#define hi_fatal_ks(fmt...)                 hi_tee_printf(fmt)
#define hi_err_ks(fmt...)                   hi_tee_printf(fmt)
#define hi_warn_ks(fmt...)                  hi_tee_printf(fmt)
#define hi_info_ks(fmt...)                  hi_tee_printf(fmt)
#else

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_KEYSLOT

#define hi_debug_ks(fmt...)                 hi_log_dbg(fmt)
#define hi_fatal_ks(fmt...)                 hi_log_fatal(fmt)
#define hi_err_ks(fmt...)                   hi_log_err(fmt)
#define hi_warn_ks(fmt...)                  hi_log_warn(fmt)
#define hi_info_ks(fmt...)                  hi_log_info(fmt)
#endif
#define ks_func_enter()                     hi_debug_ks("[ENTER]:%s\n", __FUNCTION__)
#define ks_func_exit()                      hi_debug_ks("[EXIT] :%s\n", __FUNCTION__)

#define print_dbg_hex(val)                  hi_debug_ks("%s = 0x%x\n", #val, val)
#define print_dbg_hex2(x, y)                hi_debug_ks("%s = 0x%x %s = 0x%x\n", #x, x, #y, y)
#define print_dbg_hex3(x, y, z)             hi_debug_ks("%s = 0x%x %s = 0x%x %s = 0x%x\n", #x, x, #y, y, #z, z)

#define print_err_hex(val)                  hi_err_ks("%s = 0x%x\n", #val, val)
#define print_err_hex2(x, y)                hi_err_ks("%s = 0x%x %s = 0x%x\n", #x, x, #y, y)
#define print_err_hex3(x, y, z)             hi_err_ks("%s = 0x%x %s = 0x%x %s = 0x%x\n", #x, x, #y, y, #z, z)
#define print_err_hex4(w, x, y, z)          hi_err_ks("%s = 0x%x %s = 0x%x %s = 0x%x %s = 0x%x\n", #w, \
                                                      w, #x, x, #y, y, #z, z)
#define print_err_val(val)                  hi_err_ks("%s = %d\n", #val, val)
#define print_err_point(val)                hi_err_ks("%s = %p\n", #val, val)
#define print_err_code(err_code)            hi_err_ks("return [0x%x]\n", err_code)
#define print_warn_code(err_code)           hi_warn_ks("return [0x%x]\n", err_code)
#define print_err_func(func, err_code)      hi_err_ks("call [%s] return [0x%x]\n", #func, err_code)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __TEE_KEYSLOT_H__ */