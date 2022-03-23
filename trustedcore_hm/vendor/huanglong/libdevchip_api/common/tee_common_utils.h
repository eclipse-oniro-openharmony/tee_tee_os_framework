/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tee common utils impl head file
 */

#ifndef __TEE_COMMON_UTILS_H__
#define __TEE_COMMON_UTILS_H__

#undef  HI_LOG_D_MODULE_ID
#define HI_LOG_D_MODULE_ID HI_ID_SYS

#undef  HI_LOG_D_FUNCTRACE
#define HI_LOG_D_FUNCTRACE 1

#undef  HI_LOG_D_UNFTRACE
#define HI_LOG_D_UNFTRACE  1

#include "hi_log.h"
#include "hi_tee_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX(a, b) (((a) < (b)) ? (b) : (a))
#define MIN(a, b) (((a) > (b)) ? (b) : (a))

#define HI_FATAL_COMMON(fmt...) hi_log_fatal(fmt)
#define HI_ERR_COMMON(fmt...)   hi_log_err(fmt)
#define HI_WARN_COMMON(fmt...)  hi_log_warn(fmt)
#define HI_INFO_COMMON(fmt...)  hi_log_info(fmt)
#define HI_DBG_COMMON(fmt...)   hi_log_dbg(fmt)

#define TEE_COMMON_ENTER()                     hi_dbg_func_enter()
#define TEE_COMMON_EXIT()                      hi_dbg_func_exit()

#define TEE_COMMON_PrintFuncWar(Func, ErrCode) hi_warn_print_call_fun_err(Func, ErrCode)
#define TEE_COMMON_PrintFuncErr(Func, ErrCode) hi_err_print_call_fun_err(Func, ErrCode)
#define TEE_COMMON_PrintErrCode(ErrCode)       hi_err_print_err_code(ErrCode)

#define TEE_COMMON_LOG_PrintS32(val)           hi_warn_print_s32(val)
#define TEE_COMMON_LOG_PrintU32(val)           hi_warn_print_u32(val)
#define TEE_COMMON_LOG_PrintS64(val)           hi_warn_print_s64(val)
#define TEE_COMMON_LOG_PrintU64(val)           hi_warn_print_u64(val)
#define TEE_COMMON_LOG_PrintH32(val)           hi_warn_print_h32(val)
#define TEE_COMMON_LOG_PrintH64(val)           hi_warn_print_h64(val)
#define TEE_COMMON_LOG_PrintStr(val)           hi_warn_print_str(val)
#define TEE_COMMON_LOG_PrintVoid(val)          hi_warn_print_void(val)
#define TEE_COMMON_LOG_PrintFloat(val)         hi_warn_print_float(val)
#define TEE_COMMON_LOG_PrintInfo(val)          hi_warn_print_info(val)

#define TEE_COMMON_DBG_PrintS32(val)           hi_dbg_print_s32(val)
#define TEE_COMMON_DBG_PrintU32(val)           hi_dbg_print_u32(val)
#define TEE_COMMON_DBG_PrintS64(val)           hi_dbg_print_s64(val)
#define TEE_COMMON_DBG_PrintU64(val)           hi_dbg_print_u64(val)
#define TEE_COMMON_DBG_PrintH32(val)           hi_dbg_print_h32(val)
#define TEE_COMMON_DBG_PrintH64(val)           hi_dbg_print_h64(val)
#define TEE_COMMON_DBG_PrintStr(val)           hi_dbg_print_str(val)
#define TEE_COMMON_DBG_PrintVoid(val)          hi_dbg_print_void(val)
#define TEE_COMMON_DBG_PrintFloat(val)         hi_dbg_print_float(val)
#define TEE_COMMON_DBG_PrintInfo(val)          hi_dbg_print_info(val)

#define common_check_pointer(p) do {                              \
    if ((p) == HI_NULL) {                                         \
        TEE_COMMON_LOG_PrintInfo("pointer parameter is NULL.\n"); \
        return HI_FAILURE;                                        \
    }                                                             \
} while (0)

hi_s32 tee_common_get_version_info(hi_char *version_info, hi_u32 len, hi_u32 total_size);

#ifdef __cplusplus
}
#endif

#endif

