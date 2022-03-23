/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee api log interface.
 */

#include "stdarg.h"
#include "stdint.h"

#include "hmdrv.h"
#include "hm_msg_type.h"

#include "hi_tee_log.h"
#include "hi_tee_hal.h"
#include "hi_tee_errcode.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_syscall_id.h"
#include "tee_drv_common_ioctl.h"

/* This macro is not allowed to be defined externally, it can only be defined here to use key print function. */
#ifdef HI_KEY_PRINT_OUT
#undef HI_KEY_PRINT_OUT
#endif

#if defined (CFG_HI_TEE_LOG_SUPPORT) && !defined (CFG_HI_TEE_ADVCA_FUNCTION_RELEASE)
static hi_s32 tee_log_ioctl(unsigned long cmd, hi_void *pri_args)
{
    unsigned int args[] = {
        (unsigned long)cmd,
        (unsigned long)(uintptr_t)pri_args,
    };

    return hm_drv_call(HI_TEE_SYSCALL_LOG, args, ARRAY_SIZE(args));
}

hi_s32 hi_tee_log_set_level(hi_mod_id module_id, hi_tee_log_level log_level)
{
    hi_s32 ret;
    log_tee_level_info ioctl_para = {0};

    if (module_id >= HI_ID_MAX) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    if (log_level >= HI_LOG_LEVEL_MAX) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    ioctl_para.module_id = module_id;
    ioctl_para.log_level = log_level;

    ret = tee_log_ioctl(LOG_TEE_IOCTL_SET_LEVEL, &ioctl_para);
    if (ret != HI_SUCCESS) {
        return HI_FAILURE;
    }

    return HI_SUCCESS;
}

hi_s32 hi_tee_log_get_level(hi_mod_id module_id, hi_tee_log_level *log_level)
{
    hi_s32 ret;
    log_tee_level_info ioctl_para = {0};

    if (log_level == HI_NULL) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    if (module_id >= HI_ID_MAX) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    ioctl_para.module_id = (unsigned int)module_id;

    ret = tee_log_ioctl(LOG_TEE_IOCTL_GET_LEVEL, &ioctl_para);
    if (ret != HI_SUCCESS) {
        return HI_FAILURE;
    }

    *log_level = ioctl_para.log_level;
    return HI_SUCCESS;
}

hi_void hi_log_print(hi_u32 log_level, hi_u32 module_id, const hi_u8 *func_name,
                     hi_u32 line_num, const hi_char *format, ...)
{
    hi_s32  ret;
    hi_s32  ret_val;
    hi_char log_str[HI_LOG_MAX_TRACE_LEN] = {0};
    va_list ap;
    hi_tee_log_level cur_log_level;

    if (func_name == HI_NULL || format == HI_NULL) {
        return;
    }
    if (log_level >= HI_LOG_LEVEL_MAX || module_id >= HI_ID_MAX) {
        return;
    }

    ret = hi_tee_log_get_level(module_id, &cur_log_level);
    if (ret != HI_SUCCESS) {
        return;
    }
    if (cur_log_level < log_level) {
        return;
    }

    va_start(ap, format);
    ret_val = vsnprintf_s(log_str, HI_LOG_MAX_TRACE_LEN, HI_LOG_MAX_TRACE_LEN - 1, format, ap);
    va_end(ap);

    if (ret_val < 0 || ret_val >= (hi_s32)sizeof(log_str)) {
        return;
    }

    hi_tee_printf("[TEE-API-%04X: %s %d] %s", module_id, func_name, line_num, log_str);
    return;
}

hi_void hi_tee_log_print_key(hi_mod_id module_id, hi_tee_log_level log_level, hi_char *addr, hi_u32 len)
{
#ifdef HI_KEY_PRINT_OUT
    hi_s32 ret;
    hi_u32 i;
    hi_tee_log_level cur_log_level;

    if (addr == HI_NULL) {
        return;
    }
    if (module_id >= HI_ID_MAX || log_level >= HI_LOG_LEVEL_MAX) {
        return;
    }

    ret = hi_tee_log_get_level(module_id, &cur_log_level);
    if (ret != HI_SUCCESS) {
        return;
    }
    if (cur_log_level < log_level) {
        return;
    }

    for (i = 0; i < len; i++) {
        if (!(i % 4)) { /* print 4 hex values in one line */
            hi_tee_printf("\n");
        }
        hi_tee_printf("0x%x ", *(addr + i));
    }
    if (i && (i % 16)) { /* 16 is formatted output param */
        hi_tee_printf("\n");
    }
#endif
    return;
}
#else
hi_s32 hi_tee_log_set_level(hi_mod_id module_id, hi_tee_log_level log_level)
{
    return HI_TEE_ERR_UNSUPPORTED;
}

hi_s32 hi_tee_log_get_level(hi_mod_id module_id, hi_tee_log_level *log_level)
{
    return HI_TEE_ERR_UNSUPPORTED;
}

hi_void hi_log_print(hi_u32 log_level, hi_u32 module_id, const hi_u8 *func_name,
                     hi_u32 line_num, const hi_char *format, ...)
{
    return;
}

hi_void hi_tee_log_print_key(hi_mod_id module_id, hi_tee_log_level log_level, hi_char *addr, hi_u32 len)
{
    return;
}
#endif

