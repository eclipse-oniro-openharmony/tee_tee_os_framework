/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: tee drv log interface.
 */

#include "stdio.h"
#include "stdarg.h"

#include "hi_type_dev.h"
#include "sre_access_control.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_drv_syscall_id.h"
#include "hmdrv_stub.h"
#include "drv_legacy_def.h"

#include "hi_log.h"
#include "hi_tee_errcode.h"
#include "hi_tee_module_id.h"
#include "tee_drv_common_ioctl.h"

/* This macro is not allowed to be defined externally, it can only be defined here to use key print function. */
#ifdef HI_KEY_PRINT_OUT
#undef HI_KEY_PRINT_OUT
#endif

#define LOG_BLOCK_PERLINE (16)

#if defined (CFG_HI_TEE_LOG_SUPPORT) && !defined (CFG_HI_TEE_ADVCA_FUNCTION_RELEASE)
static hi_s32 g_level_buf[HI_ID_MAX] = { [0 ... (HI_ID_MAX - 1)] = HI_LOG_LEVEL_ERROR };

hi_s32 hi_drv_log_set_level(hi_mod_id module_id, hi_tee_log_level log_level)
{
    if (module_id >= HI_ID_MAX) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    if (log_level >= HI_LOG_LEVEL_MAX) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    g_level_buf[module_id] = log_level;

    return HI_SUCCESS;
}

hi_s32 hi_drv_log_get_level(hi_mod_id module_id, hi_tee_log_level *log_level)
{
    if (log_level == HI_NULL) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    if (module_id >= HI_ID_MAX) {
        return HI_TEE_ERR_INVALID_PARAM;
    }

    *log_level = g_level_buf[module_id];

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

    if ((func_name == HI_NULL) || (format == HI_NULL)) {
        return;
    }
    if (log_level >= HI_LOG_LEVEL_MAX || module_id >= HI_ID_MAX) {
        return;
    }

    ret = hi_drv_log_get_level(module_id, &cur_log_level);
    if (ret != HI_SUCCESS) {
        return;
    }
    if (cur_log_level < log_level) {
        return;
    }

    va_start(ap, format);
    ret_val = vsnprintf_s(log_str, sizeof(log_str), HI_LOG_MAX_TRACE_LEN - 1, format, ap);
    va_end(ap);

    if (ret_val < 0 || ret_val >= (hi_s32)sizeof(log_str)) {
        return;
    }

    hi_tee_drv_hal_printf("[TEE-DRV-%04X: %s %d] %s", module_id, func_name, line_num, log_str);
    return;
}

hi_void hi_log_simple_print(const hi_char *format, ...)
{
    va_list args;
    hi_u32  msg_len;
    hi_char log_str[HI_LOG_MAX_TRACE_LEN] = {0};

    va_start(args, format);
    msg_len = vsnprintf_s(log_str, sizeof(log_str), HI_LOG_MAX_TRACE_LEN - 1, format, args);
    va_end(args);
    if (msg_len < 0) {
        return;
    }

    if (msg_len >= HI_LOG_MAX_TRACE_LEN) {
        log_str[HI_LOG_MAX_TRACE_LEN - 0x1] = '\0'; /* even the 'vsnprintf' commond will do it */
        log_str[HI_LOG_MAX_TRACE_LEN - 0x2] = '\n';
        log_str[HI_LOG_MAX_TRACE_LEN - 0x3] = '.';
        log_str[HI_LOG_MAX_TRACE_LEN - 0x4] = '.';
        log_str[HI_LOG_MAX_TRACE_LEN - 0x5] = '.';
    }

    hi_tee_drv_hal_printf("%s", log_str);
}

hi_void hi_log_print_block(hi_u32 level, hi_u32 module_id, hi_char *block, hi_u32 size)
{
    hi_u32 i = 0;

    hi_tee_drv_hal_printf("[TEE-DRV-%04X: %s %d] ", module_id, __FUNCTION__, __LINE__);
    for (i = 0; i < size; i++) {
        if ((i % LOG_BLOCK_PERLINE == 0) && (i != 0)) {
            hi_tee_drv_hal_printf("\n");
            hi_tee_drv_hal_printf("[TEE-DRV-%04X: %s %d] ", module_id, __FUNCTION__, __LINE__);
        }
        hi_tee_drv_hal_printf(" %02x", block[i]);
    }
    hi_tee_drv_hal_printf("\n");
}

hi_void hi_drv_log_print_key(hi_mod_id module_id, hi_tee_log_level log_level, hi_char *addr, hi_u32 len)
{
#ifdef HI_KEY_PRINT_OUT
    hi_s32 ret;
    hi_u32 i;
    hi_tee_log_level cur_log_level;

    if (addr == HI_NULL) {
        return;
    }
    if (module_id >= HI_ID_MAX || log_level >= HI_LOG_MAX_TRACE_LEN) {
        return;
    }

    ret = hi_drv_log_get_level(module_id, &cur_log_level);
    if (ret != HI_SUCCESS) {
        return;
    }
    if (cur_log_level < log_level) {
        return;
    }

    for (i = 0; i < len; i++) {
        if (!(i % 4)) { /* print 4 hex values in one line */
            hi_tee_drv_hal_printf("\n");
        }
        hi_tee_drv_hal_printf("0x%x ", *(addr + i));
    }
    if (i && (i % 16)) { /* 16 is formatted output param */
        hi_tee_drv_hal_printf("\n");
    }
#endif
    return;
}

static hi_s32 tee_drv_log_ioctl(const unsigned int cmd, hi_void *args)
{
    hi_s32 ret = HI_FAILURE;

    switch (cmd) {
        case LOG_TEE_IOCTL_SET_LEVEL: {
            log_tee_level_info *level_info = (log_tee_level_info *)args;
            ret = hi_drv_log_set_level(level_info->module_id, level_info->log_level);
            if (ret != HI_SUCCESS) {
                hi_log_err("TEE set log level failed!\n");
            }
            break;
        }
        case LOG_TEE_IOCTL_GET_LEVEL: {
            log_tee_level_info *level_info = (log_tee_level_info *)args;
            ret = hi_drv_log_get_level(level_info->module_id, &(level_info->log_level));
            if (ret != HI_SUCCESS) {
                hi_log_err("TEE get log level failed!\n");
            }
            break;
        }
        default: {
            hi_log_err("Unknown ioctl cmd!\n");
            break;
        }
    }

    return ret;
}

hi_s32 tee_log_syscall(hi_s32 swi_id, struct drv_param *params, unsigned long long permissions)
{
    hi_s32 ret;
    hi_void *argp = HI_NULL;
    hi_u32 addr;
    if (params == NULL || params->args == 0)
        return -1;
    uint64_t  *args = (uint64_t *)(uintptr_t)params->args;
    HANDLE_SYSCALL(swi_id) {
        SYSCALL_PERMISSION(HI_TEE_SYSCALL_LOG, permissions, GENERAL_GROUP_PERMISSION)
            /*
             * register usage:
             * r0: cmd, r1: args
             * Note: must call ACCESS_CHECK Convert the virtual address of the api to the virtual address of drv.
             */
            hi_log_dbg("log_syscall args[0] 0x%x, args[1] 0x%x!\n", args[0], args[1]);
            ACCESS_CHECK(args[1], _IOC_SIZE(args[0]))
            argp = (hi_void *)args[1];
            ret = tee_drv_log_ioctl(args[0], (void *)args[1]);
            if (ret != HI_SUCCESS) {
                hi_log_err("call log ioctl fail: 0x%x!\n", ret);
                args[0] = ret;
            } else {
                args[0] = 0;
            }
            SYSCALL_END
        default:
            return -EINVAL;
    }

    return ret;
}

hi_s32 tee_log_mod_init(hi_void)
{
    hi_u8 i;

    for (i = 0; i < HI_ID_MAX; i++) {
        g_level_buf[i] = HI_LOG_LEVEL_ERROR;
    }

    hi_tee_drv_hal_printf("load secure log success. build time:[%s, %s]\n", __DATE__,  __TIME__);
    return HI_SUCCESS;
}
#else
hi_s32 hi_drv_log_set_level(hi_mod_id module_id, hi_tee_log_level log_level)
{
    return HI_TEE_ERR_UNSUPPORTED;
}

hi_s32 hi_drv_log_get_level(hi_mod_id module_id, hi_tee_log_level *log_level)
{
    return HI_TEE_ERR_UNSUPPORTED;
}

hi_void hi_log_print(hi_u32 log_level, hi_u32 module_id, const hi_u8 *func_name,
                     hi_u32 line_num, const hi_char *format, ...)
{
    return;
}

hi_void hi_drv_log_print_key(hi_mod_id module_id, hi_tee_log_level log_level, hi_char *addr, hi_u32 len)
{
    return;
}

hi_s32 tee_log_syscall(hi_s32 swi_id, TSK_REGS_S *regs, UINT64 permissions)
{
    return HI_TEE_ERR_UNSUPPORTED;
}

hi_s32 tee_log_mod_init(hi_void)
{
    return HI_SUCCESS;
}
#endif

hi_tee_drv_hal_driver_init(log, 0, tee_log_mod_init, tee_log_syscall, HI_NULL, HI_NULL);

