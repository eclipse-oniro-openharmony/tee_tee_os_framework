/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description:Define public macros for keyslot drivers.
 * Author: Linux SDK team
 * Create: 2019/06/22
 */
#ifndef __DRV_KS_DEFINE_H__
#define __DRV_KS_DEFINE_H__

#include "hmdrv.h"
#include "hi_log.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_syscall_id.h"
#include "hi_tee_drv_os_hal.h"
#include "hi_tee_errcode.h"

#include "hi_tee_drv_keyslot.h"
#include "tee_drv_ioctl_keyslot.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

#if TMP_LOG_OUT
#define hi_debug_ks(fmt...)                 hi_tee_drv_hal_printf(fmt)
#define hi_fatal_ks(fmt...)                 hi_tee_drv_hal_printf(fmt)
#define hi_err_ks(fmt...)                   hi_tee_drv_hal_printf(fmt)
#define hi_warn_ks(fmt...)                  hi_tee_drv_hal_printf(fmt)
#define hi_info_ks(fmt...)                  hi_tee_drv_hal_printf(fmt)
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

#define print_dbg_hex(val)                  hi_debug_ks("%s = 0x%08x\n", #val, val)
#define print_dbg_hex2(x, y)                hi_debug_ks("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_dbg_hex3(x, y, z)             hi_debug_ks("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)

#define print_err_hex(val)                  hi_err_ks("%s = 0x%08x\n", #val, val)
#define print_err_hex2(x, y)                hi_err_ks("%s = 0x%08x %s = 0x%08x\n", #x, x, #y, y)
#define print_err_hex3(x, y, z)             hi_err_ks("%s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #x, x, #y, y, #z, z)
#define print_err_hex4(w, x, y, z)          hi_err_ks("%s = 0x%08x %s = 0x%08x %s = 0x%08x %s = 0x%08x\n", #w, \
                                            w, #x, x, #y, y, #z, z)
#define print_err_val(val)                  hi_err_ks("%s = %d\n", #val, val)
#define print_err_point(val)                hi_err_ks("%s = %p\n", #val, val)
#define print_err_code(err_code)            hi_err_ks("return [0x%08x]\n", err_code)
#define print_warn_code(err_code)           hi_warn_ks("return [0x%08x]\n", err_code)
#define print_err_func(func, err_code)      hi_err_ks("call [%s] return [0x%08x]\n", #func, err_code)

/* Register read and write */
#define reg_read(addr, result)  ((result) = *(volatile unsigned int *)(uintptr_t)(addr))
#define reg_write(addr, result)  (*(volatile unsigned int *)(uintptr_t)(addr) = (result))

/*
 * HANDLE macro
 */
#define id_2_handle(id, key) HI_HANDLE_MAKEHANDLE(HI_ID_KEYSLOT, (key), (id))
#define handle_2_id(handle)  HI_HANDLE_GET_CHNID(handle)
#define handle_2_type(handle) HI_HANDLE_GET_PriDATA(handle)

#define is_invalid_handle(handle) ({\
    hi_bool ret_ = HI_FALSE; \
    if ((((handle) >> 24) & 0xFF) != HI_ID_KEYSLOT) \
        ret_ = HI_TRUE; \
    ret_; \
})

#define udelay(us)           hi_tee_drv_hal_udelay(us)
typedef struct hi_tee_hal_mutex mutex;
#define mutex_lock(lock)     hi_tee_drv_hal_mutex_lock(lock);
#define mutex_unlock(lock)   hi_tee_drv_hal_mutex_unlock(lock);
#define mutex_init(lock)     hi_tee_drv_hal_mutex_init("ks_lock", lock);
#define mutex_destroy(lock)  hi_tee_drv_hal_mutex_destroy(lock);

#define __mutex_initializer(lock) {0}

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* end of #ifdef __cplusplus */

#endif /* end of #ifndef __DRV_KS_H__ */
