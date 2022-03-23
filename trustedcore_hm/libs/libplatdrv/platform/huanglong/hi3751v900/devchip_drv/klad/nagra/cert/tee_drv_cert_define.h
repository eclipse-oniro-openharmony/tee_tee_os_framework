/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define public macros for keyslot drivers.
 * Author: Linux SDK team
 * Create: 2019-08-23
 */
#ifndef __TEE_DRV_CERT_DEFINE_H__
#define __TEE_DRV_CERT_DEFINE_H__

#include "securec.h"
#include "hi_log.h"
#include "hi_tee_errcode.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* end of #ifdef __cplusplus */

#undef LOG_MODULE_ID
#define LOG_MODULE_ID HI_ID_CERT

#define hi_dbg_cert(fmt...)                   hi_log_dbg(fmt)
#define hi_fatal_cert(fmt...)                 hi_log_fatal(fmt)
#define hi_err_cert(fmt...)                   hi_log_err(fmt)
#define hi_warn_cert(fmt...)                  hi_log_warn(fmt)
#define hi_info_cert(fmt...)                  hi_log_info(fmt)

#define cert_func_enter()                     hi_dbg_cert("[ENTER]:%s\n", __FUNCTION__)
#define cert_func_exit()                      hi_dbg_cert("[EXIT] :%s\n", __FUNCTION__)

#define print_err(val)                        hi_err_cert("%s\n", val)
#define print_err_hex(val)                    hi_err_cert("%s = 0x%08x\n", #val, val)
#define print_dbg_hex(val)                    hi_dbg_cert("%s = 0x%08x\n", #val, val)
#define dbg_print_dbg_hex(val)                hi_dbg_cert("%s = 0x%08x\n", #val, val)
#define print_err_val(val)                    hi_err_cert("%s = %d\n", #val, val)
#define print_err_point(val)                  hi_err_cert("%s = %p\n", #val, val)
#define print_err_code(err_code)              hi_err_cert("return [0x%08x]\n", err_code)
#define print_warn_code(err_code)             hi_warn_cert("return [0x%08x]\n", err_code)
#define print_err_func(func, err_code)        hi_err_cert("call [%s] return [0x%08x]\n", #func, err_code)

/* it depends on how many pages can be maped, 0:one page, 1:two pages, 2:four pages, 3: eight pages */
#define PAGE_NUM_SHIFT    0
#define AKL_MAP_PAGE_NUM  (1ULL << PAGE_NUM_SHIFT)
#define AKL_MAP_MASK      (((AKL_MAP_PAGE_NUM) << PAGE_SHIFT) - 1)
#define AKL_MAP_SIZE      0x10000

#define BITS_PER_BYTE     8

/* Register read and write */
#define reg_read(addr, result)  ((result) = *(volatile unsigned int *)(uintptr_t)(addr))
#define reg_write(addr, result)  (*(volatile unsigned int *)(uintptr_t)(addr) = (result))

/*
 * HANDLE macro
 */
#define id_2_handle(id, key) HI_HANDLE_MAKEHANDLE(HI_ID_CERT, (key), (id))
#define handle_2_id(handle)  HI_HANDLE_GET_CHNID(handle)
#define handle_2_type(handle) HI_HANDLE_GET_PriDATA(handle)

#define is_invalid_handle(handle) ({\
    hi_bool ret_ = HI_FALSE; \
    if ((((handle) >> 24) & 0xFF) != HI_ID_CERT) \
        ret_ = HI_TRUE; \
    ret_; \
})

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* end of #ifdef __cplusplus */

#endif /* end of #ifndef __TEE_DRV_CERT_DEFINE_H__ */
