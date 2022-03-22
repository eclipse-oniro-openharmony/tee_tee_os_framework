/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define API about key slot driver
 * Author: Linux SDK team
 * Create: 2019-8-22
 */
#ifndef __TEE_CERT_H__
#define __TEE_CERT_H__

#include "hi_log.h"
#include "hi_tee_errcode.h"
#include "hi_tee_module_id.h"
#include "hi_tee_drv_cert.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

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
#define print_dbg_hex(val)                    hi_dbg_cert("%s = 0x%08x\n", #val, val)
#define dbg_print_dbg_hex(val)                hi_dbg_cert("%s = 0x%08x\n", #val, val)
#define print_err_hex(val)                    hi_err_cert("%s = 0x%08x\n", #val, val)
#define print_err_val(val)                    hi_err_cert("%s = %d\n", #val, val)
#define print_err_point(val)                  hi_err_cert("%s = %p\n", #val, val)
#define print_err_code(err_code)              hi_err_cert("return [0x%08x]\n", err_code)
#define print_warn_code(err_code)             hi_warn_cert("return [0x%08x]\n", err_code)
#define print_err_func(func, err_code)        hi_err_cert("call [%s] return [0x%08x]\n", #func, err_code)

hi_s32 hi_mpi_cert_init(hi_void);

hi_s32 hi_mpi_cert_deinit(hi_void);

hi_s32 hi_mpi_cert_usekey(hi_cert_key_data *ctl_data);

hi_s32 hi_mpi_cert_get_metadata(hi_u32 *metadata);

hi_s32 hi_mpi_cert_reset(hi_void);

hi_s32 hi_mpi_cert_lock(hi_cert_res_handle **handle);

hi_s32 hi_mpi_cert_unlock(hi_cert_res_handle *handle);

hi_s32 hi_mpi_cert_exchange(hi_cert_res_handle *handle, hi_size_t num_of_commands,
                            hi_cert_command *command, hi_size_t *num_of_processed_commands);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif /* __TEE_CERT_H__ */

