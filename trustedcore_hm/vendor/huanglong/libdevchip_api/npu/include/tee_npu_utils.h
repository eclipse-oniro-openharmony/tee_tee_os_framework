/*
 * Copyright (C) Hisilicon Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: tee npu utils impl head file
 * Author: SDK
 * Create: 2020-03-02
 * History:
 */

#ifndef __TEE_NPU_UTILS_H__
#define __TEE_NPU_UTILS_H__

#undef HI_LOG_D_MODULE_ID
#define HI_LOG_D_MODULE_ID     HI_ID_NPU

#undef HI_LOG_D_FUNCTRACE
#define HI_LOG_D_FUNCTRACE     (1)

#undef HI_LOG_D_UNFTRACE
#define HI_LOG_D_UNFTRACE      (1)

#include "hi_type_dev.h"
#include "hi_tee_log.h"
#include "hi_tee_errcode.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define NPU_NULL_POINTER_VOID(p) do { \
    if ((p) == HI_NULL) {                \
        hi_log_err("null pointer!\n"); \
        return; \
    }\
} while (0)

#define NPU_NULL_POINTER_RETURN(p) do {  \
    if ((p) == HI_NULL) {                \
        hi_log_err("null pointer!\n"); \
        return HI_TEE_ERR_INVALID_PTR; \
    }\
} while (0)

#define NPU_NULL_POINTER_GOTO(p, out_flag) do { \
    if ((p) == HI_NULL) {                       \
        hi_log_err("null pointer!\n");        \
        ret =  HI_TEE_ERR_INVALID_PTR;             \
        goto out_flag;                          \
    }\
} while (0)

#define NPU_NULL_POINTER_BREAK(p) do {   \
    if ((p) == HI_NULL) {                \
        hi_log_err("null pointer!\n"); \
        break;                   \
    }\
} while (0)

#define NPU_UNUSED(x) ((x) = (x))
#define unlikely(condition) (condition)

#define NPU_FATAL_CON_VOID_RETURN(condition) do { \
    if (unlikely(condition)) { \
        hi_log_fatal("NPU FATAL ERROR: %s\n", #condition); \
        return;  \
    } \
} while (0)

#define NPU_FATAL_CON_VOID_GOTO(condition, out_flag) do { \
    if (unlikely(condition)) { \
        hi_log_fatal("NPU FATAL ERROR: %s\n", #condition); \
        goto out_flag;  \
    } \
} while (0)


#define NPU_FATAL_CON_RETURN(condition, err_code) do { \
    if (unlikely(condition)) { \
        hi_log_fatal("NPU FATAL ERROR: %s\n", #condition); \
        return err_code;  \
    } \
} while (0)

#define NPU_FATAL_CON_GOTO(condition, err_code, out_flag) do { \
    if (unlikely(condition)) { \
        hi_log_fatal("NPU FATAL ERROR: %s\n", #condition); \
        ret = err_code; \
        goto out_flag;  \
    } \
} while (0)

hi_s32 tee_npu_init(hi_void);
hi_s32 tee_npu_deinit(hi_void);
hi_s32 __tee_npu_ioctl(unsigned long cmd, hi_void *pri_args);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif

#endif  /* __TEE_NPU_UTILS_H__ */
