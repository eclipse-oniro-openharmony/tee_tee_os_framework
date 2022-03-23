/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define MSP core error numbers.
 * Author : w00371137
 * Create: 2019/12/25
 */

#ifndef __MSPC_ERRNO_H__
#define __MSPC_ERRNO_H__

#define MSPC_OK              0x5A5A
#define MSPC_ERROR           0xA5A5

/* mspc teeos  err prefix */
#define ERR_PREFIX           0xA4

#define ERR_MAKEUP(prefix, module, errcode) \
    (((prefix) << 24U) | (((module) & 0xff) << 16U) | ((errcode) & 0xffffU))

#define MSPC_ERRCODE(errcode) \
    ERR_MAKEUP(ERR_PREFIX, MSPC_THIS_MODULE, (errcode))

#define MSPC_ERRCODE_MASK 0xffffU

enum mspc_module_type {
    MSPC_MODULE_TEEOS       = 0x0,
    MSPC_MODULE_POWER       = 0x1,
    MSPC_MODULE_API         = 0x2,
    MSPC_MODULE_IPC         = 0x3,
};

enum mspc_error_no {
    INVALID_PARAM           = 0x0,
    LIBC_COPY_ERR           = 0x1,
    TIMEOUT_ERR             = 0x2,
    OVERFLOW_ERR            = 0x3,
    CHECK_FAC_MODE_ERR      = 0x4,
};

#endif /* __MSPC_ERRNO_H__ */
