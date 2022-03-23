/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Define MSP core error numbers.
 * Create: 2019/12/25
 */

#ifndef __MSPC_ERRNO_H__
#define __MSPC_ERRNO_H__

/*
 * CAUTION!
 * Some error numbers are supported to TA to do special process, so donnot modify
 * these defines. If you must modify it, please amend the define in file
 * vendor/huaweiplatform/itrustee/secure_os/trustedcore_hm/libs/libmspcore_a32/src/mspc_ext_api.c
 * synchronously. These macro defines below cannot be modified:
 * ERR_PREFIX, MSPC_MODULE_POWER, MSPC_MODULE_API, TIMEOUT_ERR, MSPC_API_RESET_ERR.
 */

#define MSPC_OK              0x5A5A
#define MSPC_ERROR           0xA5A5

/* mspc teeos  err prefix */
#define ERR_PREFIX           0xA4 /* Donnot modify it, see CAUTION. */

#define ERR_MAKEUP(prefix, module, errcode) \
    (((prefix) << 24U) | (((module) & 0xff) << 16U) | ((errcode) & 0xffffU))

#define MSPC_ERRCODE(errcode) \
    ERR_MAKEUP(ERR_PREFIX, MSPC_THIS_MODULE, (errcode))

#define MSPC_ERRCODE_MASK 0xffffU

enum mspc_module_type {
    MSPC_MODULE_TEEOS       = 0x0,
    MSPC_MODULE_POWER       = 0x1, /* Donnot modify it, see CAUTION. */
    MSPC_MODULE_API         = 0x2, /* Donnot modify it, see CAUTION. */
    MSPC_MODULE_IPC         = 0x3,
};

enum mspc_error_no {
    INVALID_PARAM           = 0x0,
    LIBC_COPY_ERR           = 0x1,
    TIMEOUT_ERR             = 0x2, /* Donnot modify it, see CAUTION. */
    OVERFLOW_ERR            = 0x3,
    CHECK_FAC_MODE_ERR      = 0x4,
};

#endif /* __MSPC_ERRNO_H__ */
