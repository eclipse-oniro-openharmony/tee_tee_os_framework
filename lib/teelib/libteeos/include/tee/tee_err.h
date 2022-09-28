/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: Reference of TEE error definitions
 * Create: 2021-03-09
 */

#ifndef TEE_ERROR_H
#define TEE_ERROR_H

#include <tee_crypto_err.h>

/*
 * notes: all extension tee error rule is TEE_EXT_ERROR_BASE | xx_MODULE_ERR_ID | base_error_value,
 * For example, the crypto module extension error codes are prefixed with 0x8002.
 */
#define TEE_EXT_ERROR_BASE 0x80000000

enum ext_error_module {
    SSA_MODULE_ERR_ID    = 0x010000,
    CRYPTO_MODULE_ERR_ID = 0x020000,
};

#endif
