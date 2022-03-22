/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef __SSI_ERROR_H__
#define __SSI_ERROR_H__

#ifdef __KERNEL__
#include <linux/types.h>
#define INT32_MAX 0x7FFFFFFFL
#else
#include <stdint.h>
#endif

typedef enum SaSiSymRetCode {
    SASI_RET_OK = 0,                       /* No error */
    SASI_RET_UNSUPP_ALG,                   /* Unsupported algorithm */
    SASI_RET_UNSUPP_ALG_MODE,              /* Unsupported algorithm mode */
    SASI_RET_UNSUPP_OPERATION,             /* Unsupported operation */
    SASI_RET_UNSUPP_HWKEY,                 /* Unsupported hw key */
    SASI_RET_INV_HWKEY,                    /* invalid hw key */
    SASI_RET_INVARG,                       /* Invalid parameter */
    SASI_RET_INVARG_QID,                   /* Invalid queue ID */
    SASI_RET_INVARG_KEY_SIZE,              /* Invalid key size */
    SASI_RET_INVARG_CTX_IDX,               /* Invalid context index */
    SASI_RET_INVARG_CTX,                   /* Bad or corrupted context */
    SASI_RET_INVARG_BAD_ADDR,              /* Bad address */
    SASI_RET_INVARG_INCONSIST_DMA_TYPE,    /* DIN is inconsist with DOUT DMA type */
    SASI_RET_PERM,                         /* Operation not permitted */
    SASI_RET_NOEXEC,                       /* Execution format error */
    SASI_RET_BUSY,                         /* Resource busy */
    SASI_RET_NOMEM,                        /* Out of memory */
    SASI_RET_OSFAULT,                      /* Internal OS error */
    SEPSYMCRYPTO_RET_RESERVE32 = INT32_MAX /* assure this enum is 32b */
} SaSiSymRetCode_t;

#endif /* __SSI_ERROR_H__ */
