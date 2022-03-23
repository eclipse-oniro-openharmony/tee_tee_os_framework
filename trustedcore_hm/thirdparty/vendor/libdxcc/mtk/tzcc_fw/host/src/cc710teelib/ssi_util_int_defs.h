/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_INT_DEFS_H
#define _SSI_UTIL_INT_DEFS_H

#include "ssi_hal.h"
#include "ssi_regs.h"
#include "ssi_general_defs.h"

#define SASI_UTIL_BUFF_IN_WORDS (sizeof(struct drv_ctx_cipher) / 2 + 3)
#define SASI_UTIL_BUFF_IN_BYTES (SASI_UTIL_BUFF_IN_WORDS * sizeof(uint32_t))

/* session key definition */
#define SASI_UTIL_SESSION_KEY_IS_UNSET 0

/* Check KDR error bit in LCS register */
#define SASI_UTIL_IS_OTP_KDR_ERROR(rc)                                                                 \
    do {                                                                                               \
        rc = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_REG));                               \
        rc = (rc >> DX_LCS_REG_ERROR_KDR_ZERO_CNT_BIT_SHIFT) & DX_LCS_REG_ERROR_KDR_ZERO_CNT_BIT_SIZE; \
    } while (0)

/* Check session key validity */
#define SASI_UTIL_IS_SESSION_KEY_VALID(rc)                                                 \
    do {                                                                                   \
        rc = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_SESSION_KEY_IS_VALID)); \
        rc = SASI_REG_FLD_GET(0, HOST_SESSION_KEY_IS_VALID, VALUE, rc);                    \
    } while (0)

/* Check if secure LCS register */
#define SASI_UTIL_IS_SEC_LCS(rc)                                                              \
    do {                                                                                      \
        rc = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_REG));                      \
        rc = (rc >> DX_LCS_REG_LCS_REG_BIT_SHIFT) & ((1 << DX_LCS_REG_LCS_REG_BIT_SIZE) - 1); \
        rc = (rc == SASI_LCS_SECURE_LCS) ? SASI_TRUE : SASI_FALSE;                            \
    } while (0)

/* Get LCS register */
#define SASI_UTIL_GET_LCS(rc)                                                                 \
    do {                                                                                      \
        rc = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_REG));                      \
        rc = (rc >> DX_LCS_REG_LCS_REG_BIT_SHIFT) & ((1 << DX_LCS_REG_LCS_REG_BIT_SIZE) - 1); \
    } while (0)

/* endorsement key definitions */
#define SASI_UTIL_EK_CMAC_COUNT                   0x03
#define SASI_UTIL_EK_ECC256_ORDER_LENGTH          0x20 /* 32 bytes for ECC256  */
#define SASI_UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS (SASI_UTIL_EK_ECC256_ORDER_LENGTH >> 2)

#define SASI_UTIL_EK_DATA_IN_CMAC_LENGTH (4 + SASI_UTIL_EK_ECC256_ORDER_LENGTH) /* need 4 additional bytes */
#define SASI_UTIL_EK_PREFIX1_DATA0       0x01
#define SASI_UTIL_EK_PREFIX2_DATA0       0x02
#define SASI_UTIL_EK_PREFIX3_DATA0       0x03
#define SASI_UTIL_EK_PREFIX_DATA1        0x45
#define SASI_UTIL_EK_PREFIX_DATA2        0x00
#define SASI_UTIL_EK_SUFIX_DATA          0x80

#define SASI_UTIL_EK_LABEL 0x45

/* set session key definitions */
#define SASI_UTIL_SK_RND_DATA_LENGTH 0x0B
#define SASI_UTIL_SK_LABEL           0x53

#endif /* _SSI_UTIL_INT_DEFS_H */
