/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef _DX_UTIL_DEFS_H
#define _DX_UTIL_DEFS_H

#define DX_UTIL_BUFF_IN_WORDS (sizeof(struct sep_ctx_cipher) / 2 + 3)
#define DX_UTIL_BUFF_IN_BYTES (DX_UTIL_BUFF_IN_WORDS * sizeof(uint32_t))

/* Check KDR error bit in LCS register */
#define DX_UTIL_IS_OTP_KDR_ERROR(rc)                                                                   \
    do {                                                                                               \
        rc = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(HOST_RGF, LCS_REG));                               \
        rc = (rc >> DX_LCS_REG_ERROR_KDR_ZERO_CNT_BIT_SHIFT) & DX_LCS_REG_ERROR_KDR_ZERO_CNT_BIT_SIZE; \
    } while (0)

/* endorsement key definitions */
#define DX_UTIL_EK_CMAC_COUNT                   0x03
#define DX_UTIL_EK_ECC256_ORDER_LENGTH          0x20 /* 32 bytes for ECC256  */
#define DX_UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS (DX_UTIL_EK_ECC256_ORDER_LENGTH >> 2)
#define DX_UTIL_EK_DATA_IN_CMAC_LENGTH          (4 + DX_UTIL_EK_ECC256_ORDER_LENGTH) /* need 4 additional bytes */
#define DX_UTIL_EK_PREFIX1_DATA0                0x01
#define DX_UTIL_EK_PREFIX2_DATA0                0x02
#define DX_UTIL_EK_PREFIX3_DATA0                0x03
#define DX_UTIL_EK_PREFIX_DATA1                 0x45
#define DX_UTIL_EK_PREFIX_DATA2                 0x00
#define DX_UTIL_EK_SUFIX_DATA                   0x80

/* set session key definitions */
#define DX_UTIL_SK_RND_DATA_LENGTH     0x0B
#define DX_UTIL_SK_DATA_IN_CMAC_LENGTH (4 + DX_UTIL_SK_RND_DATA_LENGTH) // need 4 additional bytes
#define DX_UTIL_SK_PREFIX_DATA0        0x01
#define DX_UTIL_SK_PREFIX_DATA1        0x53
#define DX_UTIL_SK_PREFIX_DATA2        0x00
#define DX_UTIL_SK_SUFIX_DATA          0x80

#endif /* _DX_UTIL_DEFS_H */
