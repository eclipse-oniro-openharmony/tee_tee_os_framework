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

#ifndef _DX_OTP_DEFS_H
#define _DX_OTP_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

/* OTP memory layout */
#define DX_OTP_BASE_ADDR    0x00
#define DX_OTP_START_OFFSET 0x00
#define DX_OTP_KDR_OFFSET   0x00
#define DX_OTP_SCP_OFFSET   0x08

#define DX_OTP_MANUFACTRER_FLAG_OFFSET         0x0A
#define DX_OTP_MANUFACTRER_FLAG_SD_BIT_SHIFT   16
#define DX_OTP_MANUFACTRER_FLAG_SD_BIT_SIZE    4
#define DX_OTP_MANUFACTRER_FLAG_TRNG_BIT_SHIFT 20
#define DX_OTP_MANUFACTRER_FLAG_TRNG_BIT_SIZE  11
#define DX_OTP_MANUFACTRER_FLAG_RMA_BIT_SHIFT  31
#define DX_OTP_MANUFACTRER_FLAG_RMA_BIT_SIZE   1

#define DX_OTP_OEM_FLAG_OFFSET         0x0B
#define DX_OTP_OEM_FLAG_HBK0_BIT_SHIFT 0
#define DX_OTP_OEM_FLAG_HBK0_BIT_SIZE  8
#define DX_OTP_OEM_FLAG_HBK1_BIT_SHIFT 8
#define DX_OTP_OEM_FLAG_HBK1_BIT_SIZE  8
#define DX_OTP_OEM_FLAG_KCE_BIT_SHIFT  24
#define DX_OTP_OEM_FLAG_KCE_BIT_SIZE   8

#define DX_OTP_KCE_OFFSET          0x0C
#define DX_OTP_BASE_HASH_OFFSET    0x10
#define DX_OTP_HASH_INDEX_0_OFFSET 0x10
#define DX_OTP_HASH_INDEX_1_OFFSET 0x14
#define DX_OTP_SW_VERSION_OFFSET   0x18
#define DX_OTP_LAST_OFFSET         0x1F

#define DX_OTP_VERSION_COUNTER1_OFFSET DX_OTP_SW_VERSION_OFFSET
#define DX_OTP_VERSION_COUNTER2_OFFSET (DX_OTP_SW_VERSION_OFFSET + 1)

#ifdef __cplusplus
}
#endif

#endif
