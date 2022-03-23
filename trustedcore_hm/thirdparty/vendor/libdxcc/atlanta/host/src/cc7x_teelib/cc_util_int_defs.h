/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/

#ifndef  _CC_UTIL_INT_DEFS_H
#define  _CC_UTIL_INT_DEFS_H

#include "cc_hal.h"
#include "cc_regs.h"
#include "cc_general_defs.h"

#define CC_UTIL_BUFF_IN_WORDS	(sizeof(struct drv_ctx_cipher)/2 + 3)
#define CC_UTIL_BUFF_IN_BYTES	(CC_UTIL_BUFF_IN_WORDS*sizeof(uint32_t))

/* session key definition */
#define CC_UTIL_SESSION_KEY_IS_UNSET		0

/* Check KDR error bit in LCS register */
#define CC_UTIL_IS_OTP_KDR_ERROR(rc) 						                              \
	do { 											              \
		rc = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,LCS_REG));			              \
		rc = (rc >> DX_LCS_REG_ERROR_KDR_ZERO_CNT_BIT_SHIFT) & DX_LCS_REG_ERROR_KDR_ZERO_CNT_BIT_SIZE;\
	}while(0)


/* Check session key validity */
#define CC_UTIL_IS_SESSION_KEY_VALID(rc) 						         \
	do { 											 \
		rc = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_SESSION_KEY_IS_VALID));\
		rc = CC_REG_FLD_GET(0, HOST_SESSION_KEY_IS_VALID, VALUE, rc);			 \
	}while(0)

/* Check if secure LCS register */
#define CC_UTIL_IS_SEC_LCS(rc) 						                 \
	do { 											 \
		rc = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,LCS_REG));			 \
		rc = (rc >> DX_LCS_REG_LCS_REG_BIT_SHIFT) & ((1<<DX_LCS_REG_LCS_REG_BIT_SIZE)-1);\
		rc = (rc == CC_LCS_SECURE_LCS)?CC_TRUE:CC_FALSE;\
	}while(0)

/* Check if Kcust disable */
#define CC_UTIL_IS_KCUST_DISABLE(rc) 						                 \
	do { 											 \
		rc = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_KCST_DISABLE));		 \
		rc = CC_REG_FLD_GET(0, HOST_KCST_DISABLE, VALUE, rc);			 	 \
	}while(0)

/* Get LCS register */
#define CC_UTIL_GET_LCS(rc) 						                 	 \
	do { 											 \
		rc = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF,LCS_REG));			 \
		rc = (rc >> DX_LCS_REG_LCS_REG_BIT_SHIFT) & ((1<<DX_LCS_REG_LCS_REG_BIT_SIZE)-1);\
	}while(0)

/* Poll on the LCS valid register */
#define CC_UTIL_WAIT_ON_LCS_VALID_BIT(rc) 							\
	do { 											\
		do { 										\
			rc = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, LCS_IS_VALID));	\
			rc = CC_REG_FLD_GET(0, LCS_IS_VALID, VALUE, rc); 		\
		}while( !rc ); 								\
	}while(0)

/* endorsement key definitions*/
#define UTIL_EK_CMAC_COUNT 		0x03
#define UTIL_EK_ECC256_ORDER_LENGTH     0x20 /* 32 bytes for ECC256  */
#define UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS   (UTIL_EK_ECC256_ORDER_LENGTH>>2)
#define UTIL_EK_ECC256_FULL_RANDOM_LENGTH  (UTIL_EK_ECC256_ORDER_LENGTH + CC_RND_FIPS_ADDIT_BYTES_FOR_RND_IN_RANGE)
#define UTIL_EK_ECC256_FULL_RANDOM_LENGTH_IN_WORDS  (UTIL_EK_ECC256_FULL_RANDOM_LENGTH>>2)

#define UTIL_EK_LABEL		0x45

/* set session key definitions*/
#define UTIL_SK_RND_DATA_BYTE_LENGTH  	0x0C	/* 96bit */
#define UTIL_SK_LABEL			0x53

#define CC_BSV_KCUST_IS_DISABLED_ON	1

typedef enum  {
	UTIL_USER_KEY = 0,
	UTIL_ROOT_KEY = 1,
	UTIL_SESSION_KEY = 2,
	UTIL_END_OF_KEY_TYPE = 0x7FFFFFFF
}UtilKeyType_t;

#endif /*_CC_UTIL_INT_DEFS_H*/
