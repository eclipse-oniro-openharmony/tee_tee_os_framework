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

#ifndef _CC_OTP_DEFS_H
#define _CC_OTP_DEFS_H

/*!
@file
@brief This file contains general OTP definitions and memory layout.
*/


#ifdef __cplusplus
extern "C"
{
#endif


/* OTP memory layout */
#define CC_OTP_BASE_ADDR			0x00UL
#define CC_OTP_START_OFFSET			0x00UL

#define CC_OTP_KDR_OFFSET			0x00UL
#define CC_OTP_KDR_SIZE_IN_WORDS              	8

#define CC_OTP_SCP_OFFSET			0x08UL
#define CC_OTP_SCP_SIZE_IN_WORDS              	2

#define CC_OTP_MANUFACTURE_FLAG_OFFSET		0x0AUL

#define CC_OTP_MANUFACTURE_FLAG_KDR_ZERO_BITS_BIT_SHIFT       0
#define CC_OTP_MANUFACTURE_FLAG_KDR_ZERO_BITS_BIT_SIZE        8
#define CC_OTP_MANUFACTURE_FLAG_KDR_ZERO_BITS_MASK         	\
				(((1<<CC_OTP_MANUFACTURE_FLAG_KDR_ZERO_BITS_BIT_SIZE)-1)<<CC_OTP_MANUFACTURE_FLAG_KDR_ZERO_BITS_BIT_SHIFT)

#define CC_OTP_MANUFACTURE_FLAG_SCP_ZERO_BITS_BIT_SHIFT       8
#define CC_OTP_MANUFACTURE_FLAG_SCP_ZERO_BITS_BIT_SIZE        8
#define CC_OTP_MANUFACTURE_FLAG_SCP_ZERO_BITS_MASK         	\
				(((1<<CC_OTP_MANUFACTURE_FLAG_SCP_ZERO_BITS_BIT_SIZE)-1)<<CC_OTP_MANUFACTURE_FLAG_SCP_ZERO_BITS_BIT_SHIFT)

#define CC_OTP_MANUFACTURE_FLAG_KDR_SCP_ZERO_BITS_MASK               \
				(CC_OTP_MANUFACTURE_FLAG_KDR_ZERO_BITS_MASK | CC_OTP_MANUFACTURE_FLAG_SCP_ZERO_BITS_MASK)

#define CC_OTP_MANUFACTURE_FLAG_KCUST_DISABLED_BIT_SHIFT 	15
#define CC_OTP_MANUFACTURE_FLAG_KCUST_DISABLED_BIT_SIZE 	1
#define CC_OTP_MANUFACTURE_FLAG_KCUST_DISABLED_MASK    			\
				(((1<<CC_OTP_MANUFACTURE_FLAG_KCUST_DISABLED_BIT_SIZE)-1)<<CC_OTP_MANUFACTURE_FLAG_KCUST_DISABLED_BIT_SHIFT)

#define CC_OTP_MANUFACTURE_FLAG_SD_BIT_SHIFT 			16
#define CC_OTP_MANUFACTURE_FLAG_SD_BIT_SIZE 			4
#define CC_OTP_MANUFACTURE_FLAG_SD_MASK    			\
				(((1<<CC_OTP_MANUFACTURE_FLAG_SD_BIT_SIZE)-1)<<CC_OTP_MANUFACTURE_FLAG_SD_BIT_SHIFT)

#define CC_OTP_MANUFACTURE_FLAG_SECURITY_ENABLE_VAL           0x3UL


#define CC_OTP_MANUFACTURE_FLAG_RMA_BIT_SHIFT              	31
#define CC_OTP_MANUFACTURE_FLAG_RMA_BIT_SIZE               	1
#define CC_OTP_MANUFACTURE_FLAG_RMA_MASK                   	\
				(((1<<CC_OTP_MANUFACTURE_FLAG_RMA_BIT_SIZE)-1)<<CC_OTP_MANUFACTURE_FLAG_RMA_BIT_SHIFT)


#define CC_OTP_OEM_FLAG_OFFSET			0x0BUL
#define CC_OTP_OEM_FLAG_HBK0_BIT_SHIFT 		0
#define CC_OTP_OEM_FLAG_HBK0_BIT_SIZE 		8
#define CC_OTP_OEM_FLAG_HBK1_BIT_SHIFT 		8
#define CC_OTP_OEM_FLAG_HBK1_BIT_SIZE 		8
#define CC_OTP_OEM_FLAG_KCE_BIT_SHIFT 		24
#define CC_OTP_OEM_FLAG_KCE_BIT_SIZE 		8

#define CC_OTP_KCE_OFFSET			0x0CUL
#define CC_OTP_KCE_SIZE_IN_WORDS              	4

#define CC_OTP_BASE_HASH_OFFSET			0x10UL
#define CC_OTP_HASH_INDEX_0_OFFSET		0x10UL
#define CC_OTP_HASH_INDEX_1_OFFSET		0x14UL
#define CC_OTP_SW_VERSION_OFFSET		0x18UL

#define CC_OTP_EKCUST_OFFSET			0x20UL
#define CC_OTP_EKCUST_SIZE_IN_WORDS		0x04UL

#define CC_OTP_EKCUST_NUM_OF_ZEROS_OFFSET	0x24UL
#define CC_OTP_EKCUST_NUM_OF_ZEROS_SIZE_IN_WORDS 0x01UL

#define CC_OTP_LAST_OFFSET			0x24UL

#define CC_OTP_VERSION_COUNTER1_OFFSET		CC_OTP_SW_VERSION_OFFSET
#define CC_OTP_VERSION_COUNTER2_OFFSET		(CC_OTP_SW_VERSION_OFFSET+1)

#ifdef __cplusplus
}
#endif

#endif



