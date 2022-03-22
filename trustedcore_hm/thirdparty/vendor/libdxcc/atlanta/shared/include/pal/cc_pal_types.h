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

#ifndef CC_PAL_TYPES_H
#define CC_PAL_TYPES_H

/*!
@file
@brief This file contains platform-dependent definitions and types.
*/

#include "cc_pal_types_plat.h"

typedef enum {
    CC_FALSE = 0,
    CC_TRUE = 1
} CCBool;

#define CC_SUCCESS              0UL
#define CC_FAIL		  	1UL

#define CC_1K_SIZE_IN_BYTES	1024
#define CC_BITS_IN_BYTE		8
#define CC_BITS_IN_32BIT_WORD	32
#define CC_32BIT_WORD_SIZE	(sizeof(uint32_t))

#define CC_OK   0

#define CC_UNUSED_PARAM(prm)  ((void)prm)

#define CC_MAX_UINT32_VAL 	(0xFFFFFFFF)


/* Minimum and Maximum macros */
/* ND need to replace name */
#ifdef  min
#define CC_MIN(a,b) min( a , b )
#else
#define CC_MIN( a , b ) ( ( (a) < (b) ) ? (a) : (b) )
#endif

#ifdef max
#define CC_MAX(a,b) max( a , b )
#else
#define CC_MAX( a , b ) ( ( (a) > (b) ) ? (a) : (b) )
#endif

#define CALC_FULL_BYTES(numBits) 		((numBits)/CC_BITS_IN_BYTE + (((numBits) & (CC_BITS_IN_BYTE-1)) > 0))
#define CALC_FULL_32BIT_WORDS(numBits) 		((numBits)/CC_BITS_IN_32BIT_WORD +  (((numBits) & (CC_BITS_IN_32BIT_WORD-1)) > 0))
#define CALC_32BIT_WORDS_FROM_BYTES(sizeBytes)  ((sizeBytes)/CC_32BIT_WORD_SIZE + (((sizeBytes) & (CC_32BIT_WORD_SIZE-1)) > 0))
#define ROUNDUP_BITS_TO_32BIT_WORD(numBits) 	(CALC_FULL_32BIT_WORDS(numBits) * CC_BITS_IN_32BIT_WORD)
#define ROUNDUP_BITS_TO_BYTES(numBits) 		(CALC_FULL_BYTES(numBits) * CC_BITS_IN_BYTE)
#define ROUNDUP_BYTES_TO_32BIT_WORD(sizeBytes) 	(CALC_32BIT_WORDS_FROM_BYTES(sizeBytes) * CC_32BIT_WORD_SIZE)

#endif
