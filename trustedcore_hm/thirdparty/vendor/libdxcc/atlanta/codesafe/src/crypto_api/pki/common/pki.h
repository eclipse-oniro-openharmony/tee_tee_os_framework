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



#ifndef PKA_EXPORT_H
#define PKA_EXPORT_H

#include "cc_pal_types.h"
#include "cc_error.h"

#ifdef __cplusplus
extern "C"
{
#endif

/* the macro gets two bits [i+1,i] LE words array */
#define PKI_GET_TWO_BITS_FROM_WORDS_ARRAY(pArr, i) \
   ((pArr[(i)>>5] >> ((i)&31)) & 3)
/* the macro gets bit[i] from LE words array */
#define PKI_GET_BIT_FROM_WORDS_ARRAY(pArr, i) \
   ((pArr[(i)>>5] >> ((i)&31)) & 1)


bool PkiIsModSquareRootExists(void);

void PkiClearAllPka(void);

void PkiConditionalSecureSwapUint32(uint32_t *x,
				    uint32_t *y,
				    uint32_t swp);

CCError_t  PkiCalcNp(uint32_t *pNp,
			uint32_t *pN,
			uint32_t  sizeNbits);


CCError_t  PkiLongNumDiv(uint32_t *pNumA,
			   uint32_t numASizeInWords,
			   uint32_t *pNumB,
			   uint32_t numBSizeInWords,
			   uint32_t *pModRes,
			   uint32_t *pDivRes);


CCError_t PkiLongNumMul(uint32_t *pNumA ,
			  uint32_t  ASizeInBits,
			  uint32_t *pNumB ,
			  uint32_t *pRes);

/*!< get next two bits of scalar*/
uint32_t PkiGetNextTwoMsBits(uint32_t *pScalar, uint32_t *pWord, int32_t i);

/*!< the function checks is array equal to 0  *
*    if(arr == 0) return 0, else 1.           */
bool PkiIsUint8ArrayEqualTo0(const uint8_t *arr, size_t size);

/*!< the function compares equality of two buffers of same size:
     if they are equal - return 1, else 0. */
bool PkiAreBuffersEqual(const void *buff1, const void *buff2, size_t sizeInBytes);


#ifdef __cplusplus
}
#endif

#endif
