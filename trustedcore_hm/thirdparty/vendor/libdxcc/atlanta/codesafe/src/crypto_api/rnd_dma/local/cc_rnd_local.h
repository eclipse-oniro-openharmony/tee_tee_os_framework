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

#ifndef _CC_RND_LOCAL_H
#define _CC_RND_LOCAL_H

#ifdef __cplusplus
extern "C"
{
#endif


#include "cc_rnd.h"


/************************ Defines ****************************/


/*************************************************************/
/****** Common definitions for RND_DMA and non DMA     *******/
/*************************************************************/

#define CC_RND_VECT_IN_RANGE_MAX_COUNT_OF_TRIES    100

#define CC_RND_BASIC_BLOCK_SIZE_IN_WORDS 4
#define CC_RND_BASIC_BLOCK_SIZE_IN_BYTES (CC_RND_BASIC_BLOCK_SIZE_IN_WORDS*sizeof(uint32_t))
#define CC_RND_ENTROPY_BLOCK_SIZE_IN_WORDS 4
#define CC_RND_ENTROPY_BLOCK_SIZE_IN_BYTES (CC_RND_ENTROPY_BLOCK_SIZE_IN_WORDS*sizeof(uint32_t))

/* Bit-fields of Instantiation steps in the StateFlag:
    - b'0: 0 - not instantiated, 1 - instantiated normally;
    - b'1: 1 - loss samples, 0 - no loss;
    - b'2: 1 - time exceeding, 0 - no time exceeding.
    In case of sample loss or time exceed b`0 must be 0 */
#define CC_RND_NOT_INSTANTIATED             	0UL
#define CC_RND_INSTANTIATED                	1UL
#define CC_RND_INSTANTRESEED_AUTOCORR_ERRORS 	2UL
#define CC_RND_INSTANTRESEED_TIME_EXCEED     	4UL
#define CC_RND_INSTANTRESEED_LESS_ENTROPY    	8UL

/* The 2-bit field in the StateFlag, defining the working or KAT modes:
     - b`9,8: 0 - working mode, 1 - KAT DRBG mode, 2 - KAT TRNG mode, 3 - KAT
       DRBG or/and TRNG mode */
#define CC_RND_WORK_Mode                  (0UL << 8)
#define CC_RND_KAT_DRBG_Mode 	          (1UL << 8)
#define CC_RND_KAT_TRNG_Mode              (2UL << 8)
#define CC_RND_KAT_Mode 	          CC_RND_KAT_DRBG_Mode

/* The bit-field in the StateFlag, defining that the previous generated random
   block is valid for comparison with current block or not */
#define CC_RND_PreviousIsValid          (1UL << 16)

/* RND WorkBuffer = ESTIM_BUFF || ENTROPY_SOURCE_BUFF. Size of buffer = 1KB = *
*  1024 words.  Max size (in words) of internal buffers:		      */
#define CC_RND_FULL_ENTROPY_SOURCE_BUFF_SIZE_WORDS 504
#define CC_RND_ESTIM_BUFF_SIZE_WORDS           386 /*256+128+2*/
#define CC_RND_ENTROPY_SOURCE_BUFF_SIZE_WORDS     1024/*2+504+504+12+1+padding */
/* Offsets of buffers used in KAT mode */
#define CC_RND_WORK_BUFF_TMP1_OFFSET  (CC_RND_ESTIM_BUFF_SIZE_WORDS + CC_RND_ENTROPY_SOURCE_BUFF_SIZE_WORDS + 4)
#define CC_RND_WORK_BUFF_TMP2_OFFSET  (CC_RND_WORK_BUFF_TMP1_OFFSET + CC_RND_SEED_MAX_SIZE_WORDS + 4)

/* max size of KAT entropy and nonce data in words on SWEE and FE modes*/
#define CC_RND_ENTROPY_TEMP_BUFFER_MAX_SIZE_WORDS  126

/* RND buffers placing: |EstimatorBuffer||RND_SrcBuffer|KAT buffers|,  where:
        RND_SrcBuffer = |Empty 2words for CC|TRNG source+AddData|    */
#define CC_RND_SRC_BUFF_OFFSET_WORDS  CC_RND_ESTIM_BUFF_SIZE_WORDS


/* Offsets (in words) of RND estimator buffer members inside the buffer */
#define CC_RND_H_BUFF_OFFSET   0
#define CC_RND_EC_BUFF_OFFSET  256

/* Validation tag for random working state: should be set by:   	      *
   RndInstantiateOrReseed function on not continued mode or by           *
*  LLF_RND_StartTrngHW function on continued mode       		      */
#define CC_RND_WORK_STATE_VALID_TAG  0X0123ABCD

/*Values for entropy flag*/
#define LLF_RNG_ENTROPY_FLAG_REQUIRED   0x0
#define LLF_RNG_ENTROPY_FLAG_LOW        0x1
#define LLF_RNG_ENTROPY_FLAG_NULL       0x2
#define LLF_RNG_ENTROPY_FLAG_KAT_MODE   0x3

#define LLF_RNG_MAX_COLLECTION_ITERATION_SIZE 0x5

#define LLF_RND_MAX_NUM_OF_ROSCS 0x4
/************************ Enums ********************************/


/************************ Structs  ******************************/

/* The CC Random Generator Parameters  structure CCRndParams_t -
   structure containing the user given Parameters */
typedef struct  CCRndParams_t
{
	/* parameters defining TRNG */
	CCRndMode_t TrngMode;

	/* allowed ring oscillator lengths: bits 0,1,2,3  */
	uint32_t  RoscsAllowed;

	/* sampling interval: count of ring oscillator cycles between
	   consecutive bits sampling */
	uint32_t  SubSamplingRatio;

    uint32_t  SubSamplingRatio1;
    uint32_t  SubSamplingRatio2;
    uint32_t  SubSamplingRatio3;
    uint32_t  SubSamplingRatio4;

}CCRndParams_t;


/************************ Typedefs  ****************************/

/************************ Public Variables **********************/

/************************ Public Functions **********************/


#ifdef __cplusplus
}
#endif

#endif


