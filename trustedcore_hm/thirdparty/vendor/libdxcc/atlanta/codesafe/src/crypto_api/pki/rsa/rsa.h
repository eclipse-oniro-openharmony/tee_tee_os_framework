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


#ifndef LLF_RSA_H
#define LLF_RSA_H


#include "cc_rsa_types.h"
#include "cc_rnd.h"

#ifdef __cplusplus
extern "C"
{
#endif

/************************ Defines ******************************/

#define PKA_MAX_RSA_KEY_GENERATION_SIZE_BITS   CC_RSA_MAX_KEY_GENERATION_SIZE_BITS
/* max allowed size of pprimes P, Q in RSA KG */
#define PKA_RSA_KG_MAX_PQ_SIZE_BITS  (PKA_MAX_RSA_KEY_GENERATION_SIZE_BITS/2)
/* max. total count of avaliable PKA registers in RSA KG */
#define PKA_RSA_KG_MAX_COUNT_REGS  \
        CC_MIN(PKA_MAX_COUNT_OF_PHYS_MEM_REGS, \
                (8*CC_SRAM_PKA_SIZE_IN_BYTES) / (PKA_RSA_KG_MAX_PQ_SIZE_BITS + CC_PKA_WORD_SIZE_IN_BITS))
/* max. count of avaliable registers in RSA KG without auxiliary regs. 30,31  */
#define PKA_RSA_KG_MAX_REG_ID (PKA_RSA_KG_MAX_COUNT_REGS - 2)

/* define size of auxiliary prime numbers for RSA  *
*  (see FIPS 186-4 C3 tab.C3)                      */
#define PKA_RSA_KEY_1024_AUX_PRIME_SIZE_BITS   104   /* for P,Q size 1024 bit aux.size > 100 bits */
#define PKA_RSA_KEY_2048_AUX_PRIME_SIZE_BITS   144   /* for P,Q size 2048 bit aux.size > 140 bits */
#define PKA_RSA_KEY_3072_AUX_PRIME_SIZE_BITS   176   /* for P,Q size 3072 bit aux.size > 170 bits */

#define PKA_RSA_AUX_PRIME_BUFF_SIZE_IN_32BIT_WORDS 8 /* max size of temp buffer for auxiliary prime */

/* define count of Miller-Rabin tests for P,Q and  auxiliary prime numbers *
*  for RSA key generation (see FIPS 186-4 C3 tab.C3)                       */
#define PKA_RSA_KEY_1024_AUX_PRIME_RM_TST_COUNT 38
#define PKA_RSA_KEY_1024_PQ_PRIME_RM_TST_COUNT   7
#define PKA_RSA_KEY_2048_AUX_PRIME_RM_TST_COUNT 32
#define PKA_RSA_KEY_2048_PQ_PRIME_RM_TST_COUNT   4
#define PKA_RSA_KEY_3072_AUX_PRIME_RM_TST_COUNT 27
#define PKA_RSA_KEY_3072_PQ_PRIME_RM_TST_COUNT   3


/* define this flag to test RSA KG algorithm with predefined P,Q and p1,p2,   *
*  q1,q2 random data                                                          */
//#define RSA_KG_NO_RND 1

/*  RSA   key generation parameters structure */
typedef struct
{
        uint32_t auxPrimesSizeInBits;
        uint32_t pqPrimesMilRabTestsCount;
        uint32_t auxPrimesMilRabTestsCount;
}RsaKgParams_t;

CCError_t RsaGenerateKeyPair(CCRndContext_t *rndContext_ptr,
			       CCRsaPubKey_t  *PubKey_ptr,
			       CCRsaPrivKey_t *PrivKey_ptr,
			       CCRsaKgData_t *KeyGenData_ptr);



CCError_t RsaPrimeTestCall(CCRndContext_t *rndContext_ptr,
			     uint32_t *P_ptr,
			     int32_t   sizeWords,
			     int32_t   rabinTestsCount,
			     int8_t   *isPrime_ptr,
			     uint32_t *TempBuff_ptr,
			     CCRsaDhPrimeTestMode_t primeTestMode);
#ifdef __cplusplus
}
#endif

#endif
