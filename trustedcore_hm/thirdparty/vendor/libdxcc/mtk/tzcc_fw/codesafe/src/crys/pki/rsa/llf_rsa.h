/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef LLF_RSA_H
#define LLF_RSA_H

#include "sasi_rsa_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

#define PKA_MAX_RSA_KEY_GENERATION_SIZE_BITS SaSi_RSA_MAX_KEY_GENERATION_SIZE_BITS
/* max allowed size of pprimes P, Q in RSA KG */
#define PKA_RSA_KG_MAX_PQ_SIZE_BITS (PKA_MAX_RSA_KEY_GENERATION_SIZE_BITS / 2)
/* max. total count of avaliable PKA registers in RSA KG */
#define PKA_RSA_KG_MAX_COUNT_REGS            \
    SaSi_MIN(PKA_MAX_COUNT_OF_PHYS_MEM_REGS, \
             (8 * SASI_SRAM_PKA_SIZE_IN_BYTES) / (PKA_RSA_KG_MAX_PQ_SIZE_BITS + SASI_PKA_WORD_SIZE_IN_BITS))
/* max. count of avaliable registers in RSA KG without auxiliary regs. 30,31  */
#define PKA_RSA_KG_MAX_REG_ID (PKA_RSA_KG_MAX_COUNT_REGS - 2)

/* define size of auxiliary prime numbers for RSA  *
 *  (see FIPS 186-4 C3 tab.C3)                      */
#define PKA_RSA_KEY_1024_AUX_PRIME_SIZE_BITS 104 /* for P,Q size 1024 bit aux.size > 100 bits */
#define PKA_RSA_KEY_2048_AUX_PRIME_SIZE_BITS 144 /* for P,Q size 2048 bit aux.size > 140 bits */
#define PKA_RSA_KEY_3072_AUX_PRIME_SIZE_BITS 176 /* for P,Q size 3072 bit aux.size > 170 bits */

#define PKA_RSA_AUX_PRIME_BUFF_SIZE_IN_32BIT_WORDS 8 /* max size of temp buffer for auxiliary prime */

/* define count of Miller-Rabin tests for P,Q and  auxiliary prime numbers *
 *  for RSA key generation (see FIPS 186-4 C3 tab.C3)                       */
#define PKA_RSA_KEY_1024_AUX_PRIME_RM_TST_COUNT 38
#define PKA_RSA_KEY_1024_PQ_PRIME_RM_TST_COUNT  7
#define PKA_RSA_KEY_2048_AUX_PRIME_RM_TST_COUNT 32
#define PKA_RSA_KEY_2048_PQ_PRIME_RM_TST_COUNT  4
#define PKA_RSA_KEY_3072_AUX_PRIME_RM_TST_COUNT 27
#define PKA_RSA_KEY_3072_PQ_PRIME_RM_TST_COUNT  3

/* define this flag to test RSA KG algorithm with predefined P,Q and p1,p2,   *
 *  q1,q2 random data                                                          */
// #define RSA_KG_NO_RND 1

/* *********************** Enums ****************************** */

/* *********************** Typedefs  ************************** */

/*  LLF RSA   key generation parameters structure */
typedef struct {
    uint32_t auxPrimesSizeInBits;
    uint32_t pqPrimesMilRabTestsCount;
    uint32_t auxPrimesMilRabTestsCount;
} LlfRsaKgParams_t;

/*
    The struct is used by llfRsaKgX931MillerRabinTest.
    Two modulus sizes buffers hold randon vecoorts - prime candidate,
    the 3td modulus size buffer used as temporary buffer by SaSi_RndGenerateWordsArrayInRange. Each of the first 3
   buffers need 2 additional words. For llfRsaKgX932FindPrim1 we need 3/2 modulus size buffers + CALC_PRIME_PRODUCT
   size; for llfRsaKgX932FindPrim2 we need additional CALC_PRIME_PRODUCT buffer so
   3*SaSi_RSA_MAXIMUM_MOD_BUFFER_SIZE_IN_WORDS is enough for all usage.
*/
typedef struct {
    uint32_t temp[SaSi_PKA_KGDATA_BUFF_SIZE_IN_WORDS]; // the same size as SaSi_RSAKGData_t.sasiRSAKGDataIntBuff
} LLF_pki_key_gen_db_t;

/* *********************** Structs  **************************** */
/* *********************** Public Variables ******************** */

/* *********************** Public Functions **************************** */

/*
 * @brief This function generates a key pair
 *
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in] PubKey_ptr - the public key database.
 * @param[in] PrivKey_ptr - the private key database.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in .
 */
SaSiError_t LLF_PKI_RSA_GenerateKeyPair(SaSi_RND_Context_t *rndContext_ptr, SaSiRSAPubKey_t *PubKey_ptr,
                                        SaSiRSAPrivKey_t *PrivKey_ptr, SaSi_RSAKGData_t *KeyGenData_ptr);

/* **************************************************************************************** */
/*
 * @brief This function is used to test a primality according to ANSI X9.42 standard.
 *
 *        The function calls the llfRsaKgPrimeTest function which performs said algorithm.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 * @param[in] P_ptr           - The pointer to the prime buff.
 * @param[in] sizeWords       - The prime size in words.
 * @param[in] rabinTestsCount - The count of Rabin-Miller tests repetition.
 * @param[in] isPrime         - The flag indicates primality:
 *                                  if is not prime - SASI_FALSE, otherwise - SASI_TRUE.
 * @param[in] TempBuff_ptr   - The temp buffer of minimum size:
 *                               - on HW platform  8*MaxModSizeWords,
 *                               - on SW platform  41*MaxModSizeWords.
 * @param[in] primeTestMode - primality testing mode (RSA or DH - defines how are performed some
 *            operations on temp buffers.
 */
SaSiError_t LLF_PKI_RSA_primeTestCall(SaSi_RND_Context_t *rndContext_ptr, uint32_t *P_ptr, int32_t sizeWords,
                                      int32_t rabinTestsCount, int8_t *isPrime_ptr, uint32_t *TempBuff_ptr,
                                      SaSi_RSA_DH_PrimeTestMode_t primeTestMode);
#ifdef __cplusplus
}
#endif

#endif
