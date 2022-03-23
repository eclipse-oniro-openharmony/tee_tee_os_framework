/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/*
 *  Object %name    : %
 *  State           :  %state%
 *  Creation date   :  24 Oct. 2007
 *  Last modified   :  %modify_time%
 */
/* * @file
 *  \brief This file contains functions for generation and checking of the
 *         Diffie-Hellman (DLP) domain and public key parameters
 *
 *  \version sasi_dh_kg.c#1:csrc:5
 *  \author R.Levin
 */

/* ************ Include Files ************** */
#include "ssi_pal_mem.h"
#include "sasi_rnd.h"
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "ssi_compiler.h"
#include "sasi_hash.h"
#include "pka.h"
#include "llf_rsa.h"
#include "llf_rsa_public.h"
#include "llf_rsa_private.h"
#include "sasi_dh_error.h"
#include "sasi_dh.h"
#include "sasi_dh_kg.h"
#include "sasi_rnd_error.h"
#include "sasi_fips_defs.h"

/* *********************** Defines ***************************** */

/* canceling the lint warning:
   Use of goto is deprecated */


/* *********************** Enums ******************************* */

/* *********************** macros ****************************** */

/* * @brief This macro is required to remove compilers warnings if the HASH or PKI is not supported */

/* ********************** Global data  ************************* */

/* ************ External functions prototypes  *************************** */

SaSiError_t SaSi_RndGenerateWordsArrayInRange(SaSi_RND_Context_t *rndContext_ptr, uint32_t rndSizeInBits,
                                              uint32_t *maxVect_ptr, uint32_t *rndVect_ptr, uint32_t *tmp_ptr);

/* *************************************************************************************** */
/* ***********************         Private Functions          **************************** */
/* *************************************************************************************** */

/* ***************************************************************************** */
/*
 *      The function adds value to the number N, presented as bytes array in the buffer,
 *      given by uint32_t pointer n_ptr, where MSbyte is a most left one.
 *
 *      Algorithm:
 *          n = (N + val) mod 2^(8*sizeBytes).
 *      Assumed: The array and its size are aligned to 32-bit words.
 *           val > 0.
 *
 * @author reuvenl (7/1/2012)
 *
 * @param n_ptr
 * @param sizeBytes
 * @param val - value to add
 *
 * @return carry from last addition
 */
static uint32_t DX_DH_KG_AddValueToMsbLsbBytesArray(uint32_t *arr_ptr, uint32_t val, uint32_t sizeBytes)
{
    int32_t i;
    uint32_t *ptr = (uint32_t *)arr_ptr;
    uint32_t tmp, curr;

    for (i = sizeBytes / SASI_32BIT_WORD_SIZE - 1; i >= 0; i--) {
#ifndef BIG__ENDIAN
        tmp = curr = SaSi_COMMON_REVERSE32(ptr[i]);
#else
        tmp = curr = ptr[i];
#endif
        tmp += val;

#ifndef BIG__ENDIAN
        ptr[i] = SaSi_COMMON_REVERSE32(tmp);
#else
        ptr[i]     = tmp;
#endif

        if (tmp < curr) {
            val = 1;
        } else {
            val = 0;
        }
    }

    return val; /* carry */
}

/* ***************************************************************************** */
/*
 * @brief This function returns the effective size in bits of the MSB bytes array.
 *
 *        Assumed, that MSB > 0 is stored in the most left cell in the array.
 *
 * @param[in] arr_ptr -  The counter buffer.
 * @param[in] sizeInBytes -  The counter size in bytes.
 *
 * @return result - The effective counters size in bits.
 */

static uint32_t DX_DH_KG_GetSizeInBitsOfMsbLsbBytesArray(uint8_t *arr_ptr, uint32_t sizeInBytes)
{
    /* FUNCTION LOCAL DECLERATIONS */

    /* loop variable */
    int32_t i;

    /* the effective size in bits */
    uint32_t sizeInBits = 8 * sizeInBytes;

    /* the effective MS byte */
    uint8_t msbVal = arr_ptr[0], mask = 0x80;

    /* FUNCTION LOGIC */

    /* adjusting the effective size in bits */
    for (i = 0; i < 8; i++) {
        /* if the MS bit is set exit the loop */
        if (msbVal & mask) {
            break;
        }

        sizeInBits--;

        mask >>= 1;
    }

    return sizeInBits;

} /* END OF  DX_DH_KG_GetSizeInBitsOfMsbLsbBytesArray */

/* * @brief The function finds prime number Q for key generation according to X9.42-2001.
 *
 *
 * @param[in]  rndContext_ptr      - Pointer to the RND context buffer.
 * @param[in]  QSizeBits          - The size of order of generator in bits. According to ANSI X9.42:
 *                                  m must be multiple of 32 bits and 160 <= m. According to ANSI X9.30-1:
 *                                  m = 160 bit. We allow using Q as multiplies of 32 in range 160 - 256 bits (see
 *                                  FIPS 186-4 Tab. C.1).
 * @param[in]  seedSizeBits      - The  seed size in bits. Requirements:
 *                                  seedSize >= orderQSize and seedSize <= MIN(modPSizeBytes,
 SaSi_DH_MAX_VALID_KEY_SIZE_VALUE_IN_BYTES - 4), (the last is required by our implementation).
 * @param[in]  generateSeed       - The  flag defining whether the seed to be generated (1) or not (0),
 * @param[out] Q_ptr              - The pointer to the order Q of generator. The buffer must be aligned to 4 bytes.
 *                                  Note: The order Q is set as Words array, where LSWord is left most.
 * @param[out] S_ptr              - The random seed used for generation of primes. The buffer must be aligned to 4
 bytes.
 *                                  Note: The seed is set in the buffer as BE bytes array.
 * @param[in]  TempBuff1_ptr      - The temp buffer of size not less than max modulus size, aligned to 4 bytes.
 * @param[in]  TempBuff2_ptr      - The temp buffer of size not less than max
 *                                  modulus size, aligned to 4 bytes.
 * @param[in]  TempBuff3_ptr      - The large temp buffer (aligned to 4 bytes) of size:
 *                                    - on HW platform not less than 8*SaSi_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS.
 *                                    - on SW platform not less than 41*SaSi_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS.
 *
 *   Note: The function is static, sizes of its input arrays (mod, ord, seed) are checked in
 *         caller functions and don't need to be chcked again.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a predefined error code.
 *
 *
 */
static SaSiError_t DX_DH_X942_FindPrimeQ(SaSi_RND_Context_t *rndContext_ptr, uint32_t QsizeBits, /* in */
                                         uint32_t seedSizeBits,                                  /* in */
                                         uint32_t generateSeed,                                  /* in */
                                         uint32_t *Q_ptr,                                        /* out */
                                         uint8_t *S_ptr,                                         /* out */
                                         uint32_t *TempBuff1_ptr,                                /* in */
                                         uint32_t *TempBuff2_ptr,                                /* in - large buffer */
                                         uint32_t *TempBuff3_ptr)                                /* in */
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error;

    /* size of order in 160-bit blocks: M1 */
    uint32_t M1;

    /* primality flag (if prime, then isPrime = 1, else 0 ) */
    int8_t isPrime;

    /* flag of first hash calculating */
    uint8_t isFirst = 1;

    /* HASH input and result pointers */
    uint32_t *hashDataIn1_ptr, *hashDataIn2_ptr;
    SaSi_HASH_Result_t *hashRes1_ptr, *hashRes2_ptr;

    /* current data pointer and sizes */
    uint8_t *current_ptr;

    /* order size in bytes and in words */
    uint32_t QsizeBytes;

    /* exact seed size in bits and in words */
    uint32_t seedSizeBytes, remainingSize;

    /* shift value (in bits) for adding counter to seed */
    uint32_t shift;
    uint8_t mask, mask1;

    /* loop counters */
    uint32_t i, j;
    uint32_t countMilRabTests;

    SaSi_RND_State_t *rndState_ptr;
    SaSiRndGenerateVectWorkFunc_t RndGenerateVectFunc;

    /* FUNCTION  LOGIC */

    Error = SaSi_OK;

    /* check parameters */
    if (rndContext_ptr == NULL)
        return SaSi_RND_CONTEXT_PTR_INVALID_ERROR;
    if (rndContext_ptr->rndGenerateVectFunc == NULL)
        return SaSi_RND_GEN_VECTOR_FUNC_ERROR;

    rndState_ptr        = &(rndContext_ptr->rndState);
    RndGenerateVectFunc = rndContext_ptr->rndGenerateVectFunc;

    /* Step 1. Check input parameters */
    /* ------------------------------- */

    /* check pointers: modP, generator and tempBuff. Note: other pointers may be NULL  */
    if (Q_ptr == NULL || S_ptr == NULL || TempBuff1_ptr == NULL || TempBuff2_ptr == NULL || TempBuff3_ptr == NULL) {
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
    }

    /* --------------------------------- */
    /*  Step 2.  Initializations         */
    /* --------------------------------- */

    /* order and seed sizes */
    QsizeBytes    = CALC_FULL_BYTES(QsizeBits);
    seedSizeBytes = CALC_FULL_BYTES(seedSizeBits);

    /* order size M1 in 160-bit blocks (rounded up) */
    M1 = (QsizeBits + SaSi_DH_SEED_MIN_SIZE_IN_BITS - 1) / SaSi_DH_SEED_MIN_SIZE_IN_BITS;

    /* if M1 > SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS / SaSi_DH_SEED_MIN_SIZE_IN_BITS,
     *  then return error. This checking is for preventing KW warnings   */
    if (SaSi_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS < M1 / SaSi_DH_SEED_MIN_SIZE_IN_BITS) {
        return SaSi_DH_INVALID_ORDER_SIZE_ERROR;
    }

    /* RL  seed size must allow adding counters for hashing without overflow of temp buffers: */
    /* we limit this size relating to max buffer */
    if (seedSizeBytes > (SaSi_DH_MAX_MOD_SIZE_IN_WORDS - 1) * sizeof(uint32_t))
        return SaSi_DH_INVALID_SEED_SIZE_ERROR;

    /* zeroing  Q buffer */
    SaSi_PalMemSetZero(Q_ptr, QsizeBytes);

    /* set HASH pointers to temp buffer */
    hashDataIn1_ptr = TempBuff1_ptr;
    hashDataIn2_ptr = TempBuff2_ptr;
    hashRes1_ptr    = (SaSi_HASH_Result_t *)TempBuff3_ptr;
    hashRes2_ptr    = hashRes1_ptr + 1;

    /* ------------------------------- */
    /* Step 3. Create random prime Q  */
    /* ------------------------------- */

    /* check size and copy seed S into HASH input buffers */
    if (generateSeed != 1) {
        if (seedSizeBits != DX_DH_KG_GetSizeInBitsOfMsbLsbBytesArray(S_ptr, seedSizeBytes))
            return SaSi_DH_INVALID_SEED_SIZE_ERROR;

        /* check that (seed + DH_MAX_HASH_COUNTER_VALUE) is less than
           2^seedSizeBits, i.e. prevent addition overflow in
           generation process */
        SaSi_PalMemCopy((uint8_t *)hashDataIn2_ptr, S_ptr, seedSizeBytes);
        if (DX_DH_KG_AddValueToMsbLsbBytesArray(hashDataIn2_ptr, DH_SEED_MAX_ADDING_VAL, seedSizeBytes) != 0)
            return SaSi_DH_PASSED_INVALID_SEED_ERROR;
    }

    /* shift value to bit position of MSbit of the seed  */
    shift = 8 * seedSizeBytes - seedSizeBits;
    mask  = 0xFF >> shift;
    mask1 = 0x80 >> shift;

    /* initialize isPrime, orderSizeInBlocks, and Q buffer */
    isPrime = SASI_FALSE;

    /* set count of M-R tests for Q sccording FIPS 186-4 C.3: Tab. C.1. */
    if (QsizeBits <= 160) {
        countMilRabTests = 19;
    } else if (QsizeBits <= 224) {
        countMilRabTests = 24;
    } else if (QsizeBits <= 256) {
        countMilRabTests = 27;
    } else {
        countMilRabTests = 28;
    }

    /* Step 3.1. Try Q candidates     */
    /* -------------------------------- */
    while (isPrime != SASI_TRUE) {
        uint32_t isSeedValid = 0;

        /* Step 3.1.1. Create random seed  S  */
        if (generateSeed == 1) {
            /* generation of random vector */
            while (isSeedValid == 0) {
                Error = RndGenerateVectFunc(rndState_ptr, (uint16_t)seedSizeBytes, S_ptr);

                if (Error != SaSi_OK) {
                    goto EndWithError;
                }

                /* Set the MS bit of S and provide exact size of seed in bits */
                S_ptr[0] = (S_ptr[0] & mask) | mask1;

                /* check that (seed + DH_MAX_HASH_COUNTER_VALUE) is less than
                   2^seedSizeBits, i.e. prevent addition overflow */
                SaSi_PalMemCopy((uint8_t *)hashDataIn2_ptr, S_ptr, seedSizeBytes);
                if (DX_DH_KG_AddValueToMsbLsbBytesArray(hashDataIn2_ptr, DH_SEED_MAX_ADDING_VAL, seedSizeBytes) == 0)
                    isSeedValid = 1;
            }

        } else if (isFirst == 0) {
            return SaSi_DH_PASSED_INVALID_SEED_ERROR;
        }

        /* copy seed into hashDataIn1/2 buffers */
        SaSi_PalMemCopy((uint8_t *)hashDataIn1_ptr, S_ptr, seedSizeBytes);
        SaSi_PalMemCopy((uint8_t *)hashDataIn2_ptr, S_ptr, seedSizeBytes);
        DX_DH_KG_AddValueToMsbLsbBytesArray(hashDataIn2_ptr, M1, seedSizeBytes);

        /* set current pointer and size for copying HASH results into *
         *  TempBuff3 as big endian bytes                  */
        current_ptr   = &((uint8_t *)Q_ptr)[QsizeBytes - SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES];
        remainingSize = QsizeBytes;

        /* Step 3.1.2. Create Q candidate:  For i=0 to M1 do:
        Q = Q + (SHA1(S+i) XOR SHA1(S+M1+i))*(2^(160*i)) */
        for (i = 0; i < M1; i++) {
            if (i != 0) {
                /* increment hashDataIn1 and hashDataIn2 by 1 *
                 *  starting from second cycle             */
                DX_DH_KG_AddValueToMsbLsbBytesArray(hashDataIn1_ptr, 1, seedSizeBytes);
                DX_DH_KG_AddValueToMsbLsbBytesArray(hashDataIn2_ptr, 1, seedSizeBytes);
            }

            /* calculate first HASH result */
            Error = SaSi_HASH_MTK(SaSi_HASH_SHA1_mode, (uint8_t *)hashDataIn1_ptr, seedSizeBytes, *hashRes1_ptr);

            if (Error != SaSi_OK) {
                goto EndWithError;
            }

            /* calculate  second HASH result */
            Error = SaSi_HASH_MTK(SaSi_HASH_SHA1_mode, (uint8_t *)hashDataIn2_ptr, seedSizeBytes, *hashRes2_ptr);

            if (Error != SaSi_OK) {
                goto EndWithError;
            }

            /* XOR HASH results */
            for (j = 0; j < SaSi_HASH_SHA1_DIGEST_SIZE_IN_WORDS; j++) {
                (*hashRes1_ptr)[j] ^= (*hashRes2_ptr)[j];
            }

            /* copying HASH results into Q buffer */
            if (remainingSize >= SaSi_DH_SEED_MIN_SIZE_IN_BYTES) {
                SaSi_PalMemCopy(current_ptr, hashRes1_ptr, SaSi_DH_SEED_MIN_SIZE_IN_BYTES);
                remainingSize -= SaSi_DH_SEED_MIN_SIZE_IN_BYTES;
                current_ptr -= SaSi_DH_SEED_MIN_SIZE_IN_BYTES;
            } else { /* copy remaining low bytes to Q_ptr */
                SaSi_PalMemCopy((uint8_t *)Q_ptr,
                                (uint8_t *)hashRes1_ptr + SaSi_DH_SEED_MIN_SIZE_IN_BYTES - remainingSize,
                                remainingSize);
            }

            /* set flag */
            isFirst = 0;

        } /* end of for() loop */

        /* set the High and Low bits of Q equal to 1 */
        ((uint8_t *)Q_ptr)[0] |= 0x80;              /* MS bit - big endian */
        ((uint8_t *)Q_ptr)[QsizeBytes - 1] |= 0x01; /* LS bit - big endian */

        /* Step 3.2. Perform primality tests on Q: 8 Miller-Rabin and 1 Lucas tests (X9.42-2001) */
        /* --------------------------------------------------------------------------------------- */

        /* convert Q to words */
        Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(Q_ptr, QsizeBytes, (uint8_t *)Q_ptr, QsizeBytes);
        if (Error) {
            goto EndWithError;
        }

        Error = LLF_PKI_RSA_primeTestCall(rndContext_ptr, Q_ptr, QsizeBytes / SASI_32BIT_WORD_SIZE, countMilRabTests,
                                          &isPrime, TempBuff2_ptr, SaSi_DH_PRIME_TEST_MODE);

        if (Error != SaSi_OK) {
            goto EndWithError;
        }

    } /* END of while() loop */

    /* End of function */

    return Error;

EndWithError:

    SaSi_PalMemSetZero((uint8_t *)Q_ptr, QsizeBytes);
    SaSi_PalMemSetZero((uint8_t *)S_ptr, seedSizeBytes);

    return Error;

} /* End of DX_DH_X942_FindPrimeQ */

/* *************************************************************************************** */
/*
 * @brief The function finds prime modulus P for key generation according to X9.42-2001.
 *
 * @param[in]  rndContext_ptr      - Pointer to the RND context buffer.
 * @param[in]  modPSizeBits       - The  modulus (prime) P size in bits equal 256*n, where n >= 4.
 * @param[in]  QSizeBbytes        - The size of order of generator in bytes. Must be m >= 20 bytes and
 *                                  multiple of 4 bytes. According to ANSI X9.30-1: size = 20.
 * @param[in]  orderQSizeBits     - The size of order of generator in bits. Must be m >= 160 and
 *                                  multiple of 32 bits. According to ANSI X9.30-1: m = 160.
 * @param[in]  seedSizeBits       - The  seed size in bits (the size must be:  seedSizeBits >= 160,
 *                                  seedSizeBits <= modPSizeBits - 1 (the last required by implementation).
 * @param[out] P_ptr              - The prime modulus P of structure P = j*Q + 1, where Q is prime
 *                                  and j is an integer.The buffer must be aligned to 4 bytes.
 * @param[out] Q_ptr              - The pointer to the order Q of generator. The buffer must be aligned to 4 bytes.
 * @param[out] S_ptr              - The random seed used for generation of primes. The buffer must be aligned to 4
 * bytes.
 * @param[out] pgenCounter_ptr    - The pointer to counter of tries to generate the primes.
 * @param[in]  TempBuff1_ptr      - The temp buffer of size not less than max modulus size, aligned to 4 bytes.
 * @param[in]  TempBuff2_ptr      - The large temp buffer of size:
 *                                - on HW platform not less than 8*SaSi_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS.
 *                                - on SW platform not less than 41*SaSi_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS.
 * @param[in]  TempBuff3_ptr      - The temp buffer of size: 2*SaSi_DH_MAX_MOD_BUFFER_SIZE_IN_WORDS.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a predefined error code.
 *
 *   Note: The function is static, therefore sizes of its input arrays (mod, ord, seed) are checked in
 *         caller functions and don't need to be chcked again.
 *
 */
static SaSiError_t DX_DH_X942_FindPrimeP(SaSi_RND_Context_t *rndContext_ptr, uint32_t modPsizeBits, /* in */
                                         uint32_t orderQsizeBits,                                   /* in */
                                         uint32_t seedSizeBits,                                     /* in */
                                         uint32_t *P_ptr,                                           /* out */
                                         uint32_t *Q_ptr,                                           /* out */
                                         uint8_t *S_ptr,                                            /* out */
                                         uint32_t *pgenCounter_ptr,                                 /* out */
                                         uint32_t *TempBuff1_ptr,                                   /* in */
                                         uint32_t *TempBuff2_ptr,       /* in - large buffer */
                                         uint32_t *TempBuff_ptr) /* in */ // RL used in SW only
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error;

    /* mod size in bytes and in words */
    uint32_t modSizeBytes, modSizeWords;

    /* seed size in bytes and words */
    uint32_t seedSizeBytes;

    /* mod size in 160 bits blocks (rounded up) */
    uint32_t L1;

    /* order sizes: M1 - in 160-bit blocks (rounded up) */
    uint32_t orderSizeWords, M1;

    /* flag of first hash calculating */
    uint8_t isFirst = 1;

    /* primality flag (if prime, then isPrime = 1, else 0 ) */
    uint8_t isPrime;

    /* HASH input and result pointers */
    uint32_t *hashDataIn_ptr;
    SaSi_HASH_Result_t *hashRes_ptr;

    /* current data pointer and size */
    uint8_t *current_ptr;
    int32_t remainingSize;

    SaSi_COMMON_CmpCounter_t cmpRes;

    /* loop counter and carry */
    uint32_t i, carry;

    /* temp buffers pointers */
    uint32_t *TempBuff3_ptr, *TempBuff4_ptr, *TempBuff5_ptr;
    uint32_t countMilRabTests;

    /* FUNCTION  LOGIC */

    Error = SaSi_OK;

    /* --------------------------------- */
    /* Step 1. Check input parameters    */
    /* ---------------------------------- */

    /* check pointers: modP, generator and tempBuff. Note: other pointers may be NULL  */
    if (P_ptr == NULL || Q_ptr == NULL || S_ptr == NULL || pgenCounter_ptr == NULL || TempBuff1_ptr == NULL ||
        TempBuff2_ptr == NULL || TempBuff_ptr == NULL) {
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
    }

    /* --------------------------------- */
    /*  Step 2.  Initializations         */
    /* --------------------------------- */

    /* mod sizes in bytes */
    modSizeBytes = CALC_FULL_BYTES(modPsizeBits);
    modSizeWords = CALC_FULL_32BIT_WORDS(modPsizeBits);
    /* mod size in 160 bit blocks */
    L1 = (modPsizeBits + SaSi_DH_SEED_MIN_SIZE_IN_BITS - 1) / SaSi_DH_SEED_MIN_SIZE_IN_BITS;

    /* order size: M1 - in 160-bit blocks (rounded up) */
    M1             = (orderQsizeBits + SaSi_DH_SEED_MIN_SIZE_IN_BITS - 1) / SaSi_DH_SEED_MIN_SIZE_IN_BITS;
    orderSizeWords = CALC_FULL_32BIT_WORDS(orderQsizeBits);

    /* seedSize in bytes */
    seedSizeBytes = CALC_FULL_BYTES(seedSizeBits);

    /* zeroing of P  */
    SaSi_PalMemSetZero(P_ptr, modSizeBytes + 2);

    /* temp buffers pointers */
    TempBuff3_ptr = TempBuff2_ptr + modSizeWords + 2;
    TempBuff4_ptr = TempBuff3_ptr + 2 * modSizeWords + 2;
    TempBuff5_ptr = TempBuff4_ptr + 2 * modSizeWords + 2;

    /* ------------------------------------------------------ */
    /* Step 3.   Create random prime P = (Q*J + 1)           */
    /* ------------------------------------------------------ */

    /* set pgenCounter 0 */
    *pgenCounter_ptr = 0;

    /* set HASH pointers to temp buffer */
    hashDataIn_ptr = TempBuff1_ptr;
    hashRes_ptr    = (SaSi_HASH_Result_t *)TempBuff4_ptr; /* used as temp buffer */

    /* Calculating R = seed + 2*M1 , where R is set in hashDataIn:
      copy the seed into hashDataIn_ptr (big endian);
      set other bytes to 0; add M1 */

    SaSi_PalMemCopy((uint8_t *)hashDataIn_ptr, S_ptr, seedSizeBytes);
    DX_DH_KG_AddValueToMsbLsbBytesArray(hashDataIn_ptr, 2 * M1, seedSizeBytes);

    /* set count of M-R tests for Q sccording FIPS 186-4 C.3: Tab. C.1. */
    if (modPsizeBits < 3072) {
        countMilRabTests = 3;
    } else {
        countMilRabTests = 2;
    }

    isPrime = SASI_FALSE;

    /* Step 3.1. Main loop - try P candidates */
    /* ---------------------------------------- */
    while (isPrime != SASI_TRUE) {
        /* Step 3.1. Create P candidate:
        For i=0 to L1 do:  P = P + SHA1(R+i) *(2^(160*i)) */

        /* set current pointer and size for copying HASH results into *
         *  mod P as big endian bytes               */
        current_ptr   = &((uint8_t *)P_ptr)[modSizeBytes - SaSi_DH_SEED_MIN_SIZE_IN_BYTES];
        remainingSize = modSizeBytes;

        for (i = 0; i < L1; i++) {
            /* Adding 1 to hashDataIn excluding the first hashing operation */
            if (isFirst != 1) {
                DX_DH_KG_AddValueToMsbLsbBytesArray(hashDataIn_ptr, 1, seedSizeBytes);
            }

            /* set 0 to isFirst */
            isFirst = 0;

            /* calculate HASH result */
            Error = SaSi_HASH_MTK(SaSi_HASH_SHA1_mode, (uint8_t *)hashDataIn_ptr, seedSizeBytes, *hashRes_ptr);

            if (Error != SaSi_OK) {
                goto EndWithError;
            }

            /* set size for copying HASH result into P buffer */
            if (remainingSize >= SaSi_DH_SEED_MIN_SIZE_IN_BYTES) {
                SaSi_PalMemCopy(current_ptr, hashRes_ptr, SaSi_DH_SEED_MIN_SIZE_IN_BYTES);
                remainingSize -= SaSi_DH_SEED_MIN_SIZE_IN_BYTES;
                current_ptr -= SaSi_DH_SEED_MIN_SIZE_IN_BYTES;
            } else {
                SaSi_PalMemCopy((uint8_t *)P_ptr,
                                (uint8_t *)hashRes_ptr + SaSi_DH_SEED_MIN_SIZE_IN_BYTES - remainingSize, remainingSize);
            }

        } /* end of j - loop */

        /* ----------------------------------------------------------------------- */

        /* convert P to LSW array */
        Error = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(P_ptr, modSizeWords * 4, (uint8_t *)P_ptr, modSizeBytes);
        if (Error) {
            return Error;
        }

        /* ---------------------------------------- */
        /* Step 3.2. Set P = P - (P mod 2*Q) + 1  */
        /* Note: Now all operations on LSW arrays */
        /* ---------------------------------------- */

        /* set the High and Low bits of Q equal to 1 */
        P_ptr[modSizeWords - 1] |= 0x80000000; /* MS bit */

        /* set TempBuff3 = 2*Q. Note: Result size is large by 1 byte (and word), than Q size */
        carry = SaSi_COMMON_Add2vectors(Q_ptr, Q_ptr, orderSizeWords, TempBuff3_ptr);

        /* if carry occurs, set next word of TempBuff3 to 1, else to 0 */
        if (carry != 0) {
            TempBuff3_ptr[orderSizeWords] = 1;
        } else {
            TempBuff3_ptr[orderSizeWords] = 0;
        }

        /* calculate TempBuff4 = P mod 2*Q */
        SaSi_PalMemSetZero((uint8_t *)TempBuff4_ptr, modSizeBytes);

        Error = LLF_PKI_RSA_Call_Div(P_ptr,              /* numerator P */
                                     modSizeWords,       /* P_size in words */
                                     TempBuff3_ptr,      /* divider */
                                     orderSizeWords + 1, /* divider_size in words */
                                     TempBuff4_ptr,      /* ModRes_ptr */
                                     TempBuff2_ptr,      /* DivRes_ptr */
                                     TempBuff5_ptr /* TempBuff_ptr - 2*N_size */);
        if (Error) {
            return Error;
        }

        /* subtract: P = P - TempBuff4 */
        SaSi_COMMON_SubtractUintArrays(P_ptr, TempBuff4_ptr, modSizeWords, P_ptr);

        /* add 1 to P */
        SaSi_COMMON_IncLsbUnsignedCounter(P_ptr, 1, (uint8_t)modSizeWords);

        /* check: if P > 2^(L-1), then perform step 3.3. */
        /* ----------------------------------------------- */

        /*  set TempBuff5 = 2^(L-1): Note: L = modPsizeBits is        *
         *   multiple of 32 bits                       */
        SaSi_PalMemSetZero((uint8_t *)TempBuff4_ptr, modSizeBytes);
        TempBuff4_ptr[modSizeWords - 1] = 0x80000000;

        /* compare */
        cmpRes = SaSi_COMMON_CmpLsWordsUnsignedCounters(P_ptr, (uint16_t)modSizeWords, TempBuff4_ptr,
                                                        (uint16_t)modSizeWords);

        /* Step 3.3. If P is not diverted, then perform primality               *
         *  tests on P: 8 Rabin-Miller and 1 Lucas tests (X9.42-2001)           *
         * ---------------------------------------------------------------------- */

        if (cmpRes == SaSi_COMMON_CmpCounter1GraterThenCounter2) {
            Error = LLF_PKI_RSA_primeTestCall(rndContext_ptr, P_ptr, modSizeWords, countMilRabTests, (int8_t *)&isPrime,
                                              TempBuff2_ptr, SaSi_DH_PRIME_TEST_MODE);
            if (Error != SaSi_OK) {
                goto EndWithError;
            }
        }

        /* RL defines: 4096 -> PGEN_COUNTER_MAX_VAL,  L = 1024 -> PRIME_MOD_MIN_VAL */
        /* update pgenCounter_ptr */
        *pgenCounter_ptr += 1;

        /* if pgenCounter >= 4096*N then return "generation is fail" */
        if (*pgenCounter_ptr >=
            DH_X942_PGEN_COUNTER_CONST * (modPsizeBits + DH_X942_PRIME_MOD_MIN_VAL - 1) / DH_X942_PRIME_MOD_MIN_VAL) {
            Error = SaSi_DH_PRIME_P_GENERATION_FAILURE_ERROR;
            goto EndWithError;
        }

    } /* END of while(isPrime != SASI_TRUE) */

    /* correction of pgenCounter */
    *pgenCounter_ptr -= 1;

    /* End of function */
    return Error;

EndWithError:

    SaSi_PalMemSetZero(P_ptr, modSizeBytes);

    return Error;

} /* End of DX_DH_X942_FindPrimeP */

/* *************************************************************************************** */
/*
 * @brief The function creates generator of GF(P) subgroup for key generation according to X9.42-2001.
 *
 *
 * @param[in]  rndContext_ptr      - Pointer to the RND context buffer.
 * @param[out] P_ptr              - The prime modulus P of structure P = j*Q + 1, where Q is prime
 *                                  and j is an integer.The buffer must be aligned to 4 bytes.
 * @param[in]  modPSizeBits       - The  modulus (prime) P size in bytes must be multiple of 4 bytes.
 * @param[out] Q_ptr              - The pointer to the order Q of generator. The buffer must be aligned to 4 bytes.
 * @param[in]  orderSizeBits      - The size of order of generator in bytes. Must be multiple of 4 bytes.
 * @param[out] G_ptr              - The generator of GF(P) subgroup. The buffer must be aligned to 4 bytes.
 *                                  size of buffer not less than modPSize in bytes.
 * @param[in]  tempBuff1_ptr      - The temp buffer of size not less than DH max modulus size, aligned to 4 bytes.
 * @param[in]  expTempBuff_ptr    - The temp buffer of defined structure.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a predefined error code.
 *
 *
 */
static SaSiError_t DX_DH_X942_CreateGenerator(SaSi_RND_Context_t *rndContext_ptr, uint32_t *P_ptr, /* in */
                                              uint32_t modSizeBits,                                /* in */
                                              uint32_t *Q_ptr,                                     /* in */
                                              uint32_t orderSizeBits,                              /* in */
                                              uint32_t *G_ptr,                                     /* out */
                                              uint32_t *tempBuff1_ptr,                             /* in */
                                              SaSi_DH_ExpTemp_t *expTempBuff_ptr)                  /* in */
{
    /* FUNCTION DECLARATIONS */

    // RL  J-factor is used in other functions
    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* modulus and order sizes in words */
    uint32_t modSizeBytes, modSizeWords, orderSizeBytes;

    uint32_t J_effectiveSizeBits;

    /* compare flag */
    SaSi_COMMON_CmpCounter_t compFlag;

    /* INITIALIZATIONS */

    modSizeBytes   = CALC_FULL_BYTES(modSizeBits);
    modSizeWords   = CALC_FULL_32BIT_WORDS(modSizeBits);
    orderSizeBytes = CALC_FULL_BYTES(orderSizeBits);

    /* FUNCTION  LOGIC */

    /* ------------------------------------- */
    /* Step 1. Calculate J = (P - 1)/Q     */
    /* ------------------------------------- */

    /*  copy modulus into TempBuff1  */
    SaSi_PalMemCopy((uint8_t *)expTempBuff_ptr->PubKey.n, (uint8_t *)P_ptr, modSizeBytes);
    SaSi_PalMemSetZero((uint8_t *)expTempBuff_ptr->PubKey.n + modSizeBytes,
                       SaSi_DH_MAX_MOD_SIZE_IN_BYTES - modSizeBytes);
    /* copy order Q into aligned buffer */
    SaSi_PalMemCopy((uint8_t *)expTempBuff_ptr->TempBuff, (uint8_t *)Q_ptr, orderSizeBytes);
    SaSi_PalMemSetZero((uint8_t *)expTempBuff_ptr->TempBuff + orderSizeBytes,
                       SaSi_DH_MAX_MOD_SIZE_IN_BYTES - orderSizeBytes);

    /* subtract: P - 1 */
    SaSi_COMMON_DecrLsbUnsignedCounter(expTempBuff_ptr->PubKey.n, 1, modSizeWords);

    /* divide (P - 1)/Q */
    LLF_PKI_RSA_Call_Div(
        expTempBuff_ptr->PubKey.n,                   /* numerator B */
        modSizeWords,                                /* B_size in words */
        expTempBuff_ptr->TempBuff,                   /* Q - divider */
        CALC_32BIT_WORDS_FROM_BYTES(orderSizeBytes), /* Q_size in words */
        expTempBuff_ptr->PubKey.e,                   /* ModRes_ptr */
        tempBuff1_ptr,                               /* DivRes_ptr */
        expTempBuff_ptr->PrimeData.DataIn); /* TempBuff_ptr: len=2*modSize (using also PrimeData_ptr->DataOut buff) */

    /* calculate actual size of J in bits: Use min() to prevent warnings  */
    J_effectiveSizeBits =
        SaSi_MIN(modSizeBits, SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(tempBuff1_ptr, modSizeWords));

    /* --------------------------------------------------------------- */
    /* Step 2. Generate random G : 1 < G < (P-1)  and                */
    /*         set it into DataIn buffer, other bytes of buffer = 0  */
    /* --------------------------------------------------------------- */
    /* cleaning of temp buffer */
    SaSi_PalMemSetZero((uint8_t *)&expTempBuff_ptr->PrimeData, sizeof(SaSi_DHPrimeData_t));

    /* generating rnd vector */

    Error = SaSi_RndGenerateWordsArrayInRange(rndContext_ptr, modSizeBits, expTempBuff_ptr->PubKey.n /* P-1 */,
                                              expTempBuff_ptr->PrimeData.DataIn /* RND */,
                                              expTempBuff_ptr->PrimeData.DataOut /* temp */);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* ---------------------------------------------------- */
    /* Step 3. Initialization of PubKey and PrivData      */
    /*         structures for exponentiation              */
    /* ---------------------------------------------------- */

    /* cleaning of temp buffer */
    SaSi_PalMemSetZero((uint8_t *)&expTempBuff_ptr->PubKey, sizeof(expTempBuff_ptr->PubKey));

    /* set modulus in DH_PubKey structure for exponentiation G^J mod P */
    SaSi_PalMemCopy((uint8_t *)expTempBuff_ptr->PubKey.n, (uint8_t *)P_ptr, modSizeBytes);
    expTempBuff_ptr->PubKey.nSizeInBits = modSizeBits;
    /* set exponent J and its size */
    SaSi_PalMemCopy((uint8_t *)expTempBuff_ptr->PubKey.e, (uint8_t *)tempBuff1_ptr,
                    CALC_FULL_BYTES(J_effectiveSizeBits));
    expTempBuff_ptr->PubKey.eSizeInBits = J_effectiveSizeBits;

    /*  initialize the H value in LLF of PubKey for exponentiation  */
    Error = LLF_PKI_RSA_InitPubKeyDb(&expTempBuff_ptr->PubKey);
    if (Error != SaSi_OK) {
        goto End;
    }

    /* ----------------------------------------------------------- */
    /* Step 4. Calculate G = G ^ J mod P , if G == 1, change     */
    /*         G (DataIn) and repeat exponentiation              */
    /* ----------------------------------------------------------- */

    compFlag = SaSi_COMMON_CmpCounter1AndCounter2AreIdentical; /* 0 - means G == 1 */
    /* set 1 to tempBuff1_ptr for comparing */                 // RL
    SaSi_PalMemSetZero((uint8_t *)tempBuff1_ptr, modSizeBytes);
    tempBuff1_ptr[0] = 1;

    while (compFlag == 0) {
        /* exponentiation DataOut = DataIn ^ Exp mod P */
        Error = LLF_PKI_RSA_ExecPubKeyExp(&expTempBuff_ptr->PubKey, &expTempBuff_ptr->PrimeData);

        if (Error != SaSi_OK) {
            return Error;
        }

        /* compare DataOut to 1: */
        compFlag = SaSi_COMMON_CmpLsWordsUnsignedCounters(expTempBuff_ptr->PrimeData.DataOut, modSizeWords,
                                                          tempBuff1_ptr, modSizeWords);

        /* if G == 1 change DataIn (by adding 1) for trying next G value */
        if (compFlag == 0) {
            SaSi_COMMON_IncLsbUnsignedCounter(expTempBuff_ptr->PrimeData.DataIn, 1, (uint8_t)modSizeWords);
        }
    }

    /* copy generator into output */
    SaSi_PalMemCopy((uint8_t *)G_ptr, (uint8_t *)expTempBuff_ptr->PrimeData.DataOut, modSizeBytes);

/* End of function */
End:
    return Error;

} /* End of DX_DH_X942_CreateGenerator */

/* *************************************************************************************** */
/*
 * @brief The function generates a DH (DLP) domain parameters in GF(P) (see X9.42-2001)
 *
 *   The function parameters are the same as in SaSi_DH_CreateDomainParams() function (see below)
 *   besides one difference: this function not checks input parameters, because it is also used locally
 *   in some other functions with input pointers = NULL.
 *
 *   Note: The function is static, therefore sizes of its input arrays (mod, ord, seed) are checked in
 *         caller functions and don't need to be chcked again.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure - a predefined error code.
 *
 */
static SaSiError_t DX_DH_CreateDomainParams(SaSi_RND_Context_t *rndContext_ptr, uint32_t modPsizeBits, /* in */
                                            uint32_t orderQsizeBits,                                   /* in */
                                            uint32_t seedSizeBits,                                     /* in */
                                            uint8_t *modP_ptr,                                         /* out */
                                            uint8_t *orderQ_ptr,                                       /* out */
                                            uint8_t *generatorG_ptr,                                   /* out */
                                            uint32_t *generGsizeBytes_ptr,                             /* in/out */
                                            uint8_t *factorJ_ptr,                                      /* out */
                                            uint32_t *JsizeBytes_ptr,                                  /* in/out */
                                            uint8_t *seedS_ptr,                                        /* in/out */
                                            int8_t generateSeed,                                       /* in */
                                            uint32_t *pgenCounter_ptr,                                 /* out */
                                            SaSi_DHKGData_t *DHKGbuff_ptr /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* pointers to temp buffers for candidates to order Q, modulus P, seed S, generator G */
    uint32_t *Q_ptr, *P_ptr, *G_ptr, *J_ptr;
    uint8_t *S_ptr;

    /* tries counter */
    uint32_t pgenCounter;

    uint32_t modSizeBytes, generatorSizeBits;

    /* temp buffer pointers */
    uint32_t *TempBuff1_ptr, *TempBuff2_ptr;

    /* --------------------------------- */
    /*  Step 2.  Initializations         */
    /* --------------------------------- */

    /* clean DHKGbuff_ptr */
    SaSi_PalMemSetZero(DHKGbuff_ptr, sizeof(SaSi_DHKGData_t));

    /* set Q, S and G- pointers on DHKGbuff_ptr->PrimData temp buffers */
    Q_ptr = DHKGbuff_ptr->TempBuff2;
    P_ptr = DHKGbuff_ptr->TempBuff3;
    G_ptr = DHKGbuff_ptr->TempBuff4;
    J_ptr = DHKGbuff_ptr->TempBuff5;
    S_ptr = (uint8_t *)J_ptr;

    /* set 32-bit temp pointers on KGData and PrimData temp buffers */
    TempBuff1_ptr = DHKGbuff_ptr->TempBuff1;
    TempBuff2_ptr = (uint32_t *)&(DHKGbuff_ptr->ExpTemps);

    if (generateSeed == 0) {
        SaSi_PalMemCopy((uint8_t *)S_ptr, seedS_ptr, CALC_FULL_BYTES(seedSizeBits));
    }

    modSizeBytes = CALC_FULL_BYTES(modPsizeBits);

    /* ------------------------------------------------------------------- */
    /* Step 1. Find random prime Q and its Seed S according to ANSI X9.42 */
    /* ------------------------------------------------------------------- */

    Error = DX_DH_X942_FindPrimeQ(rndContext_ptr, orderQsizeBits, /* in */
                                  seedSizeBits,                   /* in */
                                  generateSeed,                   /* in */
                                  Q_ptr,                          /* out */
                                  S_ptr,                          /* in/out */
                                  TempBuff1_ptr,                  /* in */
                                  TempBuff2_ptr,                  /* in */
                                  DHKGbuff_ptr->TempBuff6);       /* in */
    if (Error != SaSi_OK) {
        goto EndWithError;
    }

    /* ------------------------------------------------------ */
    /* Step 2.   Create random prime P = (Q*J + 1)           */
    /* ------------------------------------------------------ */

    Error = DX_DH_X942_FindPrimeP(rndContext_ptr, modPsizeBits, /* in */
                                  orderQsizeBits,               /* in */
                                  seedSizeBits,                 /* in */
                                  P_ptr,                        /* out */
                                  Q_ptr,                        /* out */
                                  S_ptr,                        /* in */
                                  &pgenCounter,                 /* out */
                                  TempBuff1_ptr,                /* in */
                                  TempBuff2_ptr,                /* in */
                                  DHKGbuff_ptr->TempBuff6);     /* in */

    if (Error != SaSi_OK) {
        goto EndWithError;
    }

    /* ------------------------------------------------------ */
    /* Step 3.   Create generator of GF(P) subgroup          */
    /* ------------------------------------------------------ */
    if (generatorG_ptr != NULL) {
        Error = DX_DH_X942_CreateGenerator(rndContext_ptr, P_ptr, /* in */
                                           modPsizeBits,          /* in */
                                           Q_ptr,                 /* in */
                                           orderQsizeBits,        /* in */
                                           G_ptr,                 /* out */
                                           TempBuff1_ptr,         /* in */
                                           (SaSi_DH_ExpTemp_t *)&DHKGbuff_ptr->ExpTemps /* in */);

        if (Error != SaSi_OK) {
            goto EndWithError;
        }

        /* calculate size of generator and output it in big endianness */
        generatorSizeBits =
            SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(G_ptr, (uint16_t)modSizeBytes / SASI_32BIT_WORD_SIZE);
        *generGsizeBytes_ptr = CALC_FULL_BYTES(generatorSizeBits);

        Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(generatorG_ptr, *generGsizeBytes_ptr, G_ptr,
                                                            *generGsizeBytes_ptr);
        if (Error != SaSi_OK) {
            goto EndWithError;
        }
    }

    /* output of result parameters (in big endianness) */
    Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(modP_ptr, modSizeBytes, P_ptr, modSizeBytes);
    if (Error != SaSi_OK) {
        goto EndWithError;
    }

    if (orderQ_ptr != NULL) {
        Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(orderQ_ptr, CALC_FULL_BYTES(orderQsizeBits), Q_ptr,
                                                            CALC_FULL_BYTES(orderQsizeBits));
        if (Error != SaSi_OK) {
            goto EndWithError;
        }
    }

    /* copy generated seed into output */
    if (generateSeed == 1) {
        SaSi_PalMemCopy(seedS_ptr, (uint8_t *)S_ptr, CALC_FULL_BYTES(seedSizeBits));
    }

    /* if factorJ_ptr != NULL, then calculate this factor and its size. J = (P-1) / Q */

    // RL Use J-factor from previous function
    if (factorJ_ptr != NULL) {
        LLF_PKI_RSA_Call_Div(P_ptr,                                 /* numerator B */
                             CALC_FULL_32BIT_WORDS(modPsizeBits),   /* B_size in words */
                             Q_ptr,                                 /* divider N */
                             CALC_FULL_32BIT_WORDS(orderQsizeBits), /* N_size in words */
                             TempBuff1_ptr,                         /* ModRes_ptr */
                             J_ptr,                                 /* DivRes_ptr */
                             TempBuff2_ptr);                        /* TempBuff_ptr (size >= 2*N_Size) */

        /* calculate size of J in bits */
        *JsizeBytes_ptr =
            SaSi_COMMON_GetWordsCounterEffectiveSizeInBits(J_ptr, (uint16_t)modSizeBytes / SASI_32BIT_WORD_SIZE);

        /* calculate size of J in bytes */
        *JsizeBytes_ptr = CALC_FULL_BYTES(*JsizeBytes_ptr);

        /* convert result to MSB bytes and output into factorJ_ptr buffer */
        Error = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(factorJ_ptr, *JsizeBytes_ptr, J_ptr, *JsizeBytes_ptr);
        if (Error != SaSi_OK) {
            goto EndWithError;
        }
    }

    /*  if pgenCounter_ptr != NULL put out pgenCounter */
    if (pgenCounter_ptr != NULL) {
        *pgenCounter_ptr = pgenCounter;
    }

    goto End;

    /* End of function */

EndWithError:

    /* cleaning output buffers used also in internal computations */
    SaSi_PalMemSetZero(modP_ptr, CALC_FULL_BYTES(modPsizeBits));

    if (generatorG_ptr != NULL) {
        SaSi_PalMemSetZero(generatorG_ptr, *generGsizeBytes_ptr);
    }

    if (orderQ_ptr != NULL) {
        SaSi_PalMemSetZero(orderQ_ptr, CALC_FULL_BYTES(orderQsizeBits));
    }

    if (factorJ_ptr != NULL) {
        SaSi_PalMemSetZero(factorJ_ptr, *JsizeBytes_ptr);
    }

    if (generateSeed == 1) {
        SaSi_PalMemSetZero(seedS_ptr, CALC_FULL_BYTES(seedSizeBits));
    }

End:
    /* cleaning of temp buffer */
    SaSi_PalMemSetZero(DHKGbuff_ptr, sizeof(SaSi_DHKGData_t));

    return Error;

} /* End of DX_DH_CreateDomainParams */

/* *************************************************************************************** */
/* ***********************         Public Functions           **************************** */
/* *************************************************************************************** */

/* *************************************************************************************** */
/*
* @brief The function generates a DH (DLP) domain parameters in GF(P) (see X9.42-2001)
*
*
* @param [in]  rndContext_ptr      - Pointer to the RND context buffer.
* @param [in]  modPSizeBits       - Size of the modulus (Prime) in bits equal 256*n, where n >= 4. FIPS 186-4
*                                   defines 1024 and 2048 bit.
* @param [in]  orderQSizeBits     - Size of the Generator's order in bits. FIPS 186-4 defines orderQSizeBits = 160
*                                   for modulus 1024 bit and 224 or 256 bit for modPSizeBits = 2048. We not recommend
                                    orderQSizeBits > 256 and returns an error if it > modPSizeBits/4 .
* @param [in]  seedSizeBits       - The  seed size in bits. Requirements:
*                                  seedSizeBits >= orderQSizeBits and seedSizeBits <= modPSizeBits ( the
*                                  last is required by our implementation).
* @param [out] modP_ptr           - The prime modulus P of structure P = J*Q + 1, where Q is prime
*                                  and j is an integer. Size of the buffer for output generated value must
*                                  be not less, than modulus size.
* @param [out] orderQ_ptr         - The pointer to the order Q of generator. The size of the buffer for output
*                                  generated value must be not less, than order size.
* @param [out] generatorG_ptr     - The pointer to the generator of multiplicative subgroup in GF(P).
*                                  If the pointer == NULL, the function returns an error. Size of the buffer
*                                for output generated value must be not less, than modulus size.
* @param [in/out]generGsizeBytes_ptr - The pointer to the one-word buffer, containing the generator size value (in
bytes).
*                                  The user must set the size of allocated buffer, and the function returns the
*                                actual size of the generator in bytes.
* @param [out] factorJ_ptr        - The pointer to buffer for integer factor J. If the pointer == NULL, the function
*                                  not puts this parameter out. In this case JsizeBytes_ptr must be set to NULL,
*                                  otherwise the function returns an error. The size of the buffer must be not less,
*                                  than ( modPSizesBytes - orderQSizeBytes + 1 ).
* @param [in/out] JsizeBytes_ptr  - The pointer to the size of integer factor J. If the pointer == NULL,
*                                  the function not puts this parameter out. If output of the factor J is needed, the
*                                  user must set the J size value equal to the size of allocated buffer, and the
*                                  function returns the actual size of J in bytes.
* @param [in/out] seedS_ptr       - The random seed used for generation of primes. The size of the buffer for output
*                              generated value must be not less, than passed seed size (see above) and not less
*                              20 bytes (160 bits).
* @param [in] generateSeed        - The flag, defining whether the seed generated randomly by the function
*                                  (generateSeed = 1), or it is passed by the input (generateSeed = 0).
* @param [out] pgenCounter_ptr    - The pointer to counter of tries to generate the primes. If the pointer == NULL,
*                                  the function not puts this parameter out.
* @param [out] DHKGBuff_ptr       - The temp buffer for internal calculations. The buffer is defined as structure.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure - a predefined error code.
 *
*     Note:  1. Input and Output vectors are in big endianness (high most bit is left most one).
*            2. For reliability of checking of input parameters, in case that the user don't wont output of
*               some parameters (generator or factorJ), he must set both - a pointer to appropriate buffer and a
*               pointer to its size equaled to NULL for these parameters, otherwise the function returns an error.
 *            2. In case of any error the function may clean the output buffers.
 *
 */
CEXPORT_C SaSiError_t SaSi_DH_CreateDomainParams(SaSi_RND_Context_t *rndContext_ptr, uint32_t modPsizeBits, /* in */
                                                 uint32_t orderQsizeBits,                                   /* in */
                                                 uint32_t seedSizeBits,                                     /* in */
                                                 uint8_t *modP_ptr,                                         /* out */
                                                 uint8_t *orderQ_ptr,                                       /* out */
                                                 uint8_t *generatorG_ptr,                                   /* out */
                                                 uint32_t *generGsizeBytes_ptr,                             /* in/out */
                                                 uint8_t *factorJ_ptr,                                      /* out */
                                                 uint32_t *JsizeBytes_ptr,                                  /* in/out */
                                                 uint8_t *seedS_ptr,                                        /* in/out */
                                                 int8_t generateSeed,                                       /* in */
                                                 uint32_t *pgenCounter_ptr,                                 /* out */
                                                 SaSi_DHKGData_t *DHKGbuff_ptr /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    uint32_t modSizeBytes, orderSizeBytes;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check pointers: modP, orderQ and temp buffer. Note: other pointers may be NULL, if not used  */
    if (modP_ptr == NULL || orderQ_ptr == NULL || seedS_ptr == NULL || DHKGbuff_ptr == NULL) {
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
    }
    /* check sizes */
    if (modPsizeBits < SaSi_DH_MIN_VALID_KEY_SIZE_VALUE_IN_BITS || /* check sizes */
        modPsizeBits % 256 != 0 || modPsizeBits > SaSi_DH_MAX_VALID_KEY_SIZE_VALUE_IN_BITS) {
        return SaSi_DH_INVALID_MODULUS_SIZE_ERROR;
    }

    /* init the sizes */
    modSizeBytes   = CALC_FULL_BYTES(modPsizeBits);
    orderSizeBytes = CALC_FULL_BYTES(orderQsizeBits);

    if (orderQsizeBits < SaSi_DH_SEED_MIN_SIZE_IN_BITS || orderQsizeBits > modPsizeBits / 4 ||
        orderQsizeBits % SASI_BITS_IN_32BIT_WORD != 0) {
        return SaSi_DH_INVALID_ORDER_SIZE_ERROR;
    }

    if (seedSizeBits < orderQsizeBits /* according to X9.42-2001 */ ||
        seedSizeBits > modPsizeBits /* our limitation of buffer size */) {
        return SaSi_DH_INVALID_SEED_SIZE_ERROR;
    }

    /* check generator G pointers and buffer size */
    if ((generatorG_ptr == NULL) || (generGsizeBytes_ptr == NULL) || (*generGsizeBytes_ptr < modSizeBytes)) {
        return SaSi_DH_INVALID_GENERATOR_PTR_OR_SIZE_ERROR;
    }

    /* check J-factor pointers and buffer size */
    if ((factorJ_ptr == NULL && JsizeBytes_ptr != NULL) || (factorJ_ptr != NULL && JsizeBytes_ptr == NULL) ||
        ((JsizeBytes_ptr != NULL) && (*JsizeBytes_ptr < (modSizeBytes - orderSizeBytes + 1)))) {
        return SaSi_DH_INVALID_J_FACTOR_PTR_OR_SIZE_ERROR;
    }

    /* check generateSeed parameter */
    if (generateSeed != 0 && generateSeed != 1) {
        return SaSi_DH_INVALID_ARGUMENT_OPERATION_MODE_ERROR;
    }

    /*   call exec function */
    Error = DX_DH_CreateDomainParams(rndContext_ptr, modPsizeBits, /* in */
                                     orderQsizeBits,               /* in */
                                     seedSizeBits,                 /* in */
                                     modP_ptr,                     /* out */
                                     orderQ_ptr,                   /* out */
                                     generatorG_ptr,               /* out */
                                     generGsizeBytes_ptr,          /* in/out */
                                     factorJ_ptr,                  /* out */
                                     JsizeBytes_ptr,               /* in/out */
                                     seedS_ptr,                    /* in/out */
                                     generateSeed,                 /* in */
                                     pgenCounter_ptr,              /* out */
                                     DHKGbuff_ptr);                /* in */

    return Error;
} /* End of SaSi_DH_CreateDomainParams */

/* *************************************************************************************** */
/*
 * @brief The function checks the obtained DH domain parameters according X9.42-2001.
 *
 *        There may be 3 case of checking:
 *        1. Checking of primes only ( modulus P and order Q according to passed seed S and pgenCounter).
 *           In this case all pointers and sizes of said parameters must be passed (not NULL), but generator
 *           G pointer and it size must be both set to NULL.
 *        2. Checking of generator G only in assuming that primes parameters P, Q are valid. In ths case
 *           the user must to pass the P,Q,G pointers and sizes. The seed S pointer and size must be both
 *           set to NULL, otherwise the function returns an error.
 *        3. Checking all domain parameters. In this case all input parameters must be passed to the function.
 *
 *        If any of checked domain parameters is not compliant to X9.42-2001 standard and our implementation
 *        limitation, the function returns an error according to sasi_dh_error.h file.
 *
 *        NOTE:  Detailed requirements to all used parameters are described above in SaSi_DH_CreateDomainParams
 *               functions API.
 *
 * @param[in]  rndContext_ptr     - Pointer to the RND context buffer.
 * @param[out] modP_ptr           - The prime modulus P. Must be of structure P = j*Q + 1,
 *                                  where Q is prime and j is an integer.
 * @param[in]  modPSizeBits       - The  modulus (prime) P size in bits equal 256*n, where n >= 4.
 * @param[out] orderQ_ptr         - The pointer to the order Q of generator.
 * @param[in]  orderQSizeBytes    - The size of order of generator in bytes. According to ANSI X9.43:
 *                                  m must be multiple of 32 bits and m >= 160. According to ANSI X9.30-1:
 *                                  m = 160 bit. In our implementation required, that orderQSize <= modPSizeBytes/4.
 * @param[in]  generatorG_ptr     - The pointer to the generator of multiplicative subgroup in GF(P).
 * @param[in]  generatorSizeBytes - The size of generator in bytes (must be set if generator will be checked).
 * @param[in]  seedS_ptr          - The random seed used for generation of primes (must be set if
 *                                  primes will be checked).
 * @param[in]  seedSizeBits       - The seed size in bits. If the seed is used,
 *                      then its size must be:
 *                      seedSizeBits >= orderQSizeBits and
 *                      seedSizeBits <= modPSizeBits ( the last is
 *                      required by our implementation).
 * @param[in]  pgenCounter        - The counter of tries to generate the primes (must be set if primes
 *                                  will be checked).
 * @param[in] TempBuff_ptr        - The temp buffer of defined structure.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure or if one or more domain
 *                       parameters are invalid the function returns a predefined error code.
 *
 *     Note:  Input vectors are in big endianness.
 *
 */
CEXPORT_C SaSiError_t SaSi_DH_CheckDomainParams(SaSi_RND_Context_t *rndContext_ptr, uint8_t *modP_ptr, /* in */
                                                uint32_t modPsizeBytes,                                /* in */
                                                uint8_t *orderQ_ptr,                                   /* in */
                                                uint32_t orderQsizeBytes,                              /* in */
                                                uint8_t *generatorG_ptr,                               /* in */
                                                uint32_t generatorSizeBytes,                           /* in */
                                                uint8_t *seedS_ptr,                                    /* in */
                                                uint32_t seedSizeBits,                                 /* in */
                                                uint32_t pgenCounter,                                  /* in */
                                                SaSi_DHKG_CheckTemp_t *checkTempBuff_ptr /* in */)
{
    /* FUNCTION DECLARATIONS */

    /* The return error identifier */
    SaSiError_t Error = SaSi_OK;

    /* pointers to temp buffers */
    uint32_t *Q_ptr, *P_ptr;
    SaSi_DHKGData_t *DHKGbuff_ptr;
    uint32_t *TempBuff_ptr;

    /* size of modulus in bits and in words */
    uint32_t modPsizeBits, modPsizeWords;

    /* size  order Q (in bits) */
    uint32_t orderQsizeBits;

    /* counter of trying to generate modulus P; pgenCounter */
    uint32_t pgenCounter1;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check pointers: modP, generator and tempBuff. Note: other pointers may be NULL  */
    if (modP_ptr == NULL || orderQ_ptr == NULL || checkTempBuff_ptr == NULL) {
        return SaSi_DH_INVALID_ARGUMENT_POINTER_ERROR;
    }

    /* check modulus and order sizes */
    if (modPsizeBytes < SaSi_DH_MIN_VALID_KEY_SIZE_VALUE_IN_BITS / 8 || modPsizeBytes % SASI_BITS_IN_32BIT_WORD != 0 ||
        modPsizeBytes > SaSi_DH_MAX_MOD_SIZE_IN_BYTES) {
        return SaSi_DH_INVALID_MODULUS_SIZE_ERROR;
    }

    if (orderQsizeBytes < SaSi_DH_SEED_MIN_SIZE_IN_BITS / 8 || orderQsizeBytes % SASI_32BIT_WORD_SIZE != 0 ||
        orderQsizeBytes > modPsizeBytes / 4) {
        return SaSi_DH_INVALID_ORDER_SIZE_ERROR;
    }

    /* Seed pointer and size checking:
       If pointer or size of seed are illegal, then output an error.
       Note: In case that primes checking is not needed, the seed pointer and size must be
                 set to NULL  and are legal */
    if ((seedSizeBits == 0 && seedS_ptr != NULL) || (seedSizeBits != 0 && seedS_ptr == NULL)) {
        return SaSi_DH_CHECK_SEED_SIZE_OR_PTR_NOT_VALID_ERROR;
    }

    /* Generator pointer and size checking:
       If pointer or size of generator are illegal, then output an error.
       Note: In case that generator checking is not needed, its pointer and size are equaled to NULL */
    if ((generatorSizeBytes == 0 && generatorG_ptr != NULL) || (generatorSizeBytes != 0 && generatorG_ptr == NULL)) {
        return SaSi_DH_CHECK_GENERATOR_SIZE_OR_PTR_NOT_VALID_ERROR;
    }

    /* --------------------------------- */
    /*  Step 2.  Initializations         */
    /* --------------------------------- */

    DHKGbuff_ptr = &checkTempBuff_ptr->DhKgBuff;
    TempBuff_ptr = (uint32_t *)&checkTempBuff_ptr->CheckTempBuff;

    /* clean TempBuff_ptr */
    SaSi_PalMemSetZero(checkTempBuff_ptr, sizeof(SaSi_DHKG_CheckTemp_t));

    /* calculate P and Q size in bits */
    modPsizeWords = CALC_32BIT_WORDS_FROM_BYTES(modPsizeBytes);

    /* set Q, P and G- pointers on DHKGbuff_ptr->PrimData temp buffers */
    Q_ptr = TempBuff_ptr;
    P_ptr = Q_ptr + modPsizeWords;

    if (seedS_ptr != NULL) {
        /* --------------------------------------------- */
        /* Step 3. Calculate and check primes sizes     */
        /* --------------------------------------------- */

        /* temporary convert P and Q to little endian bytes arrays  *
         *  for calculating their sizes in bits                  */
        SaSi_COMMON_ReverseMemcpy((uint8_t *)P_ptr, modP_ptr, modPsizeBytes);
        SaSi_COMMON_ReverseMemcpy((uint8_t *)Q_ptr, orderQ_ptr, orderQsizeBytes);

        modPsizeBits =
            SaSi_MIN(8 * modPsizeBytes,
                     SaSi_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)P_ptr, (uint16_t)modPsizeBytes));
        orderQsizeBits =
            SaSi_MIN(8 * orderQsizeBytes,
                     SaSi_COMMON_GetBytesCounterEffectiveSizeInBits((uint8_t *)Q_ptr, (uint16_t)orderQsizeBytes));

        /* ------------------------------------------------------------------- */
        /* Step 4. Generate random primes P,Q for given seed Seed S according */
        /*         to ANSI X9.42 for comparing with input parameters          */
        /*         The called CreateDomainParams also checks sizes of input   */
        /*         parameters                                                 */
        /* ------------------------------------------------------------------- */

        Error = DX_DH_CreateDomainParams(rndContext_ptr, modPsizeBits, /* in */
                                         orderQsizeBits,               /* in */
                                         seedSizeBits,                 /* in */
                                         (uint8_t *)P_ptr,             /* out */
                                         (uint8_t *)Q_ptr,             /* out */
                                         NULL /* generatorG_ptr */,      /* out */
                                         NULL /* generatorSize_ptr */,   /* out */
                                         NULL /* factorJ_ptr */,         /* out */
                                         NULL /* JsizeBytes_ptr */,      /* out */
                                         seedS_ptr,                    /* in/out */
                                         SASI_FALSE /* generateSeed */,  /* in */
                                         &pgenCounter1,                /* out */
                                         DHKGbuff_ptr);                /* in */

        if (Error != SaSi_OK) {
            goto End;
        }

        /* ------------------------------------------------------------------- */
        /* Step 5. Compare generated primes with input, if one of compares   */
        /*         is not "equal", the output error                          */
        /* ------------------------------------------------------------------- */

        if (SaSi_PalMemCmp(modP_ptr, (uint8_t *)P_ptr, modPsizeBytes) != 0) {
            Error = SaSi_DH_CHECK_DOMAIN_PRIMES_NOT_VALID_ERROR;
            goto End;
        }

        else if (SaSi_PalMemCmp(orderQ_ptr, (uint8_t *)Q_ptr, orderQsizeBytes) != 0) {
            Error = SaSi_DH_CHECK_DOMAIN_PRIMES_NOT_VALID_ERROR;
            goto End;
        }

        /* compare pgen counters */
        else if (pgenCounter != pgenCounter1) {
            Error = SaSi_DH_CHECK_DOMAIN_PRIMES_NOT_VALID_ERROR;
            goto End;
        }
    }

    /* ----------------------------------------------------------------- */
    /* Step 4. Check generator using the function for checking of      */
    /*    the public key because both perform identical operations     */
    /*    with appropriate parameters. In this case:                   */
    /*    if G > P-2, or G < 2, or G^Q != 1, then output an error      */
    /* ----------------------------------------------------------------- */

    if (generatorG_ptr != NULL) {
        Error = SaSi_DH_CheckPubKey(modP_ptr,                 /* in */
                                    modPsizeBytes,            /* in */
                                    orderQ_ptr,               /* in */
                                    orderQsizeBytes,          /* in */
                                    generatorG_ptr,           /* in */
                                    generatorSizeBytes,       /* in */
                                    &DHKGbuff_ptr->ExpTemps); /* in */

        /* Set error code according to checked parameter issue */
        if (Error == SaSi_DH_INVALID_PUBLIC_KEY_SIZE_ERROR || Error == SaSi_DH_INVALID_PUBLIC_KEY_ERROR) {
            Error = SaSi_DH_CHECK_GENERATOR_NOT_VALID_ERROR;
        }
    }

End:
    /* cleaning of temp buffers */
    SaSi_PalMemSetZero(&DHKGbuff_ptr->ExpTemps, sizeof(DHKGbuff_ptr->ExpTemps));

    /* End of function */

    return Error;
}
