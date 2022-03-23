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

#ifndef _CC_RND_H
#define _CC_RND_H

#include "cc_error.h"
#include "cc_aes.h"

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief This file contains the CryptoCell APIs used for random number generation.
The random-number generation module implements referenced standard NIST Special Publication 800-90A: Recommendation for Random Number
Generation Using Deterministic Random Bit Generators.
*/

/************************ Defines ******************************/

/*!  Maximal reseed counter - indicates maximal number of
requests allowed between reseeds; according to NIST 800-90
it is (2^48 - 1), our restriction is :  (0xFFFFFFFF - 0xF).*/
#define CC_RND_MAX_RESEED_COUNTER 	(0xFFFFFFFF - 0xF)

/* maximal requested size counter (12 bits active) - maximal count
of generated random 128 bit blocks allowed per one request of
Generate function according NIST 800-90 it is (2^12 - 1) = 0x3FFFF */
/* Max size for one RNG generation (in bits) =
  max_num_of_bits_per_request = 2^19 (FIPS 800-90 Tab.3) */
#define CC_RND_MAX_GEN_VECTOR_SIZE_BITS       0x7FFFF
/* Max size of generated random vector in bytes according to CC_RND_Generate function */
#define CC_RND_MAX_GEN_VECTOR_SIZE_BYTES    0xFFFF
#define CC_RND_REQUESTED_SIZE_COUNTER  0x3FFFF

/*! AES output block size in words. */
#define CC_RND_AES_BLOCK_SIZE_IN_WORDS  CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS


/* RND seed and additional input sizes */
#define CC_RND_SEED_MAX_SIZE_WORDS                  12
#ifndef CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS
#define CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS	CC_RND_SEED_MAX_SIZE_WORDS
#endif


/* allowed sizes of AES Key, in words */
#define CC_RND_AES_KEY_128_SIZE_WORDS  4
#define CC_RND_AES_KEY_192_SIZE_WORDS  6
#define CC_RND_AES_KEY_256_SIZE_WORDS  8

/*   Definitions of temp buffer for RND_DMA  */
/*******************************************************************/
/*   Definitions of temp buffer for DMA  */

#define CC_RND_WORK_BUFFER_SIZE_WORDS 1528

/*! A definition for RAM buffer to be internally used in instantiation (or reseeding) operation. */
typedef struct
{
	/* include the specific fields that are used by the low level */
	uint32_t ccRndIntWorkBuff[CC_RND_WORK_BUFFER_SIZE_WORDS];
}CCRndWorkBuff_t;

#define CCRndEntropyEstimatData_t  CCRndWorkBuff_t

/* RND source buffer inner (entrpopy) offset       */
#define CC_RND_TRNG_SRC_INNER_OFFSET_WORDS    2
#define CC_RND_TRNG_SRC_INNER_OFFSET_BYTES    (CC_RND_TRNG_SRC_INNER_OFFSET_WORDS*sizeof(uint32_t))

/* Size of the expected output buffer used by FIPS KAT */
#define CC_PRNG_FIPS_KAT_OUT_DATA_SIZE      64

/* Size of additional random bits for generation
   random number in range: according to FIPS 186-3, B.4.1 */
#define CC_RND_FIPS_ADDIT_BITS_FOR_RND_IN_RANGE   64
#define CC_RND_FIPS_ADDIT_BYTES_FOR_RND_IN_RANGE  (CC_RND_FIPS_ADDIT_BITS_FOR_RND_IN_RANGE>>3)


/************************ Enumerators  ****************************/

/* Definition of SWEE or FE mode of random generator (TRNG)*/
typedef  enum
{
	CC_RND_SWEE  = 0, /* sw entopry estimation */
	CC_RND_FE  = 1,   /* hw entropy estimation (either 80090B or full) */
	CC_RND_ModeLast = 0x7FFFFFFF,
} CCRndMode_t;


/************************ Structs  *****************************/


/* The internal state of DRBG mechanism based on AES CTR and CBC-MAC
   algorithms. It is set as global data defined by the following
   structure  */
typedef  struct
{
	/* Seed buffer, consists from concatenated Key||V: max size 12 words */
	uint32_t  Seed[CC_RND_SEED_MAX_SIZE_WORDS];
	/* Previous value for continuous test */
	uint32_t  PreviousRandValue[CC_AES_CRYPTO_BLOCK_SIZE_IN_WORDS];

	/* AdditionalInput buffer max size = seed max size words + 4w for padding*/
	uint32_t  PreviousAdditionalInput[CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS+5];
	uint32_t  AdditionalInput[CC_RND_ADDITINAL_INPUT_MAX_SIZE_WORDS+4];
	uint32_t  AddInputSizeWords; /* size of additional data set by user, words   */

	/* entropy source size in words */
	uint32_t  EntropySourceSizeWords;

	/* reseed counter (32 bits active) - indicates number of requests for entropy
	since instantiation or reseeding */
	uint32_t  ReseedCounter;

	/* key size: 4 or 8 words according to security strength 128 bits or 256 bits*/
	uint32_t KeySizeWords;

	/* State flag (see definition of StateFlag above), containing bit-fields, defining:
	- b'0: instantiation steps:   0 - not done, 1 - done;
	- 2b'9,8: working or testing mode: 0 - working, 1 - KAT DRBG test, 2 -
	  KAT TRNG test;
	b'16: flag defining is Previous random valid or not:
	        0 - not valid, 1 - valid */
	uint32_t StateFlag;

	/* Trng processing flag - indicates which ROSC lengths are:
	-  allowed (bits 0-3);
	-  total started (bits 8-11);
	-  processed (bits 16-19);
	-  started, but not processed (bits24-27)              */
	uint32_t TrngProcesState;

	/* validation tag */
	uint32_t ValidTag;

	/* Rnd source entropy size in bits */
	uint32_t  EntropySizeBits;

} CCRndState_t;


/*! The RND Generate vector function pointer type definition.
   The prototype intendent for External and CryptoCell internal RND functions
   pointers definitions.
   Full description can be found in ::CC_RndGenerateVector function API. */
typedef uint32_t (*CCRndGenerateVectWorkFunc_t)(        \
				CCRndState_t  *rndState_ptr, /*context*/   \
				size_t            outSizeBytes,   /*in*/      \
				uint8_t           *out_ptr         /*out*/);


/*! definition of RND context that includes CryptoCell RND state structure and a function pointer for rnd generate function */
typedef  struct
{
        /* The pointer to internal state of RND */
       CCRndState_t   rndState;

       /* The pointer to user given function for generation random vector */
       CCRndGenerateVectWorkFunc_t rndGenerateVectFunc;
} CCRndContext_t;


/*! Required for internal FIPS verification for PRNG KAT. */
typedef  struct
{
       CCRndWorkBuff_t      rndWorkBuff;
       uint8_t                  rndOutputBuff[CC_PRNG_FIPS_KAT_OUT_DATA_SIZE];
} CCPrngFipsKatCtx_t;


/*****************************************************************************/
/**********************        Public Functions      *************************/
/*****************************************************************************/

/*!
@brief This function initializes the RND context.
It must be called at least once prior to using this context with any API that requires it as a parameter (e.g., other RND APIs, asymmetric
cryptography key generation and signatures).
It is called as part of ARM TrustZone CryptoCell library initialization, which initializes and returns the primary RND context.
This primary context can be used as a single global context for all RND needs.
Alternatively, other contexts may be initialized and used with a more limited scope (for specific applications or specific threads).
The call to this function must be followed by a call to ::CC_RndSetGenerateVectorFunc API to set the generate vector function.
It implements referenced standard section 10.2.1.3.2 - CTR-DRBG of NIST Special Publication 800-90A: Recommendation for Random Number Generation Using Deterministic Random Bit Generators, instantiate algorithm using AES (197FIPS Publication 197: AES Advanced Encryption Standard) and Derivation Function (DF)).
\note Additional data can be mixed with the random seed (personalization data or nonce). If required, this data should be provided by calling ::CC_RndAddAdditionalInput prior to using this API.

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndInstantiation(
                        CCRndContext_t   *rndContext_ptr,       /*!< [in/out]  Pointer to the RND context buffer allocated by the user, which is used to
										   maintain the RND state, as well as pointers to the functions used for
										   random vector generation. This context must be saved and provided as a
										   parameter to any API that uses the RND module.
										   \note the context must be cleared before sent to the function. */
                        CCRndWorkBuff_t  *rndWorkBuff_ptr       /*!< [in/out] Scratchpad for the RND module's work. */
);


/*!
@brief Clears existing RNG instantiation state.

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndUnInstantiation(
                        CCRndContext_t *rndContext_ptr       /*!< [in/out] Pointer to the RND context buffer. */
);


/*!
@brief This function is used for reseeding the RNG with additional entropy and additional user-provided input.
(additional data should be provided by calling ::CC_RndAddAdditionalInput prior to using this API).
It implements section - 10.2.1.4.2 - CTR-DRBG of NIST Special Publication 800-90A: Recommendation for Random Number Generation
Using Deterministic Random Bit Generators Reseeding algorithm, using AES (FIPS Publication 197: AES Advanced Encryption Standard)
and Derivation Function (DF).

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndReseeding(
                        CCRndContext_t   *rndContext_ptr,      /*!< [in/out] Pointer to the RND context buffer. */
                        CCRndWorkBuff_t  *rndWorkBuff_ptr      /*!< [in/out] Scratchpad for the RND module's work. */
);


/****************************************************************************************/
/*!
@brief Generates a random vector according to the algorithm defined in section 10.2.1.5.2 - CTR-DRBG of NIST Special Publication
800-90A: Recommendation for Random Number Generation Using Deterministic Random Bit Generators.
The generation algorithm uses AES (FIPS Publication 197: AES Advanced Encryption Standard and Derivation Function (DF).

\note The RND module must be instantiated prior to invocation of this API. \par
\note Reseeding operation must be performed prior to vector generation if prediction resistance is required. \par
\note Reseeding operation must be performed prior to vector generation if the function returns
CC_RND_RESEED_COUNTER_OVERFLOW_ERROR, stating that the Reseed Counter has passed its upper-limit (2^32-2).

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndGenerateVector(
                            CCRndState_t *rndState_ptr,     /*!< [in/out] Pointer to the RND state structure, which is part of the RND context structure.
								     Use rndContext->rndState field of the context for this parameter. */
                            size_t    outSizeBytes,             /*!< [in]  The size in bytes of the random vector required. The maximal size is 2^16 -1 bytes. */
                            uint8_t   *out_ptr                  /*!< [out] The pointer to output buffer. */
);


/****************************************************************************************/
/*!

@brief This function sets the RND vector generation function into the RND context.

It must be called after ::CC_RndInstantiation, and prior to any other API that requires the RND context as parameter.
It is called as part of ARM TrustZone CryptoCell library initialization, to set the RND vector generation function into the primary RND context,
after ::CC_RndInstantiation is called.

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CCError_t CC_RndSetGenerateVectorFunc(
                    CCRndContext_t *rndContext_ptr,                     /*!< [in/out] Pointer to the RND context buffer allocated by the user,
											  which is used to maintain the RND state as well as pointers
											  to the functions used for random vector generation. */
                    CCRndGenerateVectWorkFunc_t rndGenerateVectFunc       /*!< [in] Pointer to the random vector generation function.
										      The pointer should point to the ::CC_RndGenerateVector function. */
);


/**********************************************************************************************************/
/*!
@brief Generates a random vector with specific limitations by testing candidates (described and used in FIPS Publication 186-4: Digital
Signature Standard (DSS): B.1.2, B.4.2 etc.).

This function draws a random vector, compare it to the range limits, and if within range - return it in rndVect_ptr.
If outside the range, the function continues retrying until a conforming vector is found, or the maximal retries limit is exceeded.
If maxVect_ptr is provided, rndSizeInBits specifies its size, and the output vector must conform to the range [1 < rndVect < maxVect_ptr].
If maxVect_ptr is NULL, rndSizeInBits specifies the exact required vector size, and the output vector must be the exact same
bit size (with its most significant bit = 1).
\note The RND module must be instantiated prior to invocation of this API.

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndGenerateVectorInRange(
                    CCRndContext_t *rndContext_ptr,     /*!< [in/out] Pointer to the RND context buffer. */
                    size_t   rndSizeInBits,                 /*!< [in]  The size in bits of the random vector required. The allowed size in range  2 <= rndSizeInBits < 2^19-1, bits. */
                    uint8_t  *maxVect_ptr,                  /*!< [in]  Pointer to the vector defining the upper limit for the random vector output, Given as little-endian byte array.
                                                                       If not NULL, its actual size is treated as [(rndSizeInBits+7)/8] bytes. */
                    uint8_t  *rndVect_ptr                   /*!< [in/out] Pointer to the output buffer for the random vector. Must be at least [(rndSizeInBits+7)/8] bytes.
                                                                 Treated as little-endian byte array. */
);


/*************************************************************************************/
/*!
@brief Used for adding additional input/personalization data provided by the user,
to be later used by the ::CC_RndInstantiation/::CC_RndReseeding/::CC_RndGenerateVector functions.

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndAddAdditionalInput(
                            CCRndContext_t *rndContext_ptr,     /*!< [in/out] Pointer to the RND context buffer. */
                            uint8_t *additonalInput_ptr,            /*!< [in]  The Additional Input buffer. */
                            size_t  additonalInputSize              /*!< [in]  The size of the Additional Input buffer (in bytes). Must be <= 48, and a multiple of 4. */
);

/*!
@brief The CC_RndEnterKatMode function sets KAT mode bit into StateFlag of global CCRndContext_t structure.

The user must call this function before calling functions performing KAT tests.

\note Total size of entropy and nonce must be not great than CC_RND_ENTROPY_TEMP_BUFFER_MAX_SIZE_WORDS.

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C CCError_t CC_RndEnterKatMode(
            CCRndContext_t *rndContext_ptr,     /*!< [in/out] Pointer to the RND context buffer. */
            uint8_t            *entrData_ptr,       /*!< [in] Entropy data. */
            size_t             entrSize,           /*!< [in] Entropy size in bytes. */
            uint8_t            *nonce_ptr,          /*!< [in] Nonce. */
            size_t             nonceSize,          /*!< [in] Entropy size in bytes. */
            CCRndWorkBuff_t  *workBuff_ptr      /*!< [out] RND working buffer, must be the same buffer, which should be passed into
							Instantiation/Reseeding functions. */
);

/**********************************************************************************************************/
/*!
@brief The CC_RndDisableKatMode function disables KAT mode bit into StateFlag of global CCRndContext_t structure.

The user must call this function after KAT tests before actual using RND module (Instantiation etc.).

@return CC_OK on success.
@return A non-zero value from cc_rnd_error.h on failure.
*/
CIMPORT_C void CC_RndDisableKatMode(
                    CCRndContext_t   *rndContext_ptr     /*!< [in/out] Pointer to the RND context buffer. */
);


#ifdef __cplusplus
}
#endif

#endif /* #ifndef _CC_RND_H */

