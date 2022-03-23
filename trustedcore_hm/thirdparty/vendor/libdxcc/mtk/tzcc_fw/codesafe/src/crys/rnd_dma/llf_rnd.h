/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef LLF_RND_H
#define LLF_RND_H

#include "sasi_rnd_local.h"

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* Definitions describing the TRNG Entropy estimator parameters:
width of bits prefix and correlation table size */
#define SaSi_RND_nb        8
#define SaSi_RND_NB        (1 << SaSi_RND_nb)
#define H_BUFF_SIZE_WORDS  SaSi_RND_NB
#define EC_BUFF_SIZE_WORDS (SaSi_RND_NB / 2)

/* Macro defining Multiplication  using 16x16 multiplier  */
#define Mult16x16(a, b) (((a)&0xffff) * ((b)&0xffff))
uint64_t Mult32x32(uint32_t a, uint32_t b);
uint64_t Mult48x16(uint64_t a, uint32_t b);

/* *********************** Enums ****************************** */
/* *********************** Typedefs  ************************** */
/* *********************** Structs  *************************** */
/* structure containing parameters and buffers for entropy estimator */
typedef struct {
    /* estimated entropy size */
    uint32_t EstimEntropySizeBits;
    /* estimated error of entropy size */
    uint32_t EstimEntropySizeErrorInBits;

    /* special buffers */
    uint32_t h[SaSi_RND_NB];      /* histogram */
    uint32_t ec[SaSi_RND_NB / 2]; /* equality counter for prefix */

} LLF_rnd_entr_estim_db_t;

/* ******************* Public Functions *********************** */

/*
 * @brief The LLF_RND_GetRngBytes returns size of random source needed for collection
 *        required entropy .
 *
 *        The function returns size of source needed for required entropy.
 *
 * @param[in/out] trngParams - The pointer to structure, containing TRNG parameters.
 * @entropySizeWords[in/out] - The pointer to size of random source. The user sets
 *                    size of entropy that is required and the function returns
 *                    the actual size of source needed for this count of entropy.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
SaSiError_t LLF_RND_GetEntropySourceSize(SaSi_RND_Params_t *trngParams,   /* in */
                                         uint16_t *entropySizeWords_ptr); /* in/out */

/* ************************************************************************************* */
/*
 * @brief The function gets user provided parameters of RNG HW.
 *
 *   This implementation is in user competence. Temporary a pseudo function
 *   is implemented for testing goals. To use this implementation the user must define
 *   compilation flag "DX_RND_TEST_MODE", otherwise
 *
 *   Note: In temporary implementation assumed, that users parameters are placed
 *         in global structure UserRngParameters (now placed in ATP tests).
 *
 * @param[in] KeySizeWords - The key size: 4 or 8 words according to security
 *                           strength 128 bits or 256 bits;
 * @param[in] TrngMode -  TRNG mode: 0 - SWEE mode, 1 - FE mode.
 * @param[in] RoscsAllowed - Ring oscillator length level: should be set
 *            as 2 bits value: 0,1,2,3.
 * @param[in] SampleCount - The sampling count - count of RND blocks of RNG HW
 *            output, required for needed entropy accumulation:
 *              - in "FE" mode a possible values are 4095 to 65535, in steps of 4096;
 *              - in "SWEE" mode, sampling counter limit is set to a low value -
 *                typically 1 or 2.
 * @param[in] MaxTrngTimeCoeff - coefficient defining relation between maximal allowed and expected
 *                  time for random generation (in percents).
 *
 * @return SaSiError_t - SaSi_OK
 */
SaSiError_t LLF_RND_GetRngParams(uint32_t *KeySizeWords, uint32_t *TrngMode, uint32_t *RoscsAllowed,
                                 uint32_t *SampleCount, uint32_t *MaxTrngTimeCoeff);

/* ********************************************************************************* */
/*
 * @brief The LLF_RND_TurnOffTrng stops the hardware random bits collection
 *        closes RND clocks and releases HW semaphore.
 *
 *
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
void LLF_RND_TurnOffTrng(void);

SaSiError_t LLF_RND_GetFastestRosc(SaSi_RND_Params_t *trngParams_ptr, uint32_t *rosc_ptr /* in/out */);

SaSiError_t LLF_RND_GetRoscSampleCnt(uint32_t rosc, SaSi_RND_Params_t *pTrngParams);

void LLF_RND_WaitRngInterrupt(uint32_t *isr_ptr);

uint32_t LLF_RND_GetCountRoscs(uint32_t roscsAllowed, uint32_t roscToStart);

uint32_t LLF_RND_GetPreferableRosc(uint32_t *rndWorkBuff_ptr);

void LLF_RND_TurnOffTrng(void);

SaSiError_t LLF_RND_EntropyEstimateFull(uint32_t *ramAddr,          /* in */
                                        uint32_t blockSizeWords,    /* in */
                                        uint32_t countBlocks,       /* in */
                                        uint32_t *entrSize_ptr,     /* out */
                                        uint32_t *rndWorkBuff_ptr); /* in */

/*
 * @brief: The function performs CPRNGT (Continued PRNG Test) according
 *         to NIST 900-80 and FIPS (if defined) standards.
 *
 * @param[in] prev_ptr - The pointer to previous saved generated random
 *                       value of size 16 bytes.
 * @param[in] buff_ptr - The pointer to generated random buffer.
 * @param[in] last_ptr - The pointer to last generated random block
 *                       of size 16 bytes used for output last bytes.
 * @param[in] countBlocks - The count of generated random blocks, including
 *                          the last block. Assumed countBlocks > 0.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in SaSi_Error.h
 */
SaSiError_t LLF_RND_RndCprngt(uint8_t *prev_ptr,    /* in */
                              uint8_t *buff_ptr,    /* in */
                              uint8_t *last_ptr,    /* in */
                              int32_t countBlocks); /* in */

#ifdef __cplusplus
#endif

#endif
