/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef LLF_RND_TRNG_H
#define LLF_RND_TRNG_H

#include "dx_rng.h"
#include "ssi_pal_mem.h"
#include "dx_sasi_kernel.h"
#include "ssi_regs.h"
#include "dx_host.h"
#include "cc_plat.h"

#include "llf_rnd.h"
#if (defined SSI_CONFIG_TRNG_MODE) && (SSI_CONFIG_TRNG_MODE == 0)
#include "ssi_config_fetrng.h"
#elif (defined SSI_CONFIG_TRNG_MODE) && (SSI_CONFIG_TRNG_MODE == 1)
#include "ssi_config_trng90b.h"
#endif

#define LLF_RND_NUM_OF_ROSCS 4

#ifdef __cplusplus
extern "C" {
#endif

/* *********************** Defines **************************** */

/* ******************* Public Functions *********************** */

/* ************************************************************************************* */
/*
 * @brief The function starts the TRNG with given parameters and ROSCs lengths
 *
 *      NOTE: It is assumed, that before calling this function, the previously
 *            started TRNG processes were compleated and Interrupts cleared.
 *
 *      Algorithm:
 *      1. If is continued mode, the function does:
 *              checks actual parameters, loaded in TRNG registers,
 *              vs. user given parameters; if any not matchs - returns Error.
 *         Else /do restart/:
 *          sets ROSCs to start: for "SW entropy estimation" - all allowed, for "Full entropy (HW)" -
 *          fastest from allowed; gets the user given parameters and sets
 *          them in the HW, starts the TRNG clocks and sets TRNG parameters
 *          into HW registers.
 *      2. Initializes the RND DMA according to ROSCs required to start,
 *         initializes the TRNG Interrupt. Enables RNG source.
 *      3. Exits.
 *
 * @param[in/out] rndContext_ptr - The pointer to the internal State buffer of DRNG.
 * @param[in/out] trngParams_ptr - The pointer to structure, containing TRNG parameters.
 * @isContinued[in] isRestart - The variable indicates is a restart required or not.
 * @roscsToStart[in] roscsToStart_ptr - The variable, defining which ROSCs to
 *                      start according to bits set: b'0...b'3. When
 *                      isRestart=TRUE, then:
 *                      for "SWEE" - starts all allowed ROSCs, for
 *                      "FE" - starts fastest ROSC from allowed.
 *                      Note: if isRestart = 1, then
 * @sramAddr[in] SRAM address to write the random source.
 *
 * @return SaSiError_t - no return value
 */
SaSiError_t LLF_RND_StartTrngHW(SaSi_RND_State_t *rndState_ptr, SaSi_RND_Params_t *trngParams_ptr, SaSiBool_t isRestart,
                                uint32_t *roscsToStart_ptr, DxSramAddr_t sramAddr);

/* **************************************************************************** */
/*
 * @brief The LLF_RND_GetTrngSource reads random source of needed size from TRNG.
 *
 *        The function is used in Self, Instantiation and Reseeding functions.
 *
 * @param[in/out] rndContext_ptr - The pointer to the internal State buffer of DRNG.
 * @param[in/out] trngParams_ptr - The pointer to structure, containing TRNG parameters.
 * @isContinued[in] isContinued - The variable indicates is the required process should
 *                  continue a  previous one or restart TRNG.
 * @entropySize_ptr[in/out] - The pointer to size of entropy in bits: input - required,
 *                            output - actual size.
 * @sourceOut_ptr_ptr[out] - The pointer to to pointer to the entropy source buffer.
 *                   The buffer contains one empty word for using by SaSi level
 *                   and then buffer for output the rng source.
 * @param[out] - sourceOutSize_ptr - The pointer to the size in bytes of entropy source
 *                      in - required size, output - actual size.
 * @param[in/out] - rndWorkBuff_ptr - The pointer to the temp buffer for allocation of
 *                     estimator buffers.
 * @param[in] - isFipsSupported - indication if FIPS is supported.
 *
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
SaSiError_t LLF_RND_GetTrngSource(SaSi_RND_State_t *rndState_ptr,    /* in/out */
                                  SaSi_RND_Params_t *trngParams_ptr, /* in/out */
                                  SaSiBool_t isContinued,            /* in */
                                  uint32_t *entropySize_ptr,         /* in/out */
                                  uint32_t **sourceOut_ptr_ptr,      /* out */
                                  uint32_t *sourceOutSize_ptr,       /* in/out */
                                  uint32_t *rndWorkBuff_ptr,         /* in */
                                  bool isFipsSupported);             /* in */

/* **************************************************************************** */
/*
 * @brief The LLF_RND_RunTrngStartupTest runs the startup tests required for TRNG.
 *
 * @param[in/out] rndContext_ptr - The pointer to the internal State buffer of DRNG.
 * @param[out] trngParams_ptr - The pointer to structure, containing TRNG parameters.
 * @param[in/out] - rndWorkBuff_ptr - The pointer to the temp buffer for allocation of
 *                     estimator buffers.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
SaSiError_t LLF_RND_RunTrngStartupTest(SaSi_RND_State_t *rndState_ptr,    /* in/out */
                                       SaSi_RND_Params_t *trngParams_ptr, /* out */
                                       uint32_t *rndWorkBuff_ptr);        /* in */

#ifdef __cplusplus
}
#endif

#endif // LLF_RND_TRNG_H
