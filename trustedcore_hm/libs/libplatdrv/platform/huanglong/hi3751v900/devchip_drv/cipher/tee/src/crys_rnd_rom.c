/*
 * Copyright (c) Hisilicon Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: rnd rom
 * Author: cipher group
 * Create: 2019-12-11
 */

#include "hi_type_dev.h"
#include "dx_pal_types.h"
#include "crys_rnd_error.h"
#include "crys_rnd_local.h"
#include "crys_common.h"
#include "crys_common_math.h"
#include "crys_cipher_common.h"
#include "drv_osal_lib.h"

#define MSB_BIT_IN_BYTE 0x80

/* *************** Global Data to be read by RNG function *************** */
/* ************************************************************************************** */
/* ****************************       Public Functions      ***************************** */
/* ************************************************************************************** */
/* ****************************************************************************************
 * @brief The CRYS_RND_GenerateVector function generates a random vector,
 *             using the FIPS-PUB [SP800-90].
 *
 *        The random function is based on the AES.
 *
 *
 * @RndSize[in] - The size of random bytes that is required.
 *
 * @Output_ptr[in,out] The output vector.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_GenerateVector(DxUint16_t RndSize, DxUint8_t *Output_ptr)
{
    hi_s32 ret;

    if (Output_ptr == DX_NULL) {
        return CRYS_RND_DATA_OUT_POINTER_INVALID_ERROR;
    }

    ret = crys_get_random_number(Output_ptr, RndSize);

    return (ret == HI_SUCCESS) ? CRYS_OK : CRYS_FATAL_ERROR;
} /* END OF CRYS_RND_GenerateVector */

/* -----------------------------------------------------------------------------
 * @brief The function performs instantiation of RNG and creates new
 *        internal State (including Seed) of RNG.
 *
 *        It implements the CTR_DRBG_Instantiate function of 9.1 [1].
 *        This function must be called at least once per system reset (boot) and
 *        required before any random generation can be produced.
 *
 * @param[in/out] entrEstimBuff_ptr - The temp buffer for specific operations
 *                               on entropy estimator.
 *                         Note: for projects, which not use entropy estimator (e.g.
 *                               SW projects), the pointer may be set to NULL.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_Instantiation(CRYS_RND_EntropyEstimatData_t *entrEstimBuff_ptr /* in/out */)
{
    return CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR;
}

#ifndef _INTERNAL_CRYS_ONE_SEED
/* -----------------------------------------------------------------------------
 * @brief The CRYS_RND_UnInstantiation cleans the unused RNG State for security goals.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_UnInstantiation(void)
{
    return CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR;
}

/* ------------------------------------------------------------/
 * @brief The function performs reseeding of RNG Seed, and performs:
 *          1. Mixing of additional entropy into the working state.
 *         2. Mixing additional input provided by the user called additional input buffer.
 *
 *        The function implements the CTR_DRBG_Reseeding function of 9.2 [1].
 *        This function must be called if reseed counter > reseed interval,
 *        in our implementation it is 2^32-1.
 *
 * @param[in/out] entrEstimBuff_ptr - The temp buffer for specific operations
 *                               on entropy estimator.
 *                         Note: for projects, which not use entropy estimator (e.g.
 *                               SW projects), the pointer may be set to NULL.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_Reseeding(CRYS_RND_EntropyEstimatData_t *entrEstimBuff_ptr /* in/out */)
{
    /* FUNCTION DECLERATIONS */
    return CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR;
} /* END OF CRYS_RND_Reseeding */

#endif /* _INTERNAL_CRYS_ONE_SEED */

/*
 * @brief The CRYS_RND_Init initializes the module
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_Init(void)
{
    return CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR;
} /* END OF CRYS_RND_Init */

#ifndef _INTERNAL_CRYS_ONE_SEED
/*
 * @brief The LLF_RND_SetAdditionalInput - This function load the AdditionaInput
 *                                            from user to the global State buffer, sets
 *                                            its Size and Valid flag to 1.
 *
 * @param[in/out] State - The pointer to the internal State buffer of DRNG.
 * @param[in] AdditonalInput_ptr - The pointer to Additional input buffer.
 * @param[in] AdditonalInputSize - The size of Additional input in words - must be up to 12 words.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_AddAdditionalInput(DxUint8_t *AdditonalInput_ptr,
                                                  DxUint16_t AdditonalInputSizeBytes)
{
    return CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR;
}

/*
 * @brief The CRYS_RND_EnterKatMode function sets KAT mode bit into StateFlag
 *        of global CRYS_RND_WorkingState structure.
 *
 *   In this, Non DMA, version of function all parameters are dummy and not
 *   used, but needed for compilation goals.
 *
 * @param entrData_ptr  - entropy data,
 * @param entrSize      - entropy size in bytes,
 * @param nonce_ptr     - nonce,
 * @param nonceSize     - nonce size in bytes,
 * @param workBuff_ptr  - RND working buffer, must be the same buffer,
 *                which should be passed into Instantiation/Reseeding functions.
 *
 *    Note: Total size of entropy and nonce must be not great than:
 *            CRYS_RND_MAX_KAT_ENTROPY_AND_NONCE_SIZE, defined
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_EnterKatMode(DxUint8_t *entrData_ptr,
                                            DxUint32_t entrSize,
                                            DxUint8_t *nonce_ptr,
                                            DxUint32_t nonceSize,
                                            CRYS_RND_WorkBuff_t *workBuff_ptr /* out */)
{
    return CRYS_OK;
} /* END OF CRYS_RND_EnterKatMode */

/*
 * @brief The CRYS_RND_DisableKatMode function sets KAT mode bit into StateFlag
 *        of global CRYS_RND_WorkingState structure.
 *
 *   The user must call this function before calling functions performing KAT tests.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C void CRYS_RND_DisableKatMode(void)
{
    /* CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR */
    return;
} /* END OF CRYS_RND_DisableKatMode */

/*
 * @brief The CRYS_RND_GenerateVectorInRange function generates a random vector Rand in range:
 *            1 < RandVect < MaxVect,   using the FIPS-PUB 186-2 standard appendix 3 :
 *        The function performs the following:
 *        1.  Check input parameters.
 *        2.  If maxVect != 0 (maxVect is provided), then calculate required size of random
 *            equaled to actual bit size of MaxVector, else set it = rndSizeInBits.
 *        3.  Calls the CRYS_RND_GenerateVector() function for generating random vector
 *            RndVect of required size.
 *        4.  If maxVect is provided, then:
 *             4.1. Sets all high bits of RndVect, greatest than MSBit of MaxVector, to 0.
 *             4.2. If size of random vector > 16 bytes, then:
 *                     4.2.1. Compares high 16 bytes of randVect to maxVect and low limit
 *                     4.2.2. If condition 1 < randVect16 < maxVect16 is not satisfied,
 *                            then generate new high 16 bytes rndVect16 and go to step 4.2.1.
 *             4.3. Compares full value of RndVect with MaxVector and with 1 . If condition
 *                 1 < RandVect < MaxVector is not satisfied, then go to step 3, else go to 6.
 *        5. Else if maxVect is not provided, then set MSBit of rndVect to 1.
 *        6. Output the result and Exit.
 *
 *         Note: Random and Max vectors are given as sequence of bytes, where LSB is most left byte
 *               and MSB = most right one.
 *
 * @rndSize[in]         - The maximal size (in bits) of random vector if maxVect is given or exact size
 *                        of required random vector.
 * @maxVect_ptr[in]     - The pointer to vector defines high limit of random vector.
 * @rndVect_ptr[in,out] - The output random vector.
 * @return CRYSError_t  - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_GenerateVectorInRange(DxUint32_t rndSizeInBits, DxUint8_t *maxVect_ptr,
                                                     DxUint8_t *rndVect_ptr)
{
    CRYSError_t error;

    if (rndVect_ptr == DX_NULL) {
        return CRYS_RND_DATA_OUT_POINTER_INVALID_ERROR;
    }

    if (maxVect_ptr != DX_NULL) {
        hi_log_print_err_code(CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR);
        return CRYS_RND_OPERATION_IS_NOT_SUPPORTED_ERROR;
    }

    if (rndSizeInBits == 0) {
        hi_log_print_err_code(CRYS_RND_VECTOR_SIZE_ERROR);
        return CRYS_RND_VECTOR_SIZE_ERROR;
    }

    error = CRYS_RND_GenerateVector(rndSizeInBits / BITS_IN_BYTE, rndVect_ptr);
    if (error != CRYS_OK) {
        hi_log_print_func_err(CRYS_RND_GenerateVector, error);
        return error;
    }

    rndVect_ptr[0] |= MSB_BIT_IN_BYTE;

    return CRYS_OK;
} /* End of CRYS_RND_GenerateVectorInRange function */

#endif /* _INTERNAL_CRYS_ONE_SEED */

#ifdef CRYS_RND_AES_OLD_128BIT_ONLY

/*
 * @brief The CRYS_RND_ResetSeed function performs Instantiate operation.
 *
 *        This function needed for backward compatibility with some projects.
 *        It is recommended to call directly the CRYS_RND_Instantiation function.
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_ResetSeed(void)
{
    return CRYS_RND_Instantiation();
} /* END OF CRYS_RND_ResetSeed */

/*
 * @brief The CRYS_RND_StartResetSeed is a dummy function needed
 *        for backward compatibility with some projects
 *
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* as defined in ...
 */
CEXPORT_C CRYSError_t CRYS_RND_StartResetSeed(void)
{
    return CRYS_OK;
} /* END OF CRYS_RND_StartResetSeed */
#endif

/*
 * @brief The DX_RND_GenerateLeWordsArrayInRange function generates a random words vector in range:
 *            1 < RndVect < MaxVect,   using the FIPS-PUB 186-2 standard appendix 3 :
 *
 *        The function generates random array  using CRYS_RND_GenerateVectorInRange function and
 *        conversion of bytes to words.
 *
 *         Note: RndVect and MaxVect arrayss are given as sequence of words, where LSWord is most left byte
 *               and MSWord - most right.
 *
 * @rndSizeInBits[in]   - If maxVect_ptr is not given, then rndSizeInBits defining the exact size (in bits)
 *                        of generated random vector. If maxVect is given, then it defines the
 *                      size (rounded up to words) of the maxVect_ptr buffer. The size must be not greate
 *                than CRYS_RND_MAX_SIZE_OF_OUTPUT_BYTES/4
 * @maxVect_ptr[in]     - The pointer to vector defining a high limit of random vector.
 * @rndVect_ptr[out]    - The output buffer for the random vector.
 * @tmp_ptr[int]        - The temp buffer for the random generation. The size must be not
 *                less, than rndSizeInBits converted to words (rounded up).
 *
 * @return CRYSError_t  - On success CRYS_OK is returned, on failure - a value,
 *                defined in crys_rnd_error.h.
 */
CRYSError_t DX_RND_GenerateWordsArrayInRange(DxUint32_t rndSizeInBits,
                                             DxUint32_t *maxVect_ptr,
                                             DxUint32_t *rndVect_ptr,
                                             DxUint32_t *tmp_ptr)
{
    CRYSError_t err;

    err = CRYS_RND_GenerateVectorInRange(rndSizeInBits, DX_NULL, (DxUint8_t *)rndVect_ptr);
    if (err) {
        hi_log_print_func_err(CRYS_RND_GenerateVectorInRange, err);
        return err;
    }

    return err;
}
