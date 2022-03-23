/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SaSi_API

#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "sasi_hash.h"
#include "sasi_hash_error.h"
#include "hash.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "ssi_error.h"
#include "sasi_context_relocation.h"
#include "ssi_pal_perf.h"
#include "sasi_fips_defs.h"

/* *********************** Defines **************************** */

#if (SaSi_HASH_USER_CTX_SIZE_IN_WORDS < SASI_DRV_CTX_SIZE_WORDS)
#error SaSi_HASH_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif
/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#define SaSi_HASH_USER_CTX_ACTUAL_SIZE_IN_WORDS ((SaSi_HASH_USER_CTX_SIZE_IN_WORDS - 3) / 2)

/* *********************** Type definitions ******************** */
typedef struct SaSi_HASHPrivateContext_t {
    uint32_t isLastBlockProcessed;
} SaSi_HASHPrivateContext_t;

/* *********************** Public Functions **************************** */

/* !
 * Converts Symmetric Adaptor return code to SaSi error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return SaSiError_t one of SaSi_* error codes defined in sasi_error.h
 */
static SaSiError_t SymAdaptor2SasiHashErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
    case SASI_RET_UNSUPP_ALG:
        return SaSi_HASH_IS_NOT_SUPPORTED;
    case SASI_RET_UNSUPP_ALG_MODE:
    case SASI_RET_UNSUPP_OPERATION:
        return SaSi_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    case SASI_RET_INVARG:
    case SASI_RET_INVARG_QID:
        return SaSi_HASH_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_KEY_SIZE:
    case SASI_RET_INVARG_CTX_IDX:
        return SaSi_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    case SASI_RET_INVARG_CTX:
        return SaSi_HASH_USER_CONTEXT_CORRUPTED_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SaSi_HASH_DATA_IN_POINTER_INVALID_ERROR;
    case SASI_RET_NOMEM:
        return SaSi_OUT_OF_RESOURCE_ERROR;
    case SASI_RET_INVARG_INCONSIST_DMA_TYPE:
        return SaSi_ILLEGAL_RESOURCE_VAL_ERROR;
    case SASI_RET_PERM:
    case SASI_RET_NOEXEC:
    case SASI_RET_BUSY:
    case SASI_RET_OSFAULT:
    default:
        return SaSi_FATAL_ERROR;
    }
}

/*
 * This function initializes the HASH machine on the SaSi level.
 *
 * This function allocates and initializes the HASH Context .
 * The function receives as input a pointer to store the context handle to HASH Context ,
 * it initializes the
 * HASH Context with the cryptographic attributes that are needed for
 * the HASH block operation ( initialize H's value for the HASH algorithm ).
 *
 * The function flow:
 *
 * 1) checking the validity of the arguments - returnes an error on an illegal argument case.
 * 2) Aquiring the working context from the CCM manager.
 * 3) Initializing the context with the parameters passed by the user and with the init values
 *    of the HASH.
 * 4) loading the user tag to the context.
 * 5) release the CCM context.
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 * @param[in] OperationMode - The operation mode : MD5 or SHA1.
 *
 * @return SaSiError_t on success the function returns SaSi_OK else non ZERO error.
 *
 */
CEXPORT_C SaSiError_t SaSi_HASH_Init_MTK(SaSi_HASHUserContext_t *ContextID_ptr, SaSi_HASH_OperationMode_t OperationMode)
{
    struct drv_ctx_hash *pHashContext;
    SaSi_HASHPrivateContext_t *pHashPrivContext;
    int symRc                  = SASI_RET_OK;
    SaSi_PalPerfData_t perfIdx = 0;

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SaSi_HASH_INIT);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return SaSi_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (OperationMode >= SaSi_HASH_NumOfModes) {
        return SaSi_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* pointer for CTX  allocation */
    /* FUNCTION LOGIC */
    /* Get pointer to contiguous context in the HOST buffer */
    pHashContext = (struct drv_ctx_hash *)SaSi_InitUserCtxLocation(ContextID_ptr->buff, sizeof(SaSi_HASHUserContext_t),
                                                                   sizeof(struct drv_ctx_hash));
    if (pHashContext == NULL) {
        return SaSi_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }
    pHashPrivContext =
        (SaSi_HASHPrivateContext_t *)&(((uint32_t *)pHashContext)[SaSi_HASH_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    pHashContext->alg                      = DRV_CRYPTO_ALG_HASH;
    pHashPrivContext->isLastBlockProcessed = 0;

    switch (OperationMode) {
    case SaSi_HASH_SHA1_mode:
        pHashContext->mode = SEP_HASH_SHA1;
        break;
    case SaSi_HASH_SHA224_mode:
        pHashContext->mode = SEP_HASH_SHA224;
        break;
    case SaSi_HASH_SHA256_mode:
        pHashContext->mode = SEP_HASH_SHA256;
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case SaSi_HASH_SHA384_mode:
        pHashContext->mode = SEP_HASH_SHA384;
        break;
    case SaSi_HASH_SHA512_mode:
        pHashContext->mode = SEP_HASH_SHA512;
        break;
#endif
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
    case SaSi_HASH_MD5_mode:
        pHashContext->mode = SEP_HASH_MD5;
        break;
#endif
    default:
        return SaSi_HASH_ILLEGAL_OPERATION_MODE_ERROR;
    }

    symRc = SymDriverAdaptorInit((struct drv_ctx_generic *)pHashContext);
    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SaSi_HASH_INIT);
    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHashErr);
}

/*
 * This function process a block of data via the HASH Hardware.
 * The function receives as input an handle to the  HASH Context , that was initialized before
 * by an SaSi_HASH_Init_MTK function or by other SaSi_HASH_Update_MTK
 * function. The function Sets the hardware with the last H's
 * value that where stored in the SaSi HASH context and then
 * process the data block using the hardware and in the end of
 * the process stores in the HASH context the H's value HASH
 * Context with the cryptographic attributes that are needed for
 * the HASH block operation ( initialize H's value for the HASH
 * algorithm ). This function is used in cases not all the data
 * is arrange in one continues buffer.
 *
 * The function flow:
 *
 * 1) checking the parameters validty if there is an error the function shall exit with an error code.
 * 2) Aquiring the working context from the CCM manager.
 * 3) If there isnt enouth data in the previous update data buff in the context plus the received data
 *    load it to the context buffer and exit the function.
 * 4) fill the previous update data buffer to contain an entire block.
 * 5) Calling the hardware low level function to execute the update.
 * 6) fill the previous update data buffer with the data not processed at the end of the received data.
 * 7) release the CCM context.
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 * @param DataIn_ptr a pointer to the buffer that stores the data to be
 *                       hashed .
 *
 * @param DataInSize  The size of the data to be hashed in bytes.
 *
 * @return SaSiError_t on success the function returns SaSi_OK else non ZERO error.
 *
 */
CEXPORT_C SaSiError_t SaSi_HASH_Update_MTK(SaSi_HASHUserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                           uint32_t DataInSize)
{
    struct drv_ctx_hash *pHashContext;
    SaSi_HASHPrivateContext_t *pHashPrivContext;
    int symRc                    = SASI_RET_OK;
    int hash_block_size_in_bytes = 0;
    SaSi_PalPerfData_t perfIdx   = 0;

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SaSi_HASH_UPDATE);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return SaSi_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (DataInSize == 0) {
        return SaSi_OK;
    }

    if (DataIn_ptr == NULL) {
        return SaSi_HASH_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHashContext = (struct drv_ctx_hash *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);

    pHashPrivContext =
        (SaSi_HASHPrivateContext_t *)&(((uint32_t *)pHashContext)[SaSi_HASH_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);
    if (pHashPrivContext->isLastBlockProcessed != 0) {
        return SaSi_HASH_LAST_BLOCK_ALREADY_PROCESSED_ERROR;
    }

    if (pHashContext->mode < SEP_HASH_SHA512 || pHashContext->mode == SEP_HASH_MD5)
        hash_block_size_in_bytes = SaSi_HASH_BLOCK_SIZE_IN_BYTES;
    else
        hash_block_size_in_bytes = SaSi_HASH_SHA512_BLOCK_SIZE_IN_BYTES;

    if ((DataInSize % hash_block_size_in_bytes) == 0) {
        symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pHashContext, DataIn_ptr, NULL, DataInSize);

        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHashErr);
        }
    } else { /* this is the last block */
        pHashPrivContext->isLastBlockProcessed = 1;
        symRc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pHashContext, DataIn_ptr, NULL, DataInSize);

        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHashErr);
        }
    }

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SaSi_HASH_UPDATE);
    return SaSi_OK;
}

/*
 * This function finalize the hashing process of data block.
 * The function receives as input an handle to the HASH Context , that was initialized before
 * by an SaSi_HASH_Init_MTK function or by SaSi_HASH_Update_MTK function.
 * The function "adds" an header to the data block as the specific hash standard
 * specifics , then it loads the hardware and reads the final message digest.
 *
 *  the function flow:
 *
 * 1) checking the parameters validty if there is an error the function shall exit with an error code.
 * 2) Calling the hardware low level function to execute the
 *    finish.
 *
 *  @param[in] ContextID_ptr - a pointer to the HASH context buffer allocated by the user that
 *                       is used for the HASH machine operation.
 *
 *  @retval HashResultBuff a pointer to the target buffer where the
 *                       HASE result stored in the context is loaded to.
 *
 *  @return SaSiError_t on success the function returns SaSi_OK else non ZERO error.
 */

CEXPORT_C SaSiError_t SaSi_HASH_Finish_MTK(SaSi_HASHUserContext_t *ContextID_ptr, SaSi_HASH_Result_t HashResultBuff)
{
    struct drv_ctx_hash *pHashContext;
    SaSi_HASHPrivateContext_t *pHashPrivContext;
    int symRc                  = SASI_RET_OK;
    SaSi_PalPerfData_t perfIdx = 0;

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SaSi_HASH_FIN);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return SaSi_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (HashResultBuff == NULL) {
        return SaSi_HASH_INVALID_RESULT_BUFFER_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHashContext = (struct drv_ctx_hash *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);

    pHashPrivContext =
        (SaSi_HASHPrivateContext_t *)&(((uint32_t *)pHashContext)[SaSi_HASH_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (pHashPrivContext->isLastBlockProcessed == 0) {
        symRc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pHashContext, NULL, NULL, 0);

        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHashErr);
        }
    }

    /* Copy the result to the user buffer */
    SaSi_PalMemCopy(HashResultBuff, pHashContext->digest, SaSi_HASH_RESULT_SIZE_IN_WORDS * sizeof(uint32_t));

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SaSi_HASH_FIN);
    return SaSi_OK;
}

/*
 * @brief This function clears the hash context
 *
 * @param[in] ContextID_ptr - a pointer to the HASH context
 *                       buffer allocated by the user that is
 *                       used for the HASH machine operation.
 *                       This should be the same context that
 *                       was used on the previous call of this
 *                       session.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* sasi_hash_error.h
 */
CEXPORT_C SaSiError_t SaSi_HASH_Free_MTK(SaSi_HASHUserContext_t *ContextID_ptr)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return SaSi_HASH_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    SaSi_PalMemSetZero(ContextID_ptr, sizeof(SaSi_HASHUserContext_t));

    return SaSi_OK;
}

/*
 * This function provide HASH function to process one buffer of data.
 * The function allocates an internal HASH Context , it initializes the
 * HASH Context with the cryptographic attributes that are needed for
 * the HASH block operation ( initialize H's value for the HASH algorithm ).
 * Then the function loads the Hardware with the initializing values and after
 * that process the data block using the hardware to do hash .
 * At the end the function return the message digest of the data buffer .
 *
 * @param[in] OperationMode - The operation mode : MD5 or SHA1.
 *
 * @param DataIn_ptr a pointer to the buffer that stores the data to be
 *                       hashed .
 *
 * @param DataInSize  The size of the data to be hashed in bytes.
 *
 * @retval HashResultBuff a pointer to the target buffer where the
 *                      HASE result stored in the context is loaded to.
 *
 * @return SaSiError_t on success the function returns SaSi_OK else non ZERO error.
 *
 */
CEXPORT_C SaSiError_t SaSi_HASH_MTK(SaSi_HASH_OperationMode_t OperationMode, uint8_t *DataIn_ptr, uint32_t DataSize,
                                    SaSi_HASH_Result_t HashResultBuff)
{
    SaSiError_t Error = SaSi_OK;
    SaSi_HASHUserContext_t UserContext;

    Error = SaSi_HASH_Init_MTK(&UserContext, OperationMode);
    if (Error != SaSi_OK) {
        goto end;
    }

    Error = SaSi_HASH_Update_MTK(&UserContext, DataIn_ptr, DataSize);
    if (Error != SaSi_OK) {
        goto end;
    }

    Error = SaSi_HASH_Finish_MTK(&UserContext, HashResultBuff);

end:
    SaSi_HASH_Free_MTK(&UserContext);

    return Error;
}
