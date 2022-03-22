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
#include "sasi_hmac.h"
#include "sasi_hmac_error.h"
#include "hmac.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "ssi_error.h"
#include "sasi_context_relocation.h"
#include "sasi_fips_defs.h"

/* *********************** Defines **************************** */
#if (SaSi_HMAC_USER_CTX_SIZE_IN_WORDS < SASI_DRV_CTX_SIZE_WORDS)
#error SaSi_HMAC_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#define SaSi_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS ((SaSi_HMAC_USER_CTX_SIZE_IN_WORDS - 3) / 2)

/* *********************** Type definitions ******************** */
typedef struct SaSi_HMACPrivateContext_t {
    uint32_t isLastBlockProcessed;
} SaSi_HMACPrivateContext_t;

/* *********************** Private Functions ******************** */

/* !
 * Get Hash block Size length in bytes.
 *
 * \param mode Hash mode
 *
 * \return int digest size return value.
 */
static int GetHmacBlocktSize(const enum sep_hash_mode mode)
{
    if (mode >= SEP_HASH_MODE_NUM) {
        SASI_PAL_LOG_ERR("Unsupported hash mode");
        return 0;
    }

    if (mode <= SEP_HASH_SHA224 || mode == SEP_HASH_MD5)
        return SaSi_HASH_BLOCK_SIZE_IN_BYTES;
    else
        return SaSi_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
}

/* !
 * Converts Symmetric Adaptor return code to SaSi error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return SaSiError_t one of SaSi_* error codes defined in sasi_error.h
 */
static SaSiError_t SymAdaptor2SasiHmacErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
    case SASI_RET_UNSUPP_ALG:
        return SaSi_HMAC_IS_NOT_SUPPORTED;
    case SASI_RET_UNSUPP_ALG_MODE:
    case SASI_RET_UNSUPP_OPERATION:
        return SaSi_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    case SASI_RET_INVARG:
    case SASI_RET_INVARG_QID:
        return SaSi_HMAC_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_KEY_SIZE:
        return SaSi_HMAC_UNVALID_KEY_SIZE_ERROR;
    case SASI_RET_INVARG_CTX_IDX:
        return SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    case SASI_RET_INVARG_CTX:
        return SaSi_HMAC_USER_CONTEXT_CORRUPTED_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SaSi_HMAC_DATA_IN_POINTER_INVALID_ERROR;
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

static inline enum sep_hash_mode Sasi2SepHashMode(SaSi_HASH_OperationMode_t OperationMode)
{
    enum sep_hash_mode result;

    switch (OperationMode) {
    case SaSi_HASH_SHA1_mode:
        result = SEP_HASH_SHA1;
        break;
    case SaSi_HASH_SHA224_mode:
        result = SEP_HASH_SHA224;
        break;
    case SaSi_HASH_SHA256_mode:
        result = SEP_HASH_SHA256;
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case SaSi_HASH_SHA384_mode:
        result = SEP_HASH_SHA384;
        break;
    case SaSi_HASH_SHA512_mode:
        result = SEP_HASH_SHA512;
        break;
#endif
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
    case SaSi_HASH_MD5_mode:
        result = SEP_HASH_MD5;
        break;
#endif
    default:
        result = SEP_HASH_NULL;
    }

    return result;
}

/* *********************** Public Functions ******************** */

/*
 * This function initializes the HMAC machine on the SaSi level.
 *
 * The function allocates and initializes the HMAC Context .
 * The function receives as input a pointer to store the context handle to HMAC Context.
 *
 * The function executes a HASH_init session and processes a HASH update
 * on the Key XOR ipad and stores it in the context.
 *
 * @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 * @param[in] OperationMode - The operation mode according to supported hash operation mode..
 *
 * @param[in] key_ptr - The pointer to the user's key buffer,
 *            or its digest (if larger than the hash block size).
 *
 * @param[in] keySize - The size of the received key. Must not exceed the associated
 *                      hash block size. For larger keys the caller must provide
 *                      a hash digest of the key as the actual key.
 *
 * @return SaSiError_t - On success the function returns the value SaSi_OK,
 *            and on failure a non-ZERO error.
 *
 */
CIMPORT_C SaSiError_t SaSi_HMAC_Init_MTK(SaSi_HMACUserContext_t *ContextID_ptr, SaSi_HASH_OperationMode_t OperationMode,
                                         uint8_t *key_ptr, uint16_t keySize)
{
    struct drv_ctx_hmac *pHmacContext;
    SaSi_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = SASI_RET_OK;
    uint32_t HashBlockSize;
    SaSiError_t error = SaSi_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check if the key pointer is valid */
    if (key_ptr == NULL) {
        return SaSi_HMAC_INVALID_KEY_POINTER_ERROR;
    }

    /* check if the operation mode is legal and set hash block size */
    switch (OperationMode) {
    case SaSi_HASH_SHA1_mode:
    case SaSi_HASH_SHA224_mode:
    case SaSi_HASH_SHA256_mode:
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
    case SaSi_HASH_MD5_mode:
#endif
        HashBlockSize = SaSi_HASH_BLOCK_SIZE_IN_BYTES;
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case SaSi_HASH_SHA384_mode:
    case SaSi_HASH_SHA512_mode:
        HashBlockSize = SaSi_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
        break;
#endif
    default:
        return SaSi_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the key size is valid */
    if (keySize == 0) {
        return SaSi_HMAC_UNVALID_KEY_SIZE_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hmac *)SaSi_InitUserCtxLocation(ContextID_ptr->buff, sizeof(SaSi_HMACUserContext_t),
                                                                   sizeof(struct drv_ctx_hmac));
    if (pHmacContext == NULL) {
        return SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }
    pHmacPrivContext =
        (SaSi_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[SaSi_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    pHmacContext->alg                      = DRV_CRYPTO_ALG_HMAC;
    pHmacContext->mode                     = Sasi2SepHashMode(OperationMode);
    pHmacPrivContext->isLastBlockProcessed = 0;

    if (keySize > HashBlockSize) {
        error = SaSi_HASH_MTK(OperationMode, key_ptr, keySize,
                              (uint32_t *)pHmacContext->k0); /* Write the result into th context */

        if (error != SaSi_OK)
            return symRc;

        /* update the new key size according to the mode */
        switch (OperationMode) {
        case SaSi_HASH_SHA1_mode:
            keySize = SaSi_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
            break;
        case SaSi_HASH_SHA224_mode:
            keySize = SaSi_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
            break;
        case SaSi_HASH_SHA256_mode:
            keySize = SaSi_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
            break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
        case SaSi_HASH_SHA384_mode:
            keySize = SaSi_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
            break;
        case SaSi_HASH_SHA512_mode:
            keySize = SaSi_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
            break;
#endif
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
        case SaSi_HASH_MD5_mode:
            keySize = SaSi_HASH_MD5_DIGEST_SIZE_IN_BYTES;
            break;
#endif
        default:
            return SaSi_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
        }
    } /* end of key larger then 64 bytes case */
    else {
        SaSi_PalMemCopy((uint8_t *)pHmacContext->k0, key_ptr, keySize);
    }
    pHmacContext->k0_size = keySize;

    symRc = SymDriverAdaptorInit((struct drv_ctx_generic *)pHmacContext);
    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHmacErr);
}

/*
 * This function processes a HMAC block of data via the HASH hardware/software.
 * The function receives as input a handle to the HMAC Context,
 * and performs a HASH update on the data described below.
 *
 * @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 * @param DataIn_ptr - A pointer to the buffer that stores the data to be hashed.
 *
 * @param DataInSize - The size of the data to be hashed, in bytes.
 *
 * @return SaSiError_t - On success the function returns SaSi_OK,
 *            and on failure a non-ZERO error.
 */

CIMPORT_C SaSiError_t SaSi_HMAC_Update_MTK(SaSi_HMACUserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                           uint32_t DataInSize)
{
    struct drv_ctx_hmac *pHmacContext;
    SaSi_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = SASI_RET_OK;
    uint32_t blockSizeBytes;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal and the size is not 0 return an error */
    if ((DataIn_ptr == NULL) && DataInSize) {
        return SaSi_HMAC_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the data size is zero no need to execute an update , return SaSi_OK */
    if (DataInSize == 0) {
        return SaSi_OK;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hmac *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext =
        (SaSi_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[SaSi_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (pHmacPrivContext->isLastBlockProcessed != 0) {
        return SaSi_HMAC_LAST_BLOCK_ALREADY_PROCESSED_ERROR;
    }

    blockSizeBytes = GetHmacBlocktSize(pHmacContext->mode);
    if ((DataInSize % blockSizeBytes) == 0) {
        symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pHmacContext, DataIn_ptr, NULL, DataInSize);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHmacErr);
        }
    } else { /* this is the last block */
        pHmacPrivContext->isLastBlockProcessed = 1;
        symRc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pHmacContext, DataIn_ptr, NULL, DataInSize);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHmacErr);
        }
    }
    return SaSi_OK;
}

/*
 * This function finalizes the HMAC processing of a data block.
 * The function receives as input a handle to the HMAC Context that was previously initialized
 * by a SaSi_HMAC_Init_MTK function or by a SaSi_HMAC_Update_MTK function.
 * This function finishes the HASH operation on the ipad and text, and then
 * executes a new HASH operation with the key XOR opad and the previous HASH operation result.
 *
 *  @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 *  @retval HmacResultBuff - A pointer to the target buffer where the
 *                       HMAC result stored in the context is loaded to.
 *
 * @return SaSiError_t - On success the function returns SaSi_OK,
 *            and on failure a non-ZERO error.
 */
CIMPORT_C SaSiError_t SaSi_HMAC_Finish_MTK(SaSi_HMACUserContext_t *ContextID_ptr, SaSi_HASH_Result_t HmacResultBuff)
{
    struct drv_ctx_hmac *pHmacContext;
    SaSi_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = SASI_RET_OK;
    uint32_t hmacDigesSize;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (HmacResultBuff == NULL) {
        return SaSi_HMAC_INVALID_RESULT_BUFFER_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct drv_ctx_hmac *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);
    pHmacPrivContext =
        (SaSi_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[SaSi_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (pHmacPrivContext->isLastBlockProcessed == 0) {
        symRc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pHmacContext, NULL, NULL, 0);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiHmacErr);
        }
    }
    switch (pHmacContext->mode) {
    case SEP_HASH_SHA1:
        hmacDigesSize = SEP_SHA1_DIGEST_SIZE;
        break;
    case SEP_HASH_SHA224:
        hmacDigesSize = SEP_SHA224_DIGEST_SIZE;
        break;
    case SEP_HASH_SHA256:
        hmacDigesSize = SEP_SHA256_DIGEST_SIZE;
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case SEP_HASH_SHA384:
        hmacDigesSize = SEP_SHA384_DIGEST_SIZE;
        break;
    case SEP_HASH_SHA512:
        hmacDigesSize = SEP_SHA512_DIGEST_SIZE;
        break;
#endif
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
    case SEP_HASH_MD5:
        hmacDigesSize = SEP_MD5_DIGEST_SIZE;
        break;
#endif
    default:
        hmacDigesSize = -1;
        return SaSi_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    }

    SaSi_PalMemCopy(HmacResultBuff, pHmacContext->digest, hmacDigesSize);
    return SaSi_OK;
}

/*
 * @brief This function clears the hash context
 *
 * @param[in] ContextID_ptr - a pointer to the HMAC context
 *                       buffer allocated by the user that is
 *                       used for the HMAC machine operation.
 *                       This should be the same context that
 *                       was used on the previous call of this
 *                       session.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* sasi_hash_error.h
 */
CEXPORT_C SaSiError_t SaSi_HMAC_Free_MTK(SaSi_HMACUserContext_t *ContextID_ptr)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (ContextID_ptr == NULL) {
        return SaSi_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    SaSi_PalMemSetZero(ContextID_ptr, sizeof(SaSi_HMACUserContext_t));

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
 *
 * @param[in] OperationMode - The operation mode according to supported hash operation mode.
 *
 * @param[in] key_ptr - The pointer to the users key buffer.
 *
 * @oaram[in] keySize - The size of the received key.
 *
 * @param[in] ContextID_ptr - a pointer to the HMAC context buffer allocated by the user that
 *                       is used for the HMAC machine operation.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the HMAC. The pointer does
 *                         not need to be aligned. On CSI input mode the pointer must be equal to
 *                         value (0xFFFFFFFC | DataInAlignment).
 *
 * @param[in] DataInSize - The size of the data to be hashed in bytes. On CSI data transfer mode the size must
 *                         multiple of HASH_BLOCK_SIZE for used HASH mode.
 *
 * param[out] HashResultBuff - a pointer to the target buffer where the
 *                      HMAC result stored in the context is loaded to.
 *
 * @return SaSiError_t on success the function returns SaSi_OK else non ZERO error.
 *
 */
CIMPORT_C SaSiError_t SaSi_HMAC_MTK(SaSi_HASH_OperationMode_t OperationMode, uint8_t *key_ptr, uint16_t keySize,
                                    uint8_t *DataIn_ptr, uint32_t DataSize, SaSi_HASH_Result_t HmacResultBuff)
{
    SaSi_HMACUserContext_t UserContext;
    SaSiError_t Error = SaSi_OK;

    Error = SaSi_HMAC_Init_MTK(&UserContext, OperationMode, key_ptr, keySize);
    if (Error != SaSi_OK) {
        goto end;
    }

    Error = SaSi_HMAC_Update_MTK(&UserContext, DataIn_ptr, DataSize);
    if (Error != SaSi_OK) {
        goto end;
    }
    Error = SaSi_HMAC_Finish_MTK(&UserContext, HmacResultBuff);

end:
    return Error;
}
