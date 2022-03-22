/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_CRYS_API

#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "crys_hmac.h"
#include "crys_hmac_error.h"
#include "hmac.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "cc_acl.h"
#include "dx_error.h"
#include "crys_context_relocation.h"

/* *********************** Defines **************************** */
#if (SEP_CTX_SIZE_WORDS > CRYS_HMAC_USER_CTX_SIZE_IN_WORDS)
#error CRYS_HMAC_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#ifdef DX_CC_TEE
#define CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS ((CRYS_HMAC_USER_CTX_SIZE_IN_WORDS - 3) / 2)
#else
#define CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS CRYS_HMAC_USER_CTX_SIZE_IN_WORDS
#endif

/* *********************** Type definitions ******************** */
typedef struct CRYS_HMACPrivateContext_t {
    uint32_t isLastBlockProcessed;
} CRYS_HMACPrivateContext_t;

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
        DX_PAL_LOG_ERR("Unsupported hash mode");
        return 0;
    }

    if (mode <= SEP_HASH_SHA224 || mode == SEP_HASH_MD5)
        return CRYS_HASH_BLOCK_SIZE_IN_BYTES;
    else
        return CRYS_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
}

/* !
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static CRYSError_t SymAdaptor2CrysHmacErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
    case DX_RET_UNSUPP_ALG:
        return CRYS_HMAC_IS_NOT_SUPPORTED;
    case DX_RET_UNSUPP_ALG_MODE:
    case DX_RET_UNSUPP_OPERATION:
        return CRYS_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    case DX_RET_INVARG:
    case DX_RET_INVARG_QID:
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;
    case DX_RET_INVARG_KEY_SIZE:
        return CRYS_HMAC_UNVALID_KEY_SIZE_ERROR;
    case DX_RET_INVARG_CTX_IDX:
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    case DX_RET_INVARG_CTX:
        return CRYS_HMAC_USER_CONTEXT_CORRUPTED_ERROR;
    case DX_RET_INVARG_BAD_ADDR:
        return CRYS_HMAC_DATA_IN_POINTER_INVALID_ERROR;
    case DX_RET_NOMEM:
        return CRYS_OUT_OF_RESOURCE_ERROR;
    case DX_RET_INVARG_INCONSIST_DMA_TYPE:
        return CRYS_ILLEGAL_RESOURCE_VAL_ERROR;
    case DX_RET_PERM:
    case DX_RET_NOEXEC:
    case DX_RET_BUSY:
    case DX_RET_OSFAULT:
    default:
        return CRYS_FATAL_ERROR;
    }
}

static enum sep_hash_mode Crys2SepHashMode(CRYS_HASH_OperationMode_t OperationMode)
{
    enum sep_hash_mode result;

    switch (OperationMode) {
    case CRYS_HASH_SHA1_mode:
        result = SEP_HASH_SHA1;
        break;
    case CRYS_HASH_SHA224_mode:
        result = SEP_HASH_SHA224;
        break;
    case CRYS_HASH_SHA256_mode:
        result = SEP_HASH_SHA256;
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case CRYS_HASH_SHA384_mode:
        result = SEP_HASH_SHA384;
        break;
    case CRYS_HASH_SHA512_mode:
        result = SEP_HASH_SHA512;
        break;
#endif
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
    case CRYS_HASH_MD5_mode:
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
 * This function initializes the HMAC machine on the CRYS level.
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
 * @param[in] OperationMode - The operation mode: MD5 or SHA1.
 *
 * @param[in] key_ptr - The pointer to the user's key buffer,
 *            or its digest (if larger than the hash block size).
 *
 * @param[in] keySize - The size of the received key. Must not exceed the associated
 *                      hash block size. For larger keys the caller must provide
 *                      a hash digest of the key as the actual key.
 *
 * @return CRYSError_t - On success the function returns the value CRYS_OK,
 *            and on failure a non-ZERO error.
 *
 */
CIMPORT_C CRYSError_t CRYS_HMAC_Init(CRYS_HMACUserContext_t *ContextID_ptr, CRYS_HASH_OperationMode_t OperationMode,
                                     uint8_t *key_ptr, uint16_t keySize)
{
    struct sep_ctx_hmac *pHmacContext;
    CRYS_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = DX_RET_OK;
    uint32_t HashBlockSize;
    CRYSError_t error = CRYS_OK;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check if the key pointer is valid */
    if (key_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_KEY_POINTER_ERROR;
    }

    /* check if the operation mode is legal and set hash block size */
    switch (OperationMode) {
    case CRYS_HASH_SHA1_mode:
    case CRYS_HASH_SHA224_mode:
    case CRYS_HASH_SHA256_mode:
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
    case CRYS_HASH_MD5_mode:
#endif
        HashBlockSize = CRYS_HASH_BLOCK_SIZE_IN_BYTES;
        break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
    case CRYS_HASH_SHA384_mode:
    case CRYS_HASH_SHA512_mode:
        HashBlockSize = CRYS_HASH_SHA512_BLOCK_SIZE_IN_BYTES;
        break;
#endif
    default:
        return CRYS_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check if the key size is valid */
    if (keySize == 0) {
        return CRYS_HMAC_UNVALID_KEY_SIZE_ERROR;
    }

    /* check validity for priv */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ, key_ptr, keySize) ||
        DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, ContextID_ptr, sizeof(CRYS_HMACUserContext_t))) {
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct sep_ctx_hmac *)DX_InitUserCtxLocation(ContextID_ptr->buff, sizeof(CRYS_HMACUserContext_t),
                                                                 sizeof(struct sep_ctx_hmac));
    if (pHmacContext == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pHmacPrivContext =
        (CRYS_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    pHmacContext->alg                      = SEP_CRYPTO_ALG_HMAC;
    pHmacContext->mode                     = Crys2SepHashMode(OperationMode);
    pHmacPrivContext->isLastBlockProcessed = 0;

    if (keySize > HashBlockSize) {
        error = CRYS_HASH(OperationMode, key_ptr, keySize,
                          (uint32_t *)pHmacContext->k0); /* Write the result into th context */

        if (error != CRYS_OK)
            return symRc;

        /* update the new key size according to the mode */
        switch (OperationMode) {
        case CRYS_HASH_SHA1_mode:
            keySize = CRYS_HASH_SHA1_DIGEST_SIZE_IN_BYTES;
            break;
        case CRYS_HASH_SHA224_mode:
            keySize = CRYS_HASH_SHA224_DIGEST_SIZE_IN_BYTES;
            break;
        case CRYS_HASH_SHA256_mode:
            keySize = CRYS_HASH_SHA256_DIGEST_SIZE_IN_BYTES;
            break;
#ifdef DX_CONFIG_HASH_SHA_512_SUPPORTED
        case CRYS_HASH_SHA384_mode:
            keySize = CRYS_HASH_SHA384_DIGEST_SIZE_IN_BYTES;
            break;
        case CRYS_HASH_SHA512_mode:
            keySize = CRYS_HASH_SHA512_DIGEST_SIZE_IN_BYTES;
            break;
#endif
#ifdef DX_CONFIG_HASH_MD5_SUPPORTED
        case CRYS_HASH_MD5_mode:
            keySize = CRYS_HASH_MD5_DIGEST_SIZE_IN_BYTES;
            break;
#endif
        default:
            return CRYS_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
        }
    } /* end of key larger then 64 bytes case */
    else {
        DX_PAL_MemCopy((uint8_t *)pHmacContext->k0, key_ptr, keySize);
    }
    pHmacContext->k0_size = keySize;

    symRc = SymDriverAdaptorInit((struct sep_ctx_generic *)pHmacContext);
    return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysHmacErr);
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
 * @return CRYSError_t - On success the function returns CRYS_OK,
 *            and on failure a non-ZERO error.
 */

CIMPORT_C CRYSError_t CRYS_HMAC_Update(CRYS_HMACUserContext_t *ContextID_ptr, uint8_t *DataIn_ptr, uint32_t DataInSize)
{
    struct sep_ctx_hmac *pHmacContext;
    CRYS_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = DX_RET_OK;
    uint32_t blockSizeBytes;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal and the size is not 0 return an error */
    if ((DataIn_ptr == DX_NULL) && DataInSize) {
        return CRYS_HMAC_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the data size is zero no need to execute an update , return CRYS_OK */
    if (DataInSize == 0) {
        return CRYS_OK;
    }

    /* check validity for priv */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, ContextID_ptr, sizeof(CRYS_HMACUserContext_t))) {
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct sep_ctx_hmac *)DX_GetUserCtxLocation(ContextID_ptr->buff, sizeof(CRYS_HMACUserContext_t));
    if (pHmacContext == NULL)
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;

    pHmacPrivContext =
        (CRYS_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (pHmacPrivContext->isLastBlockProcessed != 0) {
        return CRYS_HMAC_LAST_BLOCK_ALREADY_PROCESSED_ERROR;
    }

    blockSizeBytes = GetHmacBlocktSize(pHmacContext->mode);
    if ((DataInSize % blockSizeBytes) == 0) {
        symRc = SymDriverAdaptorProcess((struct sep_ctx_generic *)pHmacContext, DataIn_ptr, NULL, DataInSize);
        if (symRc != DX_RET_OK) {
            return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysHmacErr);
        }
    } else { /* this is the last block */
        pHmacPrivContext->isLastBlockProcessed = 1;
        symRc = SymDriverAdaptorFinalize((struct sep_ctx_generic *)pHmacContext, DataIn_ptr, NULL, DataInSize);
        if (symRc != DX_RET_OK) {
            return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysHmacErr);
        }
    }
    return CRYS_OK;
}

/*
 * This function finalizes the HMAC processing of a data block.
 * The function receives as input a handle to the HMAC Context that was previously initialized
 * by a CRYS_HMAC_Init function or by a CRYS_HMAC_Update function.
 * This function finishes the HASH operation on the ipad and text, and then
 * executes a new HASH operation with the key XOR opad and the previous HASH operation result.
 *
 *  @param[in] ContextID_ptr - A pointer to the HMAC context buffer allocated by the user
 *                       that is used for the HMAC machine operation.
 *
 *  @retval HmacResultBuff - A pointer to the target buffer where the
 *                       HMAC result stored in the context is loaded to.
 *
 * @return CRYSError_t - On success the function returns CRYS_OK,
 *            and on failure a non-ZERO error.
 */
CIMPORT_C CRYSError_t CRYS_HMAC_Finish(CRYS_HMACUserContext_t *ContextID_ptr, CRYS_HASH_Result_t HmacResultBuff)
{
    struct sep_ctx_hmac *pHmacContext;
    CRYS_HMACPrivateContext_t *pHmacPrivContext;
    int symRc = DX_RET_OK;
    uint32_t hmacDigesSize;

    /* if the users context ID pointer is DX_NULL return an error */
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (HmacResultBuff == DX_NULL) {
        return CRYS_HMAC_INVALID_RESULT_BUFFER_POINTER_ERROR;
    }

    /* check validity for priv */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, ContextID_ptr, sizeof(CRYS_HMACUserContext_t))) {
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pHmacContext = (struct sep_ctx_hmac *)DX_GetUserCtxLocation(ContextID_ptr->buff, sizeof(CRYS_HMACUserContext_t));
    if (pHmacContext == NULL)
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;

    pHmacPrivContext =
        (CRYS_HMACPrivateContext_t *)&(((uint32_t *)pHmacContext)[CRYS_HMAC_USER_CTX_ACTUAL_SIZE_IN_WORDS - 1]);

    if (pHmacPrivContext->isLastBlockProcessed == 0) {
        symRc = SymDriverAdaptorFinalize((struct sep_ctx_generic *)pHmacContext, NULL, NULL, 0);
        if (symRc != DX_RET_OK) {
            return DX_CRYS_RETURN_ERROR(symRc, 0, SymAdaptor2CrysHmacErr);
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
        return CRYS_HMAC_ILLEGAL_OPERATION_MODE_ERROR;
    }

    DX_PAL_MemCopy(HmacResultBuff, pHmacContext->digest, hmacDigesSize);
    return CRYS_OK;
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
 * @return CRYSError_t - On success CRYS_OK is returned, on failure a
 *                        value MODULE_* crys_hash_error.h
 */
CEXPORT_C CRYSError_t CRYS_HMAC_Free(CRYS_HMACUserContext_t *ContextID_ptr)
{
    if (ContextID_ptr == DX_NULL) {
        return CRYS_HMAC_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check validity for priv */
    if (DxCcAcl_IsBuffAccessOk(ACCESS_READ_WRITE, ContextID_ptr, sizeof(CRYS_HMACUserContext_t))) {
        return CRYS_HMAC_ILLEGAL_PARAMS_ERROR;
    }

    DX_PAL_MemSetZero(ContextID_ptr, sizeof(CRYS_HMACUserContext_t));

    return CRYS_OK;
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
 * @param[in] OperationMode - The operation mode : MD5 or SHA1.
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
 * @return CRYSError_t on success the function returns CRYS_OK else non ZERO error.
 *
 */
CIMPORT_C CRYSError_t CRYS_HMAC(CRYS_HASH_OperationMode_t OperationMode, uint8_t *key_ptr, uint16_t keySize,
                                uint8_t *DataIn_ptr, uint32_t DataSize, CRYS_HASH_Result_t HmacResultBuff)
{
    CRYS_HMACUserContext_t UserContext;
    CRYSError_t Error = CRYS_OK;

    Error = CRYS_HMAC_Init(&UserContext, OperationMode, key_ptr, keySize);
    if (Error != CRYS_OK) {
        goto end;
    }

    Error = CRYS_HMAC_Update(&UserContext, DataIn_ptr, DataSize);
    if (Error != CRYS_OK) {
        goto end;
    }
    Error = CRYS_HMAC_Finish(&UserContext, HmacResultBuff);

end:
    return Error;
}
