/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SaSi_API

#include "sasi_aesccm.h"
#include "sasi_aesccm_error.h"
#include "aead.h"
#include "ssi_crypto_ctx.h"
#include "sym_adaptor_driver.h"
#include "ssi_pal_mem.h"
#include "dma_buffer.h"
#include "ssi_error.h"
#include "sasi_context_relocation.h"
#include "sasi_fips_defs.h"

/* *********************** Defines **************************** */
#if (SaSi_AESCCM_USER_CTX_SIZE_IN_WORDS < SASI_DRV_CTX_SIZE_WORDS)
#error SaSi_AESCCM_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#define SaSi_AESCCM_USER_CTX_ACTUAL_SIZE_IN_WORDS ((SaSi_AESCCM_USER_CTX_SIZE_IN_WORDS - 3) / 2)

/* *********************** Type definitions ******************** */
#define AESCCM_PRIVATE_CONTEXT_SIZE_WORDS 1

typedef struct SaSi_AESCCMPrivateContext {
    uint32_t isA0BlockProcessed;
} SaSi_AESCCMPrivateContext_t;

/* *********************** Private Functions ******************** */

/* !
 * Converts Symmetric Adaptor return code to SaSi error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return SaSiError_t one of SaSi_* error codes defined in sasi_error.h
 */
static SaSiError_t SymAdaptor2SasiAesCcmErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
    case SASI_RET_UNSUPP_ALG:
    case SASI_RET_UNSUPP_ALG_MODE:
        return SaSi_AESCCM_IS_NOT_SUPPORTED;
    case SASI_RET_INVARG:
    case SASI_RET_INVARG_QID:
        return SaSi_AESCCM_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_KEY_SIZE:
        return SaSi_AESCCM_ILLEGAL_KEY_SIZE_ERROR;
    case SASI_RET_INVARG_CTX_IDX:
        return SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    case SASI_RET_INVARG_CTX:
        return SaSi_AESCCM_USER_CONTEXT_CORRUPTED_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SaSi_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR;
    case SASI_RET_NOMEM:
        return SaSi_OUT_OF_RESOURCE_ERROR;
    case SASI_RET_INVARG_INCONSIST_DMA_TYPE:
        return SaSi_AESCCM_ILLEGAL_DMA_BUFF_TYPE_ERROR;
    case SASI_RET_UNSUPP_OPERATION:
    case SASI_RET_PERM:
    case SASI_RET_NOEXEC:
    case SASI_RET_BUSY:
    case SASI_RET_OSFAULT:
    default:
        return SaSi_FATAL_ERROR;
    }
}

/* !
 * Format AES-CCM Block A0 according to the given header length
 *
 * \param pA0Buff A0 block buffer
 * \param headerSize The actual header size
 *
 * \return uint32_t Number of bytes encoded
 */
static uint32_t FormatCcmA0(uint8_t *pA0Buff, uint32_t headerSize)
{
    uint32_t len = 0;

    if (headerSize < ((1UL << 16) - (1UL << 8))) {
        len = 2;

        pA0Buff[0] = (headerSize >> 8) & 0xFF;
        pA0Buff[1] = headerSize & 0xFF;
    } else {
        len = 6;

        pA0Buff[0] = 0xFF;
        pA0Buff[1] = 0xFE;
        pA0Buff[2] = (headerSize >> 24) & 0xFF;
        pA0Buff[3] = (headerSize >> 16) & 0xFF;
        pA0Buff[4] = (headerSize >> 8) & 0xFF;
        pA0Buff[5] = headerSize & 0xFF;
    }

    return len;
}

/*
 * @brief This function transfers the AESCCM_init function parameters from SaSi-SEP to
 *        SEP-Driver and backwards for operating AESCCM_init.
 *
 * @param[in] ContextID_ptr - A pointer to the AESCCM context buffer, that is allocated by the user
 *                            and is used for the AESCCM operations.
 * @param[in] EncrDecrMode  - Enumerator variable defining operation mode (0 - encrypt; 1 - decrypt).
 * @param[in] CCM_Key       - A buffer, containing the AESCCM key passed by user (predefined size 128 bits).
 * @param[in] KeySizeID     - An enum parameter, defines size of used key (128, 192, 256).
 * * @param[in] AdataSize     - Full size of additional data in bytes, which must be processed.
 *                            Limitation in our implementation is: AdataSize < 2^32. If Adata is absent,
 *                            then AdataSize = 0.
 * @param[in] TextSize      - The full size of text data (in bytes), which must be processed by CCM.
 *
 * @param[in] N_ptr           - A pointer to Nonce - unique value assigned to all data passed into CCM.
 *                            Bytes order - big endian form (MSB is the first).
 * @param[in] SizeOfN       - The size of the user passed Nonce (in bytes).
 *                  It is an element of {7,8,9,10,11,12,13}.
 * @param[in] SizeOfT       - Size of AESCCM MAC output T in bytes. Valid values: [4,6,8,10,12,14,16].
 *
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error according to SaSi_AESCCM_error.h
 *
 */
SaSiError_t SaSi_AESCCM_Init_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, SaSiAesEncryptMode_t EncrDecrMode,
                                 SaSi_AESCCM_Key_t CCM_Key, SaSi_AESCCM_KeySize_t KeySizeId, uint32_t AdataSize,
                                 uint32_t TextSize, uint8_t *N_ptr, uint8_t SizeOfN, uint8_t SizeOfT)
{
    uint32_t keySizeInBytes;
    struct drv_ctx_aead *pAeadContext;
    SaSi_AESCCMPrivateContext_t *pAesCcmPrivContext;
    uint8_t QFieldSize = 15 - SizeOfN;
    int symRc          = SASI_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check key pointer (unless secret key is used) */
    if (CCM_Key == NULL) {
        return SaSi_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR;
    }

    /* check Nonce pointer */
    if (N_ptr == NULL) {
        return SaSi_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR;
    }

    /* check the Q field size: according to our implementation QFieldSize <= 4 */
    if ((QFieldSize < 2) || (QFieldSize > 8)) {
        return SaSi_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
    }

    /* Check that TextSize fits into Q field (i.e., there are enough bits) */
    if ((BITMASK(QFieldSize * 8) & TextSize) != TextSize) {
        return SaSi_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
    }

    /* check Nonce size. Note: QFieldSize + SizeOfN == 15 */
    if ((SizeOfN < 7) || (SizeOfN != (15 - QFieldSize))) {
        return SaSi_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
    }

    /* check CCM MAC size: [4,6,8,10,12,14,16] */
    if ((SizeOfT < 4) || (SizeOfT > 16) || ((SizeOfT & 1) != 0)) {
        return SaSi_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
    }

    /* check Key size ID and get Key size in bytes */
    switch (KeySizeId) {
    case SaSi_AES_Key128BitSize:
        keySizeInBytes = 16;
        break;
    case SaSi_AES_Key192BitSize:
        keySizeInBytes = 24;
        break;
    case SaSi_AES_Key256BitSize:
        keySizeInBytes = 32;
        break;
    default:
        return SaSi_AESCCM_ILLEGAL_KEY_SIZE_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *)SaSi_InitUserCtxLocation(
        ContextID_ptr->buff, sizeof(SaSi_AESCCM_UserContext_t), sizeof(struct drv_ctx_aead));
    if (pAeadContext == NULL) {
        return SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pAesCcmPrivContext = (SaSi_AESCCMPrivateContext_t *)&(
        ((uint32_t *)pAeadContext)[SaSi_AESCCM_USER_CTX_ACTUAL_SIZE_IN_WORDS - AESCCM_PRIVATE_CONTEXT_SIZE_WORDS]);
    /* clear private context fields */
    pAesCcmPrivContext->isA0BlockProcessed = 0;

    /* init. CCM context */
    pAeadContext->alg       = DRV_CRYPTO_ALG_AEAD;
    pAeadContext->mode      = SEP_CIPHER_CCM;
    pAeadContext->direction = (enum sep_crypto_direction)EncrDecrMode;
    pAeadContext->key_size  = keySizeInBytes;
    SaSi_PalMemCopy(pAeadContext->key, CCM_Key, keySizeInBytes);
    pAeadContext->header_size = AdataSize;
    pAeadContext->nonce_size  = SizeOfN;
    SaSi_PalMemCopy(pAeadContext->nonce, N_ptr, SizeOfN);
    pAeadContext->tag_size  = SizeOfT;
    pAeadContext->text_size = TextSize;

    symRc = SymDriverAdaptorInit((struct drv_ctx_generic *)pAeadContext);
    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
}

/*
 * @brief This function transfers the SaSi_AESCCM_BlockAdata_MTK function parameters from SaSi-SEP to
 *        SEP-Driver and backwards for operating SaSi_AESCCM_BlockAdata_MTK on SEP.
 *
 * @param[in] ContextID_ptr - A pointer to the AESCCM context buffer allocated by the user that
 *                            is used for the AESCCM machine operation. This should be the same
 *                            context that was used on the previous call of this session.
 * @param[in] DataIn_ptr - A pointer to the buffer of the input additional data.
 *                         The pointer does not need to be aligned.
 * @param[in] DataInSize   - A size of the additional data in bytes.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure an error according to
 *                       SaSi_AESCCM_error.h
 *   Restrictions:
 *    1. The input data (DataIn_ptr) may reside in host memory processor and recognized as
 *       direct DMA object or reside in SEP SRAM or D-Cache and referenced by a simple direct address.
 *   2. The input data cannot be partially processed by multiple
 *      invocations.
 */
SaSiError_t SaSi_AESCCM_BlockAdata_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                       uint32_t DataInSize)
{
    struct drv_ctx_aead *pAeadContext;
    uint32_t headerA0BorrowLen, actualHeaderLen, headerA0MetaDataLen;
    SaSi_AESCCMPrivateContext_t *pAesCcmPrivContext;
    int symRc                                      = SASI_RET_OK;
    uint8_t pA0Block[SASI_AES_BLOCK_SIZE_IN_BYTES] = { 0 };

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL) {
        return SaSi_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the data size is illegal return an error */
    if (DataInSize == 0) {
        return SaSi_AESCCM_DATA_IN_SIZE_ILLEGAL;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);

    pAesCcmPrivContext = (SaSi_AESCCMPrivateContext_t *)&(
        ((uint32_t *)pAeadContext)[SaSi_AESCCM_USER_CTX_ACTUAL_SIZE_IN_WORDS - AESCCM_PRIVATE_CONTEXT_SIZE_WORDS]);

    /* additional data may be processed only once */
    if (pAesCcmPrivContext->isA0BlockProcessed == 1) {
        return SaSi_AESCCM_ADATA_WAS_PROCESSED_ERROR;
    }

    /* formate A0 block only once */
    headerA0MetaDataLen = FormatCcmA0(pA0Block, DataInSize);
    headerA0BorrowLen   = min((SASI_AES_BLOCK_SIZE_IN_BYTES - headerA0MetaDataLen), DataInSize);
    actualHeaderLen     = headerA0MetaDataLen + DataInSize;

    /* this is the first Adata block.
     *  Complete to AES block thus A0 = [META DATA 2B/6B | ADATA 14B/10B] */
    SaSi_PalMemCopy(pA0Block + headerA0MetaDataLen, DataIn_ptr, headerA0BorrowLen);

    if (actualHeaderLen <= SASI_AES_BLOCK_SIZE_IN_BYTES) {
        /* given additional data plus header meta data are smaller than AES block size: A0+Adata < 16 */
        symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pAeadContext, pA0Block, NULL, actualHeaderLen);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
        }
    } else {
        /* given additional data plus header meta data are greater than AES block size: A0+Adata > 16 */
        /* process A0 block */
        symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pAeadContext, pA0Block, NULL,
                                        SASI_AES_BLOCK_SIZE_IN_BYTES);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
        }

        /* prepare DMA buffer for rest of data */
        DataIn_ptr += headerA0BorrowLen;

        /* process user remaining additional data */
        symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pAeadContext, DataIn_ptr, NULL,
                                        DataInSize - headerA0BorrowLen);
        if (symRc != SASI_RET_OK) {
            return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
        }
    }

    pAesCcmPrivContext->isA0BlockProcessed = 1;

    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
}

/*
 * @brief This function transfers the SaSi_AESCCM_BlockTextData_MTK function parameters from SaSi-SEP to
 *        SEP-Driver and backwarderrors for operating SaSi_AESCCM_BlockTextData_MTK on SEP.
 *
 * @param[in] ContextID_ptr - A pointer to the AESCCM context buffer allocated by the user that
 *                            is used for the AES machine operation. This should be the same
 *                            context that was used on the previous call of this session.
 * @param[in] DataIn_ptr - A pointer to the buffer of the input data (plain or cipher text).
 *                         The pointer does not need to be aligned.
 * @param[in] DataInSize  - A size of the data block in bytes: must be multiple of 16 bytes and not 0.
 *                          The block of data must be not a last block, that means:
 *                            - on Encrypt mode: DataInSize < CCM_Context->RemainTextSize;
 *                            - on Decrypt mode: DataInSize < CCM_Context->RemainTextSize - SizeOfT;
 * @param[out] DataOut_ptr - A pointer to the output buffer (cipher or plain text).
 *                          The pointer does not need to be aligned.
 *                          Size of the output buffer must be not less, than DataInSize.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                       value MODULE_* SaSi_AESCCM_error.h
 *   Notes:
 *      1. Overlapping of the in-out buffers is not allowed, excluding the in placement case:
 *         DataIn_ptr = DataOut_ptr.
 */
SaSiError_t SaSi_AESCCM_BlockTextData_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                          uint32_t DataInSize, uint8_t *DataOut_ptr)
{
    struct drv_ctx_aead *pAeadContext;
    int symRc = SASI_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL) {
        return SaSi_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the Data In size is 0, return an error */
    if (DataInSize == 0) {
        return SaSi_AESCCM_DATA_IN_SIZE_ILLEGAL;
    }

    /* if the users Data Out pointer is illegal return an error */
    if (DataOut_ptr == NULL) {
        return SaSi_AESCCM_DATA_OUT_POINTER_INVALID_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);

    symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pAeadContext, DataIn_ptr, DataOut_ptr, DataInSize);
    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
}

/*
 * @brief This function transfers the SaSi_AESCCM_BlockLastTextData function parameters from SaSi-SEP to
 *        SEP-Driver and backwards for operating SaSi_AESCCM_BlockLastTextData on SEP.
 *
 * @param[in] ContextID_ptr - A pointer to the AESCCM context buffer, allocated by the user,
 *                          that is used for the AESCCM operations. This should be the same
 *                          context that was used on the previous call of this session.
 * @param[in] DataIn_ptr  - A pointer to the buffer of the input data (plain or cipher text).
 *                          The pointer does not need to be aligned.
 * @param[in] DataInSize  - A size of the data block in bytes. The size must be equal to remaining
 *                          size value, saved in the context.
 * @param[in] DataOut_ptr - A pointer to the output buffer (cipher or plain text). If
 *                          user passes DataInSize 0 bytes the DataOut_ptr may be equal to NULL.
 *                          The pointer does not need to be aligned.
 * @param[in] MacRes -   A pointer to the Mac buffer.
 * @param[out] SizeOfT - size of MAC in bytes as defined in SaSi_AESCCM_Init_MTK function.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                       value MODULE_* SaSi_AESCCM_error.h
 *   Notes:
 *      1. Overlapping of the in-out buffers is not allowed, excluding the in placement case:
 *         DataIn_ptr = DataOut_ptr.
 */
CEXPORT_C SaSiError_t SaSi_AESCCM_Finish_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                             uint32_t DataInSize, uint8_t *DataOut_ptr, SaSi_AESCCM_Mac_Res_t MacRes,
                                             uint8_t *SizeOfT)
{
    struct drv_ctx_aead *pAeadContext;
    int symRc = SASI_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if ((DataIn_ptr == NULL) && (DataInSize != 0)) {
        return SaSi_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the users Data Out pointer is illegal return an error */
    if ((DataOut_ptr == NULL) && (DataInSize != 0)) {
        return SaSi_AESCCM_DATA_OUT_POINTER_INVALID_ERROR;
    }

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if (SizeOfT == NULL) {
        return SaSi_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAeadContext = (struct drv_ctx_aead *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);

    symRc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAeadContext, DataIn_ptr, DataOut_ptr, DataInSize);
    if (symRc != SASI_RET_OK) {
        return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
    }

    /* copy MAC result to context */
    *SizeOfT = pAeadContext->tag_size;

    if (pAeadContext->direction == SEP_CRYPTO_DIRECTION_DECRYPT) {
        if (SaSi_PalMemCmp(MacRes, pAeadContext->mac_state, *SizeOfT)) {
            return SaSi_AESCCM_CCM_MAC_INVALID_ERROR;
        }
    } else { /* SEP_CRYPTO_DIRECTION_ENCRYPT */
        SaSi_PalMemCopy(MacRes, pAeadContext->mac_state, *SizeOfT);
    }

    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiAesCcmErr);
}

/*
 * @brief This function is used to perform the AES_CCM operation in one integrated process.
 *
 *        The function preforms CCM algorithm according to NIST 800-38C by call the SaSi_CCM
 *        Init, Block and Finish functions.
 *
 *        The input-output parameters of the function are the following:
 *
 * @param[in] EncrDecrMode  - Enumerator variable defining operation mode (0 - encrypt; 1 - decrypt).
 * @param[in] CCM_Key       - A buffer, containing the AESCCM key passed by user (predefined size 128 bits).
 * @param[in] KeySizeId     - An ID of AESCCM key size (according to 128, 192, or 256 bits size).
 * @param[in] N_ptr        - A pointer to Nonce - unique value assigned to all data passed into CCM.
 *                            Bytes order - big endian form (MSB is the first).
 * @param[in] SizeOfN       - The size of the user passed Nonce (in bytes).
 *                   It is an element of {7,8,9,10,11,12,13}.
 * @param[in] ADataIn_ptr    - A pointer to the additional data buffer. The pointer does
 *                             not need to be aligned.
 * @param[in] ADataInSize    - The size of the additional data in bytes;
 * @param[in] TextDataIn_ptr - A pointer to the input text data buffer (plain or cipher according to
 *                             encrypt-decrypt mode). The pointer does not need to be aligned.
 * @param[in] TextDataInSize - The size of the input text data in bytes:
 *                               - on encrypt mode: (2^32 - SizeOfT) > DataInSize >= 0;
 *                               - on Decrypt mode: 2^32 > DataInSize >= SizeOfT (SizeOfT from context).
 * @param[out] TextDataOut_ptr - The output text data pointer (cipher or plain text data).
 *
 * @param[in] SizeOfT        - Size of AES-CCM MAC output T in bytes. Valid values: [4,6,8,10,12,14,16].
 *
 * @param[in/out] Mac_Res        -  AES-CCM MAC input/output .
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a value defined in SaSi_AESCCM_error.h
 *
 */
CIMPORT_C SaSiError_t SaSi_AESCCM_MTK(SaSiAesEncryptMode_t EncrDecrMode, SaSi_AESCCM_Key_t CCM_Key,
                                      SaSi_AESCCM_KeySize_t KeySizeId, uint8_t *N_ptr, uint8_t SizeOfN,
                                      uint8_t *ADataIn_ptr, uint32_t ADataInSize, uint8_t *TextDataIn_ptr,
                                      uint32_t TextDataInSize, uint8_t *TextDataOut_ptr, uint8_t SizeOfT,
                                      SaSi_AESCCM_Mac_Res_t MacRes)
{
    SaSiError_t sasiRc = SaSi_OK;
    SaSi_AESCCM_UserContext_t ContextID;

    sasiRc = SaSi_AESCCM_Init_MTK(&ContextID, EncrDecrMode, CCM_Key, KeySizeId, ADataInSize, TextDataInSize, N_ptr,
                                  SizeOfN, SizeOfT);
    if (sasiRc != SaSi_OK) {
        return sasiRc;
    }

    if (ADataInSize > 0) {
        sasiRc = SaSi_AESCCM_BlockAdata_MTK(&ContextID, ADataIn_ptr, ADataInSize);
        if (sasiRc != SaSi_OK) {
            return sasiRc;
        }
    }

    sasiRc = SaSi_AESCCM_Finish_MTK(&ContextID, TextDataIn_ptr, TextDataInSize, TextDataOut_ptr, MacRes, &SizeOfT);
    if (sasiRc != SaSi_OK) {
        if ((EncrDecrMode == SASI_AES_DECRYPT) && (sasiRc == SaSi_AESCCM_CCM_MAC_INVALID_ERROR)) {
            SaSi_PalMemSetZero(TextDataOut_ptr, TextDataInSize);
        }
        return sasiRc;
    }

    return sasiRc;
}
