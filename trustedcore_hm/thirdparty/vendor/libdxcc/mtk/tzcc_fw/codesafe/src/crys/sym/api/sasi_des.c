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
#include "sasi_des.h"
#include "sasi_des_error.h"
#include "sym_adaptor_driver.h"
#include "dma_buffer.h"
#include "ssi_error.h"
#include "sasi_context_relocation.h"
#include "sasi_fips_defs.h"
#include "sasi_des_data.h"

#if (SaSi_DES_USER_CTX_SIZE_IN_WORDS < SASI_DRV_CTX_SIZE_WORDS)
#error SaSi_DES_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

#define DES_MAX_BLOCK_SIZE 0x100000

typedef struct _DesSingleKey {
    uint8_t key[SaSi_DES_KEY_SIZE_IN_BYTES];
} DesSingleKey;

static const DesSingleKey DesWeakKeysTable[] = NIST_TDES_WEAK_KEYS_LIST;
#define DES_NUM_OF_WEAK_KEYS (sizeof(DesWeakKeysTable) / sizeof(DesSingleKey))

static SaSiError_t DesVerifyWeakKeys(SaSi_DES_Key_t *key, SaSi_DES_NumOfKeys_t numOfKeys)
{
    uint32_t i = 0;

    /*
    ARM TrustZone CryptoCell-710 TEE System Specification, VERSION 1.61 (CCS_FIPS-9):
    The 3DES implementation should include 2 keys and 3 keys 3DES verification to SP 800-67
    */
    if (numOfKeys != SaSi_DES_3_KeysInUse) {
        return SaSi_OK;
    }

    if ((SaSi_PalMemCmp(key->key1, key->key2, SaSi_DES_KEY_SIZE_IN_BYTES) == 0) ||
        (SaSi_PalMemCmp(key->key2, key->key3, SaSi_DES_KEY_SIZE_IN_BYTES) == 0)) {
        return SaSi_DES_ILLEGAL_PARAMS_ERROR;
    }

    /*
    ARM TrustZone CryptoCell-710 TEE System Specification, VERSION 1.61 (CCS_FIPS-8):
    The 3DES implementation should include weak keys verification according to SP 800-67
    */
    for (i = 0; i < DES_NUM_OF_WEAK_KEYS; ++i) {
        if ((SaSi_PalMemCmp(DesWeakKeysTable[i].key, key->key1, SaSi_DES_KEY_SIZE_IN_BYTES) == 0) ||
            (SaSi_PalMemCmp(DesWeakKeysTable[i].key, key->key2, SaSi_DES_KEY_SIZE_IN_BYTES) == 0) ||
            (SaSi_PalMemCmp(DesWeakKeysTable[i].key, key->key3, SaSi_DES_KEY_SIZE_IN_BYTES) == 0)) {
            return SaSi_DES_ILLEGAL_PARAMS_ERROR;
        }
    }

    /*
    ARM TrustZone CryptoCell-710 TEE System Specification, VERSION 1.61 (CCS_FIPS-8 and CCS_FIPS-9):
    in any case of weak key the operation should be stopped and error should be return (without changing the FIPS state
    to error).
    */

    return SaSi_OK;
}

/* !
 * Converts Symmetric Adaptor return code to SaSi error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return SaSiError_t one of SaSi_* error codes defined in sasi_error.h
 */
static SaSiError_t SymAdaptor2SasiDesErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
    case SASI_RET_UNSUPP_ALG:
        return SaSi_DES_IS_NOT_SUPPORTED;
    case SASI_RET_UNSUPP_ALG_MODE:
    case SASI_RET_UNSUPP_OPERATION:
        return SaSi_DES_ILLEGAL_OPERATION_MODE_ERROR;
    case SASI_RET_INVARG:
    case SASI_RET_INVARG_QID:
        return SaSi_DES_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_KEY_SIZE:
        return SaSi_DES_ILLEGAL_NUM_OF_KEYS_ERROR;
    case SASI_RET_INVARG_CTX_IDX:
        return SaSi_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    case SASI_RET_INVARG_CTX:
        return SaSi_DES_USER_CONTEXT_CORRUPTED_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SaSi_DES_DATA_IN_POINTER_INVALID_ERROR;
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

static enum sep_cipher_mode MakeSepDesMode(SaSi_DES_OperationMode_t OperationMode)
{
    enum sep_cipher_mode result;

    switch (OperationMode) {
    case SaSi_DES_ECB_mode:
        result = SEP_CIPHER_ECB;
        break;
    case SaSi_DES_CBC_mode:
        result = SEP_CIPHER_CBC;
        break;
    default:
        result = SEP_CIPHER_NULL_MODE;
    }

    return result;
}

/*
 * @brief This function is used to initialize the DES machine.
 *        To operate the DES machine, this should be the first function called.
 *
 * @param[in] ContextID_ptr  - A pointer to the DES context buffer allocated by the user
 *                       that is used for the DES machine operation.
 *
 * @param[in,out] IV_ptr - The buffer of the IV.
 *                          In ECB mode this parameter is not used.
 *                          In CBC this parameter should contain the IV values.
 *
 * @param[in] Key_ptr - A pointer to the user's key buffer.
 *
 * @param[in] NumOfKeys - The number of keys used: 1, 2, or 3 (defined in the enum).
 *
 * @param[in] EncryptDecryptFlag - A flag that determines whether the DES should perform
 *                           an Encrypt operation (0) or a Decrypt operation (1).
 *
 * @param[in] OperationMode - The operation mode: ECB or CBC.
 *
 *
 * @return SaSiError_t - On success the value SaSi_OK is returned,
 *                        and on failure a value from sasi_error.h
 */

CIMPORT_C SaSiError_t SaSi_DES_Init_MTK(SaSi_DESUserContext_t *ContextID_ptr, SaSi_DES_Iv_t IV_ptr,
                                        SaSi_DES_Key_t *Key_ptr, SaSi_DES_NumOfKeys_t NumOfKeys,
                                        SaSi_DES_EncryptMode_t EncryptDecryptFlag,
                                        SaSi_DES_OperationMode_t OperationMode)
{
    int symRc = SASI_RET_OK;

    /* pointer on SEP DES context struct */
    struct drv_ctx_cipher *pDesContext;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* ............... checking the parameters validity ................... */
    /* -------------------------------------------------------------------- */

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check if the operation mode is legal */
    if (OperationMode >= SaSi_DES_NumOfModes) {
        return SaSi_DES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* if the operation mode selected is CBC then check the validity of
      the IV counter pointer */
    if ((OperationMode == SaSi_DES_CBC_mode) && (IV_ptr == NULL)) {
        return SaSi_DES_INVALID_IV_PTR_ON_NON_ECB_MODE_ERROR;
    }

    /* If the number of keys is invalid return an error */
    if ((NumOfKeys >= SaSi_DES_NumOfKeysOptions) || (NumOfKeys == 0)) {
        return SaSi_DES_ILLEGAL_NUM_OF_KEYS_ERROR;
    }

    /* check the validity of the key pointer */
    if (Key_ptr == NULL) {
        return SaSi_DES_INVALID_KEY_POINTER_ERROR;
    }

    /* Check the Encrypt / Decrypt flag validity */
    if (EncryptDecryptFlag >= SaSi_DES_EncryptNumOfOptions) {
        return SaSi_DES_INVALID_ENCRYPT_MODE_ERROR;
    }

    if (DesVerifyWeakKeys(Key_ptr, NumOfKeys) != SaSi_OK) {
        return SaSi_DES_ILLEGAL_PARAMS_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pDesContext = (struct drv_ctx_cipher *)SaSi_InitUserCtxLocation(ContextID_ptr->buff, sizeof(SaSi_DESUserContext_t),
                                                                    sizeof(struct drv_ctx_cipher));
    if (pDesContext == NULL) {
        return SaSi_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    pDesContext->alg       = DRV_CRYPTO_ALG_DES;
    pDesContext->mode      = MakeSepDesMode(OperationMode);
    pDesContext->direction = (enum sep_crypto_direction)EncryptDecryptFlag;
    pDesContext->key_size  = NumOfKeys * SASI_DRV_DES_BLOCK_SIZE;

    SaSi_PalMemCopy(pDesContext->key, Key_ptr, pDesContext->key_size);

    if (pDesContext->mode == SEP_CIPHER_CBC) {
        SaSi_PalMemCopy(pDesContext->block_state, IV_ptr, SaSi_DES_IV_SIZE_IN_BYTES);
    }

    symRc = SymDriverAdaptorInit((struct drv_ctx_generic *)pDesContext);
    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiDesErr);
}

/*
 * @brief This function is used to process a block on the DES machine.
 *        This function should be called after the SaSi_DES_Init_MTK function was called.
 *
 *
 * @param[in] ContextID_ptr - a pointer to the DES context buffer allocated by the user that
 *                       is used for the DES machine operation. this should be the same context that was
 *                       used on the previous call of this session.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the DES. The pointer does
 *                         not need to be aligned.
 *
 * @param[in] DataInSize - The size of the input data in bytes: must be not 0 and must be multiple
 *                         of 8 bytes.
 *
 * @param[in/out] DataOut_ptr - The pointer to the buffer of the output data from the DES. The pointer does not
 *                              need to be aligned.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* sasi_des_error.h
 */
CIMPORT_C SaSiError_t SaSi_DES_Block_MTK(SaSi_DESUserContext_t *ContextID_ptr, uint8_t *DataIn_ptr, uint32_t DataInSize,
                                         uint8_t *DataOut_ptr)
{
    int symRc = SASI_RET_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* pointer on SEP DES context struct */
    struct drv_ctx_cipher *pDesContext;
    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* if the users Data In pointer is illegal return an error */
    if (DataIn_ptr == NULL) {
        return SaSi_DES_DATA_IN_POINTER_INVALID_ERROR;
    }

    /* if the users Data Out pointer is illegal return an error */
    if (DataOut_ptr == NULL) {
        return SaSi_DES_DATA_OUT_POINTER_INVALID_ERROR;
    }

    /* data size must be a positive number and a block size mult */
    if (((DataInSize % SaSi_DES_BLOCK_SIZE_IN_BYTES) != 0) || (DataInSize == 0)) {
        return SaSi_DES_DATA_SIZE_ILLEGAL;
    }

    /* max size validation */
    if (DataInSize > DES_MAX_BLOCK_SIZE) {
        return SaSi_DES_DATA_SIZE_ILLEGAL;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pDesContext = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(ContextID_ptr->buff);

    symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pDesContext, DataIn_ptr, DataOut_ptr, DataInSize);
    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SasiDesErr);
}

/*
 * @brief This function is used to end the DES processing session.
 *        It is the last function called for the DES process.
 *
 *
 * @param[in] ContextID_ptr  - A pointer to the DES context buffer allocated by the user that
 *                       is used for the DES machine operation. this should be the
 *                       same context that was used on the previous call of this session.
 *
 * @return SaSiError_t - On success the value SaSi_OK is returned,
 *                        and on failure a value from sasi_error.h
 */
CIMPORT_C SaSiError_t SaSi_DES_Free_MTK(SaSi_DESUserContext_t *ContextID_ptr)
{
    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* if the users context ID pointer is NULL return an error */
    if (ContextID_ptr == NULL) {
        return SaSi_DES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    SaSi_PalMemSetZero(ContextID_ptr, sizeof(SaSi_DESUserContext_t));

    return SaSi_OK;
}

/*
 * @brief This function is used to operate the DES machine in one integrated operation.
 *
 *        The actual macros that will be used by the users are:
 *
 *
 * @param[in,out] IVCounter_ptr - this parameter is the buffer of the IV or counters on mode CTR.
 *                          On ECB mode this parameter has no use.
 *                          On CBC mode this parameter should containe the IV values.
 *
 * @param[in] Key_ptr - a pointer to the users key buffer.
 *
 * @param[in] KeySize - Thenumber of keys used by the DES as defined in the enum.
 *
 * @param[in] EncryptDecryptFlag - This flag determains if the DES shall perform an Encrypt operation [0] or a
 *                           Decrypt operation [1].
 *
 * @param[in] OperationMode - The operation mode : ECB or CBC.
 *
 * @param[in] DataIn_ptr - The pointer to the buffer of the input data to the DES. The pointer does
 *                         not need to be aligned.
 *
 * @param[in] DataInSize - The size of the input data in bytes: must be not 0 and must be multiple
 *                         of 8 bytes.
 *
 * @param[in/out] DataOut_ptr - SaSi_DES_BLOCK_SIZE_IN_BYTES The pointer to the
 *                  buffer of the output data from the DES. The
 *                  pointer does not need to be aligned.
 *
 * @return SaSiError_t - On success SaSi_OK is returned, on failure a
 *                        value MODULE_* sasi_des_error.h
 *
 */
CIMPORT_C SaSiError_t SaSi_DES_MTK(SaSi_DES_Iv_t IV_ptr, SaSi_DES_Key_t *Key_ptr, SaSi_DES_NumOfKeys_t NumOfKeys,
                                   SaSi_DES_EncryptMode_t EncryptDecryptFlag, SaSi_DES_OperationMode_t OperationMode,
                                   uint8_t *DataIn_ptr, uint32_t DataInSize, uint8_t *DataOut_ptr)
{
    SaSi_DESUserContext_t UserContext;
    SaSiError_t Error = SaSi_OK;

    /* if no data to process -we're done */
    if (DataInSize == 0) {
        goto end;
    }

    Error = SaSi_DES_Init_MTK(&UserContext, IV_ptr, Key_ptr, NumOfKeys, EncryptDecryptFlag, OperationMode);
    if (Error != SaSi_OK) {
        goto end;
    }

    Error = SaSi_DES_Block_MTK(&UserContext, DataIn_ptr, DataInSize, DataOut_ptr);
    if (Error != SaSi_OK) {
        goto end;
    }

end:
    (void)SaSi_DES_Free_MTK(&UserContext);

    return Error;
}
