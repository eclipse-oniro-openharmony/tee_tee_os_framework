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
#include "ssi_hal.h"
#include "ssi_aes.h"
#include "ssi_aes_error.h"
#include "sym_adaptor_driver.h"
#include "cipher.h"
#include "ssi_crypto_ctx.h"
#include "dma_buffer.h"
#include "ssi_error.h"
#include "ssi_crypto_ctx.h"
#include "sasi_context_relocation.h"
#include "ssi_pal_perf.h"
#include "sasi_fips_defs.h"

#define SASI_AES_REQUIRED_SEP_CTX_SIZE 2 * SASI_DRV_CTX_SIZE_WORDS + 3
#define AES_XTS_MAX_BLOCK_SIZE         0x100000

SASI_PAL_COMPILER_ASSERT(SASI_AES_REQUIRED_SEP_CTX_SIZE == SASI_AES_USER_CTX_SIZE_IN_WORDS,
                         "SASI_AES_USER_CTX_SIZE_IN_WORDS is not defined correctly!");

SASI_PAL_COMPILER_ASSERT((uint32_t)SASI_AES_PADDING_NONE == (uint32_t)DRV_PADDING_NONE,
                         "SEP/SaSiAes padding type enum mismatch!");
SASI_PAL_COMPILER_ASSERT((uint32_t)SASI_AES_PADDING_PKCS7 == (uint32_t)DRV_PADDING_PKCS7,
                         "SEP/SaSiAes padding type enum mismatch!");

SASI_PAL_COMPILER_ASSERT((uint32_t)SASI_AES_ENCRYPT == (uint32_t)SEP_CRYPTO_DIRECTION_ENCRYPT,
                         "SEP/SaSiAes direction enum mismatch!");
SASI_PAL_COMPILER_ASSERT((uint32_t)SASI_AES_DECRYPT == (uint32_t)SEP_CRYPTO_DIRECTION_DECRYPT,
                         "SEP/SaSiAes direction enum mismatch!");

#define SASI_LIB_IS_KCST_DISABLE(regVal)                                               \
    do {                                                                               \
        regVal = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_KCST_DISABLE)); \
        regVal = SASI_REG_FLD_GET(0, HOST_KCST_DISABLE, VALUE, regVal);                \
    } while (0)

#define SASI_LIB_IS_KPLT_VALID(regVal)                                               \
    do {                                                                             \
        regVal = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_KPLT_VALID)); \
        regVal = SASI_REG_FLD_GET(0, HOST_KPLT_VALID, VALUE, regVal);                \
    } while (0)

#define SASI_LIB_IS_KCST_VALID(regVal)                                               \
    do {                                                                             \
        regVal = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_KCST_VALID)); \
        regVal = SASI_REG_FLD_GET(0, HOST_KCST_VALID, VALUE, regVal);                \
    } while (0)

/* !
 * Converts Symmetric Adaptor return code to CryptoCell error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return SaSiError_t one of SASI_* error codes defined in ssi_aes_error.h
 */
static SaSiError_t SymAdaptor2SaSiAesErr(int symRetCode, uint32_t errorInfo)
{
    errorInfo = errorInfo;
    switch (symRetCode) {
    case SASI_RET_UNSUPP_ALG:
        return SASI_AES_IS_NOT_SUPPORTED;
    case SASI_RET_UNSUPP_ALG_MODE:
    case SASI_RET_UNSUPP_OPERATION:
        return SASI_AES_ILLEGAL_OPERATION_MODE_ERROR;
    case SASI_RET_INVARG:
    case SASI_RET_INVARG_QID:
        return SASI_AES_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_KEY_SIZE:
        return SASI_AES_ILLEGAL_KEY_SIZE_ERROR;
    case SASI_RET_INVARG_CTX_IDX:
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    case SASI_RET_INVARG_CTX:
        return SASI_AES_USER_CONTEXT_CORRUPTED_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SASI_AES_DATA_IN_POINTER_INVALID_ERROR;
    case SASI_RET_NOMEM:
        return SASI_OUT_OF_RESOURCE_ERROR;
    case SASI_RET_INVARG_INCONSIST_DMA_TYPE:
        return SASI_ILLEGAL_RESOURCE_VAL_ERROR;
    case SASI_RET_PERM:
    case SASI_RET_NOEXEC:
    case SASI_RET_BUSY:
    case SASI_RET_OSFAULT:
    default:
        return SASI_FATAL_ERROR;
    }
}

static enum sep_cipher_mode MakeSepAesMode(SaSiAesOperationMode_t operationMode)
{
    switch (operationMode) {
    case SASI_AES_MODE_ECB:
        return SEP_CIPHER_ECB;
    case SASI_AES_MODE_CBC:
        return SEP_CIPHER_CBC;
    case SASI_AES_MODE_CBC_MAC:
        return SEP_CIPHER_CBC_MAC;
    case SASI_AES_MODE_CTR:
        return SEP_CIPHER_CTR;
    case SASI_AES_MODE_XCBC_MAC:
        return SEP_CIPHER_XCBC_MAC;
    case SASI_AES_MODE_CMAC:
        return SEP_CIPHER_CMAC;
    case SASI_AES_MODE_XTS:
        return SEP_CIPHER_XTS;
    case SASI_AES_MODE_OFB:
        return SEP_CIPHER_OFB;
    case SASI_AES_MODE_CBC_CTS:
        return SEP_CIPHER_CBC_CTS;
    default:
        return SEP_CIPHER_NULL_MODE;
    }

    return SEP_CIPHER_NULL_MODE;
}

static enum drv_crypto_padding_type MakeSepCryptoPaddingType(SaSiAesPaddingType_t type)
{
    // Conversion is not required
    // We force both enums to have the same values using SASI_PAL_COMPILER_ASSERT
    return (enum drv_crypto_padding_type)type;
}
CIMPORT_C SaSiError_t sasi_aes_mac_mode(SaSiAesUserContext_t *pContext, SaSiBool_t *mac_mode)
{
    if (pContext == NULL || mac_mode == NULL)
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;

    struct drv_ctx_cipher *aes_ctx = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(pContext->buff);
    if (aes_ctx == NULL)
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;

    if (aes_ctx->mode == SEP_CIPHER_CBC_MAC || aes_ctx->mode == SEP_CIPHER_XCBC_MAC || aes_ctx->mode == SEP_CIPHER_CMAC)
        *mac_mode = SASI_TRUE;
    else
        *mac_mode = SASI_FALSE;
    return SASI_OK;
}

static enum sep_crypto_direction MakeSepCryptoDirection(SaSiAesEncryptMode_t direction)
{
    // Conversion is not required
    // We force both enums to have the same values using SASI_PAL_COMPILER_ASSERT
    return (enum sep_crypto_direction)direction;
}

static enum drv_crypto_key_type MakeSepAesKeyType(SaSiAesKeyType_t keyType)
{
    switch (keyType) {
    case SASI_AES_USER_KEY:
        return DRV_USER_KEY;
    case SASI_AES_PLATFORM_KEY:
        return DRV_PLATFORM_KEY;
    case SASI_AES_CUSTOMER_KEY:
        return DRV_CUSTOMER_KEY;
    default:
        return DRV_NULL_KEY;
    }
}

CIMPORT_C SaSiError_t SaSi_AesInit(SaSiAesUserContext_t *pContext, SaSiAesEncryptMode_t encryptDecryptFlag,
                                   SaSiAesOperationMode_t operationMode, SaSiAesPaddingType_t paddingType)
{
    struct drv_ctx_cipher *pAesCtx;

    SaSi_PalPerfData_t perfIdx = 0;
    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_INIT);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* checking validity of the input parameters */

    /* if the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* check if the operation mode is legal */
    if (operationMode >= SASI_AES_NUM_OF_OPERATION_MODES) {
        return SASI_AES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    /* check the Encrypt / Decrypt flag validity */
    if (encryptDecryptFlag >= SASI_AES_NUM_OF_ENCRYPT_MODES) {
        return SASI_AES_INVALID_ENCRYPT_MODE_ERROR;
    }

    /* check if the padding type is legal */
    if (paddingType >= SASI_AES_NUM_OF_PADDING_TYPES) {
        return SASI_AES_ILLEGAL_PADDING_TYPE_ERROR;
    }
    /* we support pkcs7 padding only for ECB, CBC, MAC operation modes. */
    if ((paddingType == SASI_AES_PADDING_PKCS7) &&
        ((operationMode != SASI_AES_MODE_ECB) && (operationMode != SASI_AES_MODE_CBC) &&
         (operationMode != SASI_AES_MODE_CBC_MAC))) {
        return SASI_AES_ILLEGAL_PADDING_TYPE_ERROR;
    }

    /* in MAC,XCBC,CMAC modes enable only encrypt mode  */
    if (((operationMode == SASI_AES_MODE_XCBC_MAC) || (operationMode == SASI_AES_MODE_CMAC) ||
         (operationMode == SASI_AES_MODE_CBC_MAC)) &&
        (encryptDecryptFlag != SASI_AES_ENCRYPT)) {
        return SASI_AES_DECRYPTION_NOT_ALLOWED_ON_THIS_MODE;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesCtx = (struct drv_ctx_cipher *)SaSi_InitUserCtxLocation(pContext->buff, sizeof(SaSiAesUserContext_t),
                                                                sizeof(struct drv_ctx_cipher));
    if (pAesCtx == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }
    SaSi_PalMemSetZero(pAesCtx, sizeof(struct drv_ctx_cipher));

    pAesCtx->alg          = DRV_CRYPTO_ALG_AES;
    pAesCtx->mode         = MakeSepAesMode(operationMode);
    pAesCtx->padding_type = MakeSepCryptoPaddingType(paddingType);
    pAesCtx->direction    = MakeSepCryptoDirection(encryptDecryptFlag);

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_INIT);

    return SASI_OK;
}

CIMPORT_C SaSiError_t SaSi_AesSetKey(SaSiAesUserContext_t *pContext, SaSiAesKeyType_t keyType, void *pKeyData,
                                     size_t keyDataSize)
{
    int symRc;
    struct drv_ctx_cipher *pAesCtx;
    SaSiAesUserKeyData_t *pUserKeyData;
    uint32_t regVal;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    SaSi_PalPerfData_t perfIdx = 0;
    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_SET_KEY);

    /* if the users context ID pointer is NULL return an error */
    if (pContext == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesCtx = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(pContext->buff);

    /* TODO: check that AesInit was already called */

    /* update key information in the context */
    pAesCtx->crypto_key_type = MakeSepAesKeyType(keyType);
    if (pAesCtx->crypto_key_type == DRV_NULL_KEY)
        return SASI_AES_KEY_TYPE_NOT_SUPPORTED_ERROR;

    /* case of SASI_AES_USER_KEY */
    if (keyType == SASI_AES_USER_KEY) {
        /* check the validity of the key data pointer */
        if (pKeyData == NULL) {
            return SASI_AES_INVALID_KEY_POINTER_ERROR;
        }

        if (keyDataSize != sizeof(SaSiAesUserKeyData_t)) {
            return SASI_AES_INVALID_KEY_POINTER_ERROR;
        }

        /* casting from void* to SaSiAesUserKeyData_t* */
        pUserKeyData = (SaSiAesUserKeyData_t *)pKeyData;

        /* check key size validity in various modes */
        if (pAesCtx->mode == SEP_CIPHER_XCBC_MAC) {
            if (pUserKeyData->keySize != SEP_AES_128_BIT_KEY_SIZE) {
                /* in XCBC_MAC mode, key size should be only 128 bit */
                return SASI_AES_ILLEGAL_KEY_SIZE_ERROR;
            }
        } else if (pAesCtx->mode == SEP_CIPHER_XTS) {
            if ((pUserKeyData->keySize != SEP_AES_256_BIT_KEY_SIZE) &&
                (pUserKeyData->keySize != 2 * SEP_AES_256_BIT_KEY_SIZE)) {
                /* in XTS mode, key size should be only 256/512 bit */
                return SASI_AES_ILLEGAL_KEY_SIZE_ERROR;
            }
            /* xts weak keys verification */
            if ((pUserKeyData->keySize == SEP_AES_256_BIT_KEY_SIZE) &&
                (SaSi_PalMemCmp(pUserKeyData->pKey, ((uint8_t *)pUserKeyData->pKey) + (SEP_AES_256_BIT_KEY_SIZE >> 1),
                                SEP_AES_256_BIT_KEY_SIZE >> 1) == 0)) {
                return SASI_AES_ILLEGAL_PARAMS_ERROR;
            }
            if ((pUserKeyData->keySize == 2 * SEP_AES_256_BIT_KEY_SIZE) &&
                (SaSi_PalMemCmp(pUserKeyData->pKey, ((uint8_t *)pUserKeyData->pKey) + SEP_AES_256_BIT_KEY_SIZE,
                                SEP_AES_256_BIT_KEY_SIZE) == 0)) {
                return SASI_AES_ILLEGAL_PARAMS_ERROR;
            }

        } else if ((pUserKeyData->keySize != SEP_AES_128_BIT_KEY_SIZE) &&
                   (pUserKeyData->keySize != SEP_AES_192_BIT_KEY_SIZE) &&
                   (pUserKeyData->keySize != SEP_AES_256_BIT_KEY_SIZE)) {
            /* in all other modes, key size should be only 128/192/256 bit */
            return SASI_AES_ILLEGAL_KEY_SIZE_ERROR;
        }

        /* check key pointer validity */
        if (pUserKeyData->pKey == NULL) {
            return SASI_AES_INVALID_KEY_POINTER_ERROR;
        }

        /* Copy the key to the context */
        if (pAesCtx->mode == SEP_CIPHER_XTS) {
            /* Divide by two (we have two keys of the same size) */
            pAesCtx->key_size = pUserKeyData->keySize >> 1;
            SaSi_PalMemCopy(pAesCtx->key, pUserKeyData->pKey, pAesCtx->key_size);
            /* copy second half of the double-key as XEX-key */
            SaSi_PalMemCopy(pAesCtx->xex_key, pUserKeyData->pKey + pAesCtx->key_size, pAesCtx->key_size);
        } else {
            pAesCtx->key_size = pUserKeyData->keySize;
            /* just eliminate KW issue (pAesCtx->key_size is max 32 bytes anyway) */
            pAesCtx->key_size = min(pAesCtx->key_size, SEP_AES_256_BIT_KEY_SIZE);
            /* Copy the key to the context */
            SaSi_PalMemCopy(pAesCtx->key, pUserKeyData->pKey, pAesCtx->key_size);
        }
    } else {
        /* set hw key size to 128b */
        pAesCtx->key_size = SEP_AES_128_BIT_KEY_SIZE;

        /* Verify that devise support hw keys */
        SASI_LIB_IS_KCST_DISABLE(regVal);
        if (regVal) {
            return SASI_RET_UNSUPP_HWKEY;
        }

        switch (keyType) {
        case SASI_AES_PLATFORM_KEY:
            SASI_LIB_IS_KPLT_VALID(regVal);
            if (regVal == 0) {
                return SASI_RET_INV_HWKEY;
            }
            break;
        case SASI_AES_CUSTOMER_KEY:
            SASI_LIB_IS_KCST_VALID(regVal);
            if (regVal == 0) {
                return SASI_RET_INV_HWKEY;
            }
            break;
        default:
            break;
        }
    }

    symRc = SymDriverAdaptorInit((struct drv_ctx_generic *)pAesCtx);

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_SET_KEY);

    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SaSiAesErr);
}

CIMPORT_C SaSiError_t SaSi_AesSetIv(SaSiAesUserContext_t *pContext, SaSiAesIv_t pIV)
{
    struct drv_ctx_cipher *pAesCtx;

    SaSi_PalPerfData_t perfIdx = 0;
    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_SET_IV);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pContext == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesCtx = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(pContext->buff);

    /* TODO: check that AesInit was already called */

    if ((pAesCtx->mode != SEP_CIPHER_CBC) && (pAesCtx->mode != SEP_CIPHER_CTR) && (pAesCtx->mode != SEP_CIPHER_XTS) &&
        (pAesCtx->mode != SEP_CIPHER_CBC_MAC) && (pAesCtx->mode != SEP_CIPHER_CBC_CTS) &&
        (pAesCtx->mode != SEP_CIPHER_OFB)) {
        return SASI_AES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    if (pIV == NULL) {
        return SASI_AES_INVALID_IV_OR_TWEAK_PTR_ERROR;
    }

    SaSi_PalMemCopy(pAesCtx->block_state, pIV, sizeof(SaSiAesIv_t));

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_SET_IV);

    return SASI_OK;
}

CIMPORT_C SaSiError_t SaSi_AesGetIv(SaSiAesUserContext_t *pContext, SaSiAesIv_t pIV)
{
    struct drv_ctx_cipher *pAesCtx;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pContext == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesCtx = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(pContext->buff);

    // TODO: check that AesInit was already called ??

    if ((pAesCtx->mode != SEP_CIPHER_CBC) && (pAesCtx->mode != SEP_CIPHER_CTR) && (pAesCtx->mode != SEP_CIPHER_XTS) &&
        (pAesCtx->mode != SEP_CIPHER_CBC_MAC) && (pAesCtx->mode != SEP_CIPHER_CBC_CTS) &&
        (pAesCtx->mode != SEP_CIPHER_OFB)) {
        return SASI_AES_ILLEGAL_OPERATION_MODE_ERROR;
    }

    if (pIV == NULL) {
        return SASI_AES_INVALID_IV_OR_TWEAK_PTR_ERROR;
    }

    SaSi_PalMemCopy(pIV, pAesCtx->block_state, sizeof(SaSiAesIv_t));

    return SASI_OK;
}

CIMPORT_C SaSiError_t SaSi_AesBlock(SaSiAesUserContext_t *pContext, uint8_t *pDataIn, size_t dataInSize,
                                    uint8_t *pDataOut)
{
    int symRc;
    struct drv_ctx_cipher *pAesCtx;
    void *pOutData = NULL;

    SaSi_PalPerfData_t perfIdx = 0;
    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_BLOCK);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pContext == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesCtx = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(pContext->buff);

    /* TODO: check that key and IV were already set */

    if (pDataIn == NULL) {
        return SASI_AES_DATA_IN_POINTER_INVALID_ERROR;
    }

    if (dataInSize == 0) {
        /* Size zero is not a valid block operation */
        return SASI_AES_DATA_IN_SIZE_ILLEGAL;
    }

    /* check the minimum data size according to mode */
    if ((pAesCtx->mode == SEP_CIPHER_XTS) && (dataInSize < SASI_AES_BLOCK_SIZE_IN_BYTES)) {
        SASI_PAL_LOG_ERR("Invalid XTS data size: %u\n", (unsigned int)dataInSize);
        return SASI_AES_DATA_IN_SIZE_ILLEGAL;
    }

    if ((pAesCtx->mode != SEP_CIPHER_XTS) && ((dataInSize % SASI_AES_BLOCK_SIZE_IN_BYTES) != 0)) {
        /* Only for XTS an intermediate data unit may be non aes block multiple */
        SASI_PAL_LOG_ERR("Invalid data size: %u\n", (unsigned int)dataInSize);
        return SASI_AES_DATA_IN_SIZE_ILLEGAL;
    }

    /* set the data unit size if first block */
    if (pAesCtx->data_unit_size == 0) {
        pAesCtx->data_unit_size = dataInSize;
    }

    /* In XTS mode, all the data units must be of the same size */
    if ((pAesCtx->mode == SEP_CIPHER_XTS) && (pAesCtx->data_unit_size != dataInSize)) {
        SASI_PAL_LOG_ERR("Invalid XTS data size: dataInSize=%u data_unit_size=%u\n", (unsigned int)dataInSize,
                         (unsigned int)pAesCtx->data_unit_size);
        return SASI_AES_DATA_IN_SIZE_ILLEGAL;
    }

    /* max size validation in XTS mode */
    if ((pAesCtx->mode == SEP_CIPHER_XTS) && (dataInSize > AES_XTS_MAX_BLOCK_SIZE)) {
        return SASI_AES_DATA_IN_SIZE_ILLEGAL;
    }

    if ((pAesCtx->mode == SEP_CIPHER_CMAC) || (pAesCtx->mode == SEP_CIPHER_XCBC_MAC) ||
        (pAesCtx->mode == SEP_CIPHER_CBC_MAC)) {
        pOutData = NULL;
    } else {
        if (pDataOut == NULL) {
            return SASI_AES_DATA_OUT_POINTER_INVALID_ERROR;
        }

        pOutData = pDataOut;
    }

    symRc = SymDriverAdaptorProcess((struct drv_ctx_generic *)pAesCtx, pDataIn, pOutData, dataInSize);

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_BLOCK);

    return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SaSiAesErr);
}

CIMPORT_C SaSiError_t SaSi_AesFinish(SaSiAesUserContext_t *pContext, size_t dataSize, uint8_t *pDataIn,
                                     size_t dataInBuffSize, uint8_t *pDataOut, size_t *dataOutBuffSize)
{
    int symRc;
    struct drv_ctx_cipher *pAesCtx;
    size_t paddingSize = 0;

    SaSi_PalPerfData_t perfIdx = 0;
    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_FIN);

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pContext == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    if ((pDataIn == NULL) && (dataSize != 0)) {
        return SASI_AES_DATA_IN_POINTER_INVALID_ERROR;
    }

    if (dataInBuffSize < dataSize) {
        return SASI_AES_DATA_IN_BUFFER_SIZE_ERROR;
    }

    if (dataOutBuffSize == NULL) {
        return SASI_AES_DATA_OUT_SIZE_POINTER_INVALID_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesCtx = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(pContext->buff);

    if ((pAesCtx->mode == SEP_CIPHER_CBC_MAC) || (pAesCtx->mode == SEP_CIPHER_XCBC_MAC) ||
        (pAesCtx->mode == SEP_CIPHER_CMAC)) {
        if (pDataOut == NULL) {
            return SASI_AES_DATA_OUT_POINTER_INVALID_ERROR;
        }
        if (*dataOutBuffSize < SASI_AES_BLOCK_SIZE_IN_BYTES) {
            return SASI_AES_DATA_OUT_BUFFER_SIZE_ERROR;
        }
    } else {
        if ((pDataOut == NULL) && (dataSize != 0)) {
            return SASI_AES_DATA_OUT_POINTER_INVALID_ERROR;
        }
        if (*dataOutBuffSize < dataSize) {
            return SASI_AES_DATA_OUT_BUFFER_SIZE_ERROR;
        }
    }

    if (((dataSize % SASI_AES_BLOCK_SIZE_IN_BYTES) != 0) &&
        ((pAesCtx->mode == SEP_CIPHER_ECB) || (pAesCtx->mode == SEP_CIPHER_CBC) ||
         (pAesCtx->mode == SEP_CIPHER_CBC_MAC)) &&
        (pAesCtx->padding_type == DRV_PADDING_NONE)) {
        return SASI_AES_DATA_IN_SIZE_ILLEGAL;
    }

    /* Check, that in case of CTS mode data size is not less than SASI_AES_BLOCK_SIZE_IN_BYTES */
    if ((dataSize < SASI_AES_BLOCK_SIZE_IN_BYTES) && (pAesCtx->mode == SEP_CIPHER_CBC_CTS)) {
        return SASI_AES_DATA_IN_SIZE_ILLEGAL;
    }

    /* set the data unit size if first block */
    if (pAesCtx->data_unit_size == 0) {
        pAesCtx->data_unit_size = dataSize;
    }

    if ((pAesCtx->mode == SEP_CIPHER_XTS) && (dataSize != 0)) {
        /* For XTS all the data units must be of the same size */
        if ((dataSize < SASI_AES_BLOCK_SIZE_IN_BYTES) || (pAesCtx->data_unit_size != dataSize)) {
            SASI_PAL_LOG_ERR("Invalid XTS data size: dataSize=%u data_unit_size=%u\n", (unsigned int)dataSize,
                             (unsigned int)pAesCtx->data_unit_size);
            return SASI_AES_DATA_IN_SIZE_ILLEGAL;
        }
    }

    if (pAesCtx->padding_type == DRV_PADDING_PKCS7) {
        if (pDataOut == NULL) {
            return SASI_AES_DATA_OUT_POINTER_INVALID_ERROR;
        }

        /* PKCS7 padding in case of encryption mode */
        if (pAesCtx->direction == SEP_CRYPTO_DIRECTION_ENCRYPT) {
            paddingSize = SASI_AES_BLOCK_SIZE_IN_BYTES - (dataSize % SASI_AES_BLOCK_SIZE_IN_BYTES);

            if (*dataOutBuffSize < (dataSize + paddingSize)) {
                return SASI_AES_DATA_OUT_BUFFER_SIZE_ERROR;
            }

            if (dataInBuffSize < (dataSize + paddingSize)) {
                return SASI_AES_DATA_IN_BUFFER_SIZE_ERROR;
            }

            SaSi_PalMemSet(pDataIn + dataSize, paddingSize, paddingSize);
            dataSize += paddingSize;
        }
    }

    /* For CBC_CTS mode : In case of data size aligned to 16 perform CBC operation */
    if ((pAesCtx->mode == SEP_CIPHER_CBC_CTS) && ((dataSize % SASI_AES_BLOCK_SIZE_IN_BYTES) == 0)) {
        pAesCtx->mode = SEP_CIPHER_CBC;
        symRc         = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAesCtx, pDataIn, pDataOut, dataSize);
        pAesCtx->mode = SEP_CIPHER_CBC_CTS;
    } else {
        symRc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAesCtx, pDataIn, pDataOut, dataSize);
    }

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_SASI_AES_FIN);

    if (symRc != SASI_RET_OK) {
        return SASI_SaSi_RETURN_ERROR(symRc, 0, SymAdaptor2SaSiAesErr);
    }

    if ((pAesCtx->padding_type == DRV_PADDING_PKCS7) && (pAesCtx->direction == SEP_CRYPTO_DIRECTION_DECRYPT)) {
        size_t i = 0;

        if (pDataOut == NULL) { // added for KW, already check previously
            return SASI_AES_DATA_OUT_POINTER_INVALID_ERROR;
        }
        paddingSize = pDataOut[dataSize - 1];

        if (paddingSize > SASI_AES_BLOCK_SIZE_IN_BYTES) {
            return SASI_AES_INCORRECT_PADDING_ERROR;
        }

        /* check the padding correctness */
        for (i = 0; i < paddingSize; ++i) {
            if (pDataOut[dataSize - paddingSize + i] != paddingSize) {
                return SASI_AES_CORRUPTED_OUTPUT_ERROR;
            }
        }

        /* remove the padding */
        dataSize -= paddingSize;
        SaSi_PalMemSetZero(pDataOut + dataSize, paddingSize);
    }

    if ((pAesCtx->mode == SEP_CIPHER_CBC_MAC) || (pAesCtx->mode == SEP_CIPHER_XCBC_MAC) ||
        (pAesCtx->mode == SEP_CIPHER_CMAC)) {
        *dataOutBuffSize = SASI_AES_IV_SIZE_IN_BYTES;
    } else {
        *dataOutBuffSize = dataSize;
    }

    return SASI_OK;
}

CIMPORT_C SaSiError_t SaSi_AesFree(SaSiAesUserContext_t *pContext)
{
    struct drv_ctx_cipher *pAesCtx;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pContext == NULL) {
        return SASI_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesCtx = (struct drv_ctx_cipher *)SaSi_GetUserCtxLocation(pContext->buff);

    /* Zero the context */
    SaSi_PalMemSetZero(pAesCtx, sizeof(struct drv_ctx_cipher));

    return SASI_OK;
}
