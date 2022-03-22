/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_SECURE_BOOT

/* ************ Include Files ************** */
#include "ssi_pal_log.h"
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "ssi_error.h"
#include "ssi_util_defs.h"
#include "ssi_aes_defs.h"
#include "ssi_aes.h"
#include "ssi_util_error.h"
#include "sasi_context_relocation.h"
#include "sasi_common.h"
#include "sym_adaptor_driver.h"
#include "ssi_crypto_ctx.h"

#define UTIL_CCM_NONCE_MIN_SIZE 7
#define UTIL_CCM_NONCE_MAX_SIZE 13
#define UTIL_CCM_TAG_MIN_SIZE   4
#define UTIL_CCM_TAG_MAX_SIZE   16

typedef struct utilCcm {
    uint8_t nonce[SASI_AES_IV_SIZE_IN_BYTES];
    uint32_t nonceSize;
    uint8_t key[SASI_AES_KEY_MAX_SIZE_IN_BYTES];
    uint32_t keySize;
    enum drv_crypto_key_type keyType;
    enum sep_crypto_direction direction;
    uint32_t dataInSize;
    uint32_t qSize;
    uint8_t macIv[SASI_AES_IV_SIZE_IN_BYTES];
} UtilCcm_t;

/* !
 * Converts Symmetric Adaptor return code to SaSi error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return SaSiError_t one of SaSi_* error codes defined in sasi_error.h
 */
static SaSiUtilError_t SymAdaptor2UtilCcmDeriveKeyErr(int symRetCode)
{
    switch (symRetCode) {
    case SASI_RET_INVARG:
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    case SASI_RET_INVARG_BAD_ADDR:
        return SASI_UTIL_BAD_ADDR_ERROR;
    case SASI_RET_INVARG_CTX:
    case SASI_RET_UNSUPP_ALG:
    default:
        return SASI_UTIL_FATAL_ERROR;
    }
}

static uint32_t ccmProcessBlock(struct drv_ctx_cipher *pAesContext, uint8_t *pDataIn, uint8_t *pDataOut,
                                uint32_t dataInSize)
{
    uint32_t rc                                = 0;
    uint8_t tmpBuff[SASI_AES_IV_SIZE_IN_BYTES] = { 0x0 };
    uint32_t dataInRemainingBytes              = dataInSize;
    uint8_t *pRemInBuff                        = pDataIn;
    uint8_t *pRemOutBuff                       = pDataOut;

    /* Case of MAC, finalize all data at once */
    /* Case of CTR, process data in groups of 16B, and then finilaze the remaining bytes */
    if (pAesContext->mode == SEP_CIPHER_CTR) {
        // Padd with 0's if size is not full AES block sizes
        if ((dataInSize % SASI_AES_BLOCK_SIZE_IN_BYTES) != 0) {
            dataInRemainingBytes = (dataInSize % SASI_AES_BLOCK_SIZE_IN_BYTES);
            rc                   = SymDriverAdaptorProcess((struct drv_ctx_generic *)pAesContext, pDataIn, pDataOut,
                                         dataInSize - dataInRemainingBytes);
            if (rc != 0) {
                return SymAdaptor2UtilCcmDeriveKeyErr(rc);
            }
            SaSi_PalMemCopy(tmpBuff, &pDataIn[dataInSize - dataInRemainingBytes], dataInRemainingBytes);
            pRemInBuff  = tmpBuff;
            pRemOutBuff = pDataOut + (dataInSize - dataInRemainingBytes);
        }
    }

    rc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAesContext, pRemInBuff, pRemOutBuff, dataInRemainingBytes);
    if (rc != SASI_OK) {
        return SymAdaptor2UtilCcmDeriveKeyErr(rc);
    }
    return SASI_OK;
}
static uint32_t ccmProcessMac(struct drv_ctx_cipher *pAesContext, UtilCcm_t *pUtilCcm, uint8_t *pDataIn,
                              uint8_t *pDataOut, uint32_t dataInSize)
{
    uint32_t rc = 0;

    pAesContext->alg             = DRV_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_CBC_MAC;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_ENCRYPT;
    pAesContext->key_size        = pUtilCcm->keySize;
    pAesContext->crypto_key_type = pUtilCcm->keyType;

    rc = ccmProcessBlock((struct drv_ctx_cipher *)pAesContext, pDataIn, pDataOut, dataInSize);
    if (rc != SASI_OK) {
        return SymAdaptor2UtilCcmDeriveKeyErr(rc);
    }
    return SASI_OK;
}

static uint32_t ccmProcessCtr(struct drv_ctx_cipher *pAesContext, UtilCcm_t *pUtilCcm, uint8_t *pDataIn,
                              uint8_t *pDataOut, uint32_t dataInSize)
{
    uint32_t rc = 0;

    pAesContext->alg             = DRV_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_CTR;
    pAesContext->direction       = pUtilCcm->direction;
    pAesContext->key_size        = pUtilCcm->keySize;
    pAesContext->crypto_key_type = pUtilCcm->keyType;

    rc = ccmProcessBlock((struct drv_ctx_cipher *)pAesContext, pDataIn, pDataOut, dataInSize);
    if (rc != SASI_OK) {
        return SymAdaptor2UtilCcmDeriveKeyErr(rc);
    }
    return SASI_OK;
}

static uint32_t ccmProcessAdata(struct drv_ctx_cipher *pAesContext, uint8_t *pAdata, uint32_t aDataSize,
                                UtilCcm_t *pUtilCcm)
{
    SASI_UNUSED_PARAM(pAesContext);
    SASI_UNUSED_PARAM(pAdata);
    SASI_UNUSED_PARAM(pUtilCcm);
    if (aDataSize > 0) {
        // not yet implemented
        return 1;
    }
    return 0;
}

/* ccm encrypt using SESSION_KEY without additional Data */
static uint32_t ccmInit(struct drv_ctx_cipher *pAesContext, uint8_t *pNonce, uint32_t nonceSize, uint8_t *pAdata,
                        uint32_t aDataSize, uint32_t keySize, enum drv_crypto_key_type keyType,
                        enum sep_crypto_direction direction, uint32_t tagSize, uint32_t dataInSize, UtilCcm_t *pUtilCcm)
{
    uint32_t minSizeInBytes = 0;
    uint32_t rc             = 0;

    SaSi_PalMemSetZero(pUtilCcm->nonce, sizeof(pUtilCcm->nonce));
    SaSi_PalMemSetZero(pUtilCcm->key, sizeof(pUtilCcm->key));
    pUtilCcm->keyType    = keyType;
    pUtilCcm->keySize    = keySize;
    pUtilCcm->dataInSize = dataInSize;
    pUtilCcm->nonceSize  = nonceSize;
    pUtilCcm->direction  = direction;
    pUtilCcm->qSize      = 15 - nonceSize;
    SaSi_PalMemCopy(&pUtilCcm->nonce[1], pNonce, nonceSize);

    /* A. Perform CCM first block on B0 format, CBC-MAC mode  */
    pUtilCcm->nonce[0] = (pUtilCcm->qSize - 1);   // bits 0 - 2
    pUtilCcm->nonce[0] |= (tagSize - 2) / 2 << 3; // bits 3 - 5
    if (aDataSize > 0) {
        pUtilCcm->nonce[0] = 1 << 6; // bits 6
    }
    minSizeInBytes = min(pUtilCcm->qSize, 4);
    SaSi_COMMON_ReverseMemcpy(&pUtilCcm->nonce[SASI_AES_IV_SIZE_IN_BYTES - minSizeInBytes], (uint8_t *)&dataInSize,
                              minSizeInBytes);

    SaSi_PalMemSetZero(pAesContext->block_state, sizeof(pAesContext->block_state));

    rc = ccmProcessMac(pAesContext, pUtilCcm, pUtilCcm->nonce, pUtilCcm->macIv, sizeof(pUtilCcm->nonce));
    if (rc != 0) {
        return SymAdaptor2UtilCcmDeriveKeyErr(rc);
    }

    /* B. Perform CBC-MAC mode on additional data if exists  */
    if (aDataSize > 0) {
        rc = ccmProcessAdata(pAesContext, pAdata, aDataSize, pUtilCcm);
        if (rc != 0) {
            return SymAdaptor2UtilCcmDeriveKeyErr(rc);
        }
    }

    return SASI_OK;
}

static uint32_t ccmProcessDataIn(struct drv_ctx_cipher *pAesContext, uint8_t *pDataIn, uint8_t *pDataOut,
                                 UtilCcm_t *pUtilCcm)
{
    uint32_t rc = 0;

    if (pUtilCcm->direction == SEP_CRYPTO_DIRECTION_ENCRYPT) {
        SaSi_PalMemCopy(pAesContext->block_state, pUtilCcm->macIv, sizeof(pAesContext->block_state));
        rc = ccmProcessMac(pAesContext, pUtilCcm, pDataIn, pUtilCcm->macIv, pUtilCcm->dataInSize);
        if (rc != SASI_OK) {
            return 1;
        }
    }

    SaSi_PalMemSetZero(pAesContext->block_state, sizeof(pAesContext->block_state));
    pAesContext->block_state[0] = (pUtilCcm->qSize - 1);
    SaSi_PalMemCopy(&pAesContext->block_state[1], &pUtilCcm->nonce[1], pUtilCcm->nonceSize);
    pAesContext->block_state[15] = 1;
    rc                           = ccmProcessCtr(pAesContext, pUtilCcm, pDataIn, pDataOut, pUtilCcm->dataInSize);
    if (rc != SASI_OK) {
        return 1;
    }
    if (pUtilCcm->direction == SEP_CRYPTO_DIRECTION_DECRYPT) {
        SaSi_PalMemCopy(pAesContext->block_state, pUtilCcm->macIv, sizeof(pAesContext->block_state));
        rc = ccmProcessMac(pAesContext, pUtilCcm, pDataOut, pUtilCcm->macIv, pUtilCcm->dataInSize);
        if (rc != SASI_OK) {
            return 1;
        }
    }

    return 0;
}

/* ccm encrypt/decrypt using HW keys only */
uint32_t SaSi_Util_Ccm(uint8_t *pNonce, uint32_t nonceSize, uint8_t *pAdata, uint32_t aDataSize, uint32_t keySize,
                       enum drv_crypto_key_type keyType, enum sep_crypto_direction direction, uint32_t tagSize,
                       uint8_t *pDataIn, uint32_t dataInSize, uint8_t *pDataOut)
{
    uint32_t rc                                       = 0;
    uint32_t ctxBuff[SASI_AES_USER_CTX_SIZE_IN_WORDS] = { 0x0 };
    struct drv_ctx_cipher *pAesContext;
    UtilCcm_t ccmUtilCtx;
    uint8_t tmpBuff[SASI_AES_IV_SIZE_IN_BYTES] = { 0x0 };

    if ((pNonce == NULL) || (nonceSize < UTIL_CCM_NONCE_MIN_SIZE) || (nonceSize > UTIL_CCM_NONCE_MAX_SIZE) ||
        (keyType != DRV_SESSION_KEY) ||
        (keySize != SEP_AES_128_BIT_KEY_SIZE) || // could be any HW key, but only session key was testsed
        ((direction != SEP_CRYPTO_DIRECTION_ENCRYPT) && (direction != SEP_CRYPTO_DIRECTION_DECRYPT)) ||
        (tagSize != UTIL_CCM_TAG_MAX_SIZE) || // could be 4,6,8,10,12,14, - but only 16 was tested
        (pDataIn == NULL) || (pDataOut == NULL) || (dataInSize == 0)) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Get pointer to contiguous context in the HOST buffer */
    pAesContext = (struct drv_ctx_cipher *)SaSi_InitUserCtxLocation(ctxBuff, sizeof(SaSiAesUserContext_t),
                                                                    sizeof(struct drv_ctx_cipher));
    if (pAesContext == NULL) {
        return SASI_UTIL_FATAL_ERROR;
    }

    /* A - Perform MAC for nonce and aData */
    rc = ccmInit(pAesContext, pNonce, nonceSize, pAdata, aDataSize, keySize, keyType, direction, tagSize, dataInSize,
                 &ccmUtilCtx);
    if (rc != 0) {
        return SymAdaptor2UtilCcmDeriveKeyErr(rc);
    }

    /* B - Process text data */
    rc = ccmProcessDataIn(pAesContext, pDataIn, pDataOut, &ccmUtilCtx);
    if (rc != 0) {
        return SymAdaptor2UtilCcmDeriveKeyErr(rc);
    }

    /* C. Encrypt mac result with AES-CTR */
    SaSi_PalMemSetZero(pAesContext->block_state, sizeof(pAesContext->block_state));
    pAesContext->block_state[0] = ccmUtilCtx.qSize - 1;
    SaSi_PalMemCopy(&pAesContext->block_state[1], pNonce, nonceSize);

    if (direction == SEP_CRYPTO_DIRECTION_ENCRYPT) {
        rc = ccmProcessCtr(pAesContext, &ccmUtilCtx, ccmUtilCtx.macIv, tmpBuff, sizeof(ccmUtilCtx.macIv));
        if (rc != 0) {
            return SymAdaptor2UtilCcmDeriveKeyErr(rc);
        }
        SaSi_PalMemCopy(pDataOut + dataInSize, tmpBuff, tagSize);

    } else {
        rc = ccmProcessCtr(pAesContext, &ccmUtilCtx, (pDataIn + dataInSize), tmpBuff, sizeof(tmpBuff));
        if (rc != 0) {
            return SymAdaptor2UtilCcmDeriveKeyErr(rc);
        }
        /* D - for Decrypt - comapre the TAG */
        rc = SaSi_PalMemCmp(tmpBuff, ccmUtilCtx.macIv, tagSize);
        if (rc != 0) {
            return SymAdaptor2UtilCcmDeriveKeyErr(rc);
        }
    }

    return SASI_OK;
}
