/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include <string.h>
#ifdef DEBUG
#include <stdio.h>
#endif

#include "ssi_pal_types.h"
#include "sym_adaptor_driver.h"
#include "ssi_error.h"
#include "sasi_context_relocation.h"
#include "ssi_crypto_ctx.h"
#include "ssi_util.h"
#include "ssi_pal_mem.h"
#include "ssi_aes.h"
#include "sasi_aesccm.h"

#include "secure_key_defs.h"
#include "secure_key_int_defs.h"
#include "secure_key_gen.h"
#include "sasi_fips_defs.h"

/* *********************** Defines **************************** */

#ifdef __BIG_ENDIAN__
#define SWAP_BYTE_ORDER(val) \
    (((val)&0xFF) << 24 | ((val)&0xFF00) << 8 | ((val)&0xFF0000) >> 8 | ((val)&0xFF000000) >> 24)
#else
#define SWAP_BYTE_ORDER(val) val
#endif
static uint32_t SaSi_UtilEncryptBlob(skeyNonceBuf_t skeyNonceBuf, uint8_t *dataIn, uint8_t *plainText,
                                     SaSi_AESCCM_Mac_Res_t macBlob);

static void SaSi_UtilSetRestrictedRegions(uint8_t *bufferPtr, uint32_t lowerBoundOffset, uint32_t upperBoundOffset,
                                          struct SkeyRegBounds_t *skeyRegBounds);

uint32_t SaSi_UtilGenerateSecureKeyPackage(enum secure_key_direction skeyDirection,
                                           enum secure_key_cipher_mode skeyMode, struct SkeyRegBounds_t *skeyRegBounds,
                                           uint64_t startTimeStamp, uint64_t endTimeStamp, skeyNonceBuf_t skeyNonceBuf,
                                           uint8_t *skeyBuf, enum secure_key_type skeyType, uint32_t skeyNumRounds,
                                           struct SaSiUtilNonceCtrProtParams_t *skeyProtParams,
                                           skeyPackageBuf_t skeyPackageBuf)
{
    SaSiError_t rc                                        = SASI_UTIL_OK;
    uint8_t dataFormatPtr[DX_SECURE_KEY_CCM_BUF_IN_BYTES] = { 0 };
    SaSi_AESCCM_Mac_Res_t macBlob;
    uint32_t skConfig;
    uint32_t token        = DX_SECURE_KEY_TOKEN_VALUE;
    uint32_t numOfRegions = 0;
    uint32_t regIndex     = 0;
    uint32_t skVersion    = DX_SECURE_KEY_VERSION_NUM;
    uint32_t keySizeInBytes;
    uint32_t *uint32Ptr;
    uint8_t *lNonceCtrBuff = NULL;
    uint32_t dataRange     = 0;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check input variables */
    if ((skeyDirection != DX_SECURE_KEY_DIRECTION_DECRYPT) && (skeyDirection != DX_SECURE_KEY_DIRECTION_ENCRYPT)) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }
    if ((skeyMode != DX_SECURE_KEY_CIPHER_CBC) && (skeyMode != DX_SECURE_KEY_CIPHER_CTR) &&
        (skeyMode != DX_SECURE_KEY_CIPHER_OFB) && (skeyMode != DX_SECURE_KEY_CIPHER_CTR_NONCE_PROT) &&
        (skeyMode != DX_SECURE_KEY_CIPHER_CTR_NONCE_CTR_PROT_NSP) && (skeyMode != DX_SECURE_KEY_CIPHER_CBC_CTS))
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyNonceBuf == NULL)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyBuf == NULL)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyPackageBuf == NULL)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;

    for (regIndex = 0; regIndex < DX_SECURE_KEY_RESTRICTED_REGIONS_NUM; regIndex++) {
        if ((skeyRegBounds[regIndex].skeyLowerBound == 0 && skeyRegBounds[regIndex].skeyUpperBound != 0) ||
            (skeyRegBounds[regIndex].skeyLowerBound != 0 && skeyRegBounds[regIndex].skeyUpperBound == 0)) {
            return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
        }

        if ((skeyRegBounds[regIndex].skeyLowerBound >= skeyRegBounds[regIndex].skeyUpperBound) &&
            ((skeyRegBounds[regIndex].skeyLowerBound != 0) && (skeyRegBounds[regIndex].skeyUpperBound != 0))) {
            return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
        }

        if (skeyRegBounds[regIndex].skeyLowerBound > 0) {
            numOfRegions++;
        }
    }

    if (numOfRegions == 0) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (((startTimeStamp >= endTimeStamp) && (startTimeStamp != 0) && (endTimeStamp != 0)) ||
        ((startTimeStamp != 0) && (endTimeStamp == 0)) || ((startTimeStamp == 0) && (endTimeStamp != 0))) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if ((skeyMode == DX_SECURE_KEY_CIPHER_CTR_NONCE_PROT) ||
        (skeyMode == DX_SECURE_KEY_CIPHER_CTR_NONCE_CTR_PROT_NSP)) {
        if (skeyProtParams == NULL) {
            return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
        }
        if (skeyProtParams->nonceCtrBuff == NULL) {
            return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
        }
        lNonceCtrBuff = skeyProtParams->nonceCtrBuff;

        if (!skeyProtParams->nonceLen) {
            if (!skeyProtParams->ctrLen) {
                return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
            } else if (skeyProtParams->ctrLen >= SEP_AES_IV_SIZE) {
                return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
            }
        } else {
            if (!skeyProtParams->ctrLen) {
                if (skeyProtParams->nonceLen >= SEP_AES_IV_SIZE) {
                    return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
                }
            } else if ((skeyProtParams->nonceLen + skeyProtParams->ctrLen) != SEP_AES_IV_SIZE) {
                return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
            }
        }

        if (skeyProtParams->dataRange > DX_SECURE_KEY_MAX_CTR_RANGE_VALUE) {
            return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
        }

        dataRange = (skeyProtParams->dataRange % DX_SECURE_KEY_MAX_CTR_RANGE_VALUE);

        if ((skeyProtParams->ctrLen) || (skeyProtParams->isNonSecPathOp)) {
            skeyMode = DX_SECURE_KEY_CIPHER_CTR_NONCE_CTR_PROT_NSP;
        }
        skeyNumRounds = ((skeyProtParams->nonceLen << 4) | (skeyProtParams->ctrLen));
    }

    switch (skeyType) {
    case DX_SECURE_KEY_AES_KEY128:
        keySizeInBytes = SEP_AES_128_BIT_KEY_SIZE;
        break;
    case DX_SECURE_KEY_AES_KEY256:
        keySizeInBytes = SEP_AES_256_BIT_KEY_SIZE;
        break;
    case DX_SECURE_KEY_MULTI2:
        if ((skeyNumRounds < DX_SECURE_KEY_MULTI2_MIN_ROUNDS) || (skeyNumRounds > DX_SECURE_KEY_MULTI2_MAX_ROUNDS)) {
            return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
        }
        if ((skeyMode != DX_SECURE_KEY_CIPHER_CBC) && (skeyMode != DX_SECURE_KEY_CIPHER_OFB)) {
            return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
        }
        keySizeInBytes = SEP_MULTI2_SYSTEM_N_DATA_KEY_SIZE;
        break;
    case DX_SECURE_KEY_BYPASS:
        keySizeInBytes = SEP_MULTI2_SYSTEM_N_DATA_KEY_SIZE;
        break;

    default:
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    skConfig =
        ((skeyType << DX_SECURE_KEY_RESTRICT_KEY_TYPE_BIT_SHIFT) |
         (skeyDirection << DX_SECURE_KEY_RESTRICT_DIR_BIT_SHIFT) | (skeyMode << DX_SECURE_KEY_RESTRICT_MODE_BIT_SHIFT));

    /* Format the message */
    /* B0 */
    dataFormatPtr[DX_SECURE_KEY_B0_FLAGS_OFFSET] = DX_SECURE_KEY_B0_FLAGS_VALUE;
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_B0_NONCE_OFFSET], skeyNonceBuf, DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    dataFormatPtr[DX_SECURE_KEY_B0_DATA_LEN_OFFSET] = DX_SECURE_KEY_RESTRICT_KEY_SIZE_IN_BYTES;
    /* A */
    dataFormatPtr[DX_SECURE_KEY_ADATA_LEN_OFFSET]     = DX_SECURE_KEY_ADATA_LEN_IN_BYTES;
    dataFormatPtr[DX_SECURE_KEY_ADATA_CONFIG_OFFSET]  = skConfig;
    dataFormatPtr[DX_SECURE_KEY_ADATA_NROUNDS_OFFSET] = skeyNumRounds;

    SaSi_UtilSetRestrictedRegions(dataFormatPtr, DX_SECURE_KEY_ADATA_LOWER_BOUND_0_OFFSET,
                                  DX_SECURE_KEY_ADATA_UPPER_BOUND_0_OFFSET, skeyRegBounds);

    uint32Ptr    = (uint32_t *)&startTimeStamp;
    uint32Ptr[0] = SWAP_BYTE_ORDER(uint32Ptr[0]);
    uint32Ptr[1] = SWAP_BYTE_ORDER(uint32Ptr[1]);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_START_TIME_STAMP_OFFSET], &startTimeStamp,
                    sizeof(startTimeStamp));
    uint32Ptr    = (uint32_t *)&endTimeStamp;
    uint32Ptr[0] = SWAP_BYTE_ORDER(uint32Ptr[0]);
    uint32Ptr[1] = SWAP_BYTE_ORDER(uint32Ptr[1]);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_END_TIME_STAMP_OFFSET], &endTimeStamp, sizeof(endTimeStamp));
    token = SWAP_BYTE_ORDER(token);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_TOKEN_OFFSET], &token, sizeof(uint32_t));
    skVersion = SWAP_BYTE_ORDER(skVersion);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_VERSION_OFFSET], &skVersion, sizeof(uint32_t));

    if (lNonceCtrBuff != NULL) {
        SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_IV_CTR_OFFSET], lNonceCtrBuff, SEP_AES_IV_SIZE);
    } else {
        SaSi_PalMemSet(&dataFormatPtr[DX_SECURE_KEY_ADATA_IV_CTR_OFFSET], 0, SEP_AES_IV_SIZE);
    }

    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_CTR_RANGE_OFFSET], &dataRange, sizeof(uint32_t));
    if (skeyType != DX_SECURE_KEY_BYPASS) {
        /* key */
        SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], skeyBuf, keySizeInBytes);
    } else {
        SaSi_PalMemSet(&dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], 0, keySizeInBytes);
    }

    /* build the blob configuration word */
    skConfig = skConfig | (skeyNumRounds << DX_SECURE_KEY_RESTRICT_NROUNDS_BIT_SHIFT);
    skConfig = skConfig | (dataRange << DX_SECURE_KEY_RESTRICT_CTR_RANGE_BIT_SHIFT);
    skConfig = SWAP_BYTE_ORDER(skConfig);

    rc = SaSi_UtilEncryptBlob(skeyNonceBuf, dataFormatPtr, &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], macBlob);
    if (rc) {
        return rc;
    }
    SaSi_PalMemSet(skeyPackageBuf, 0, sizeof(skeyPackageBuf_t));
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_TOKEN_OFFSET * sizeof(uint32_t)], &token, sizeof(uint32_t));
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_VERSION_OFFSET * sizeof(uint32_t)], &skVersion, sizeof(uint32_t));
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_NONCE_OFFSET * sizeof(uint32_t)], skeyNonceBuf,
                    DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_CONFIG_OFFSET * sizeof(uint32_t)], &skConfig,
                    sizeof(uint32_t));

    SaSi_UtilSetRestrictedRegions(skeyPackageBuf, DX_SECURE_KEY_RESTRICT_LOWER_BOUND_0_OFFSET * sizeof(uint32_t),
                                  DX_SECURE_KEY_RESTRICT_UPPER_BOUND_0_OFFSET * sizeof(uint32_t), skeyRegBounds);

    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_START_TIME_STAMP_OFFSET * sizeof(uint32_t)], &startTimeStamp,
                    sizeof(uint64_t));
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_END_TIME_STAMP_OFFSET * sizeof(uint32_t)], &endTimeStamp,
                    sizeof(uint64_t));
    if (lNonceCtrBuff != NULL) {
        SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_IV_CTR_OFFSET * sizeof(uint32_t)], lNonceCtrBuff,
                        SEP_AES_IV_SIZE);
    } else {
        SaSi_PalMemSet(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_IV_CTR_OFFSET * sizeof(uint32_t)], 0, SEP_AES_IV_SIZE);
    }
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_KEY_OFFSET * sizeof(uint32_t)],
                    &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_MAC_OFFSET * sizeof(uint32_t)], macBlob, sizeof(macBlob));

    return SaSi_OK;
}

uint32_t SaSi_UtilGenerateSecureKeyMaintenance(skeyNonceBuf_t skeyNonceBuf, uint8_t *skeyBuf,
                                               enum secure_key_type skeyType, uint32_t skeyNumPairs,
                                               skeyPackageBuf_t skeyPackageBuf)
{
    SaSiError_t rc = SASI_UTIL_OK;
    uint8_t dataFormatPtr[DX_SECURE_KEY_CCM_BUF_IN_WORDS * sizeof(uint32_t)];
    SaSi_AESCCM_Mac_Res_t macBlob;
    uint32_t skConfig;
    uint32_t token     = DX_SECURE_KEY_TOKEN_VALUE;
    uint32_t skVersion = DX_SECURE_KEY_VERSION_NUM;
    uint32_t keySizeInBytes;
    uint32_t *uint32Ptr;

    /* set constant parameters for dk format */
    enum secure_key_cipher_mode skeyMode    = SEP_CIPHER_CBC;
    enum secure_key_direction skeyDirection = SEP_CRYPTO_DIRECTION_ENCRYPT;

    struct SkeyRegBounds_t skeyRegBounds[DX_SECURE_KEY_RESTRICTED_REGIONS_NUM] = { { 0, 0 }, { 0, 0 }, { 0, 0 },
                                                                                   { 0, 0 }, { 0, 0 }, { 0, 0 },
                                                                                   { 0, 0 }, { 0, 0 } };
    uint64_t startTimeStamp                                                    = 0;
    uint64_t endTimeStamp                                                      = 0;

    if (skeyNonceBuf == NULL)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyBuf == NULL)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyPackageBuf == NULL)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyType != DX_SECURE_KEY_MAINTENANCE)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    if ((skeyNumPairs < DX_SECURE_KEY_MAINTENANCE_MIN_PAIRS) || (skeyNumPairs > DX_SECURE_KEY_MAINTENANCE_MAX_PAIRS))
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;

    keySizeInBytes = 2 * skeyNumPairs * sizeof(uint32_t);

    skConfig = (skeyType << DX_SECURE_KEY_RESTRICT_KEY_TYPE_BIT_SHIFT) |
               (skeyDirection << DX_SECURE_KEY_RESTRICT_DIR_BIT_SHIFT) |
               (skeyMode << DX_SECURE_KEY_RESTRICT_MODE_BIT_SHIFT);

    /* Format the message */
    SaSi_PalMemSet(&dataFormatPtr[DX_SECURE_KEY_B0_FLAGS_OFFSET], 0, DX_SECURE_KEY_CCM_BUF_IN_WORDS * sizeof(uint32_t));
    /* B0 */
    dataFormatPtr[DX_SECURE_KEY_B0_FLAGS_OFFSET] = DX_SECURE_KEY_B0_FLAGS_VALUE;
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_B0_NONCE_OFFSET], skeyNonceBuf, DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    dataFormatPtr[DX_SECURE_KEY_B0_DATA_LEN_OFFSET] = DX_SECURE_KEY_RESTRICT_KEY_SIZE_IN_BYTES;
    /* A */
    dataFormatPtr[DX_SECURE_KEY_ADATA_LEN_OFFSET]     = DX_SECURE_KEY_ADATA_LEN_IN_BYTES;
    dataFormatPtr[DX_SECURE_KEY_ADATA_CONFIG_OFFSET]  = skConfig;
    dataFormatPtr[DX_SECURE_KEY_ADATA_NROUNDS_OFFSET] = skeyNumPairs;

    SaSi_UtilSetRestrictedRegions(dataFormatPtr, DX_SECURE_KEY_ADATA_LOWER_BOUND_0_OFFSET,
                                  DX_SECURE_KEY_ADATA_UPPER_BOUND_0_OFFSET, skeyRegBounds);

    uint32Ptr    = (uint32_t *)&startTimeStamp;
    uint32Ptr[0] = SWAP_BYTE_ORDER(uint32Ptr[0]);
    uint32Ptr[1] = SWAP_BYTE_ORDER(uint32Ptr[1]);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_START_TIME_STAMP_OFFSET], &startTimeStamp,
                    sizeof(startTimeStamp));
    uint32Ptr    = (uint32_t *)&endTimeStamp;
    uint32Ptr[0] = SWAP_BYTE_ORDER(uint32Ptr[0]);
    uint32Ptr[1] = SWAP_BYTE_ORDER(uint32Ptr[1]);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_END_TIME_STAMP_OFFSET], &endTimeStamp, sizeof(endTimeStamp));

    token = SWAP_BYTE_ORDER(token);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_TOKEN_OFFSET], &token, sizeof(uint32_t));
    skVersion = SWAP_BYTE_ORDER(skVersion);
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_VERSION_OFFSET], &skVersion, sizeof(uint32_t));
    /* key */
    SaSi_PalMemCopy(&dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], skeyBuf, keySizeInBytes);

    /* build the blob configuration word */
    skConfig = skConfig | (skeyNumPairs << DX_SECURE_KEY_RESTRICT_NROUNDS_BIT_SHIFT);
    skConfig = SWAP_BYTE_ORDER(skConfig);

    rc = SaSi_UtilEncryptBlob(skeyNonceBuf, dataFormatPtr, &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], macBlob);
    if (rc)
        return rc;

    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_TOKEN_OFFSET * sizeof(uint32_t)], &token, sizeof(uint32_t));
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_VERSION_OFFSET * sizeof(uint32_t)], &skVersion, sizeof(uint32_t));
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_NONCE_OFFSET * sizeof(uint32_t)], skeyNonceBuf,
                    DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_CONFIG_OFFSET * sizeof(uint32_t)], &skConfig,
                    sizeof(uint32_t));

    SaSi_UtilSetRestrictedRegions(skeyPackageBuf, DX_SECURE_KEY_RESTRICT_LOWER_BOUND_0_OFFSET * sizeof(uint32_t),
                                  DX_SECURE_KEY_RESTRICT_UPPER_BOUND_0_OFFSET * sizeof(uint32_t), skeyRegBounds);

    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_START_TIME_STAMP_OFFSET * sizeof(uint32_t)], &startTimeStamp,
                    sizeof(uint64_t));
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_END_TIME_STAMP_OFFSET * sizeof(uint32_t)], &endTimeStamp,
                    sizeof(uint64_t));

    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_KEY_OFFSET * sizeof(uint32_t)],
                    &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);
    SaSi_PalMemCopy(&skeyPackageBuf[DX_SECURE_KEY_MAC_OFFSET * sizeof(uint32_t)], macBlob, sizeof(macBlob));

    return SaSi_OK;
}

static uint32_t SaSi_UtilEncryptBlob(skeyNonceBuf_t skeyNonceBuf, uint8_t *dataIn, uint8_t *plainText,
                                     SaSi_AESCCM_Mac_Res_t macBlob)
{
    struct drv_ctx_cipher *pAesContext;
    SaSi_AESCCM_Mac_Res_t macRes;
    uint8_t counter[SEP_AES_IV_SIZE];
    uint32_t rc;
    uint32_t ctxBuff[SASI_AES_USER_CTX_SIZE_IN_WORDS] = { 0x0 };

    /* Get pointer to contiguous context in the HOST buffer */
    pAesContext = (struct drv_ctx_cipher *)SaSi_InitUserCtxLocation(ctxBuff, sizeof(SaSiAesUserContext_t),
                                                                    sizeof(struct drv_ctx_cipher));
    if (pAesContext == NULL)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;

    /* A. Perform MAC operation on B0 format, A format, and user key */
    pAesContext->key_size        = SEP_AES_BLOCK_SIZE;
    pAesContext->alg             = DRV_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_CBC_MAC;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_ENCRYPT;
    pAesContext->crypto_key_type = DRV_SESSION_KEY;

    rc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAesContext, dataIn, macRes,
                                  DX_SECURE_KEY_CCM_KEY_OFFSET + DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);
    if (rc)
        return rc;
    /* B. Encrypt user key with AES-CTR */
    counter[0] = 0x2;
    SaSi_PalMemCopy(&counter[1], skeyNonceBuf, DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    counter[13] = 0x0;
    counter[14] = 0x0;
    counter[15] = 0x1;
    SaSi_PalMemCopy(pAesContext->block_state, counter, SEP_AES_IV_SIZE);
    pAesContext->key_size        = SEP_AES_BLOCK_SIZE;
    pAesContext->alg             = DRV_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_CTR;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_ENCRYPT;
    pAesContext->crypto_key_type = DRV_SESSION_KEY;

    rc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAesContext, plainText, plainText,
                                  DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);

    if (rc)
        return rc;

    /* C. Encrypt mac result with AES-CTR */
    counter[15] = 0x0;
    SaSi_PalMemCopy(pAesContext->block_state, counter, SEP_AES_IV_SIZE);

    rc = SymDriverAdaptorFinalize((struct drv_ctx_generic *)pAesContext, macRes, macBlob, sizeof(macRes));

    return rc;
}

static void SaSi_UtilSetRestrictedRegions(uint8_t *bufferPtr, uint32_t lowerBoundOffset, uint32_t upperBoundOffset,
                                          struct SkeyRegBounds_t *skeyRegBounds)
{
    uint32_t *uint32Ptr;
    uint32_t regIndex;

    for (regIndex = 0; regIndex < DX_SECURE_KEY_RESTRICTED_REGIONS_NUM; regIndex++) {
        uint32Ptr    = (uint32_t *)&(skeyRegBounds[regIndex].skeyLowerBound);
        uint32Ptr[0] = SWAP_BYTE_ORDER(uint32Ptr[0]);
        uint32Ptr[1] = SWAP_BYTE_ORDER(uint32Ptr[1]);
        SaSi_PalMemCopy(&bufferPtr[lowerBoundOffset + (regIndex * DX_SECURE_KEY_LOWER_AND_UPPER_SIZE_IN_BYTES)],
                        &(skeyRegBounds[regIndex].skeyLowerBound), DX_SECURE_KEY_RESTRICTED_ADDRESS_SIZE_IN_BYTES);
        uint32Ptr    = (uint32_t *)&(skeyRegBounds[regIndex].skeyUpperBound);
        uint32Ptr[0] = SWAP_BYTE_ORDER(uint32Ptr[0]);
        uint32Ptr[1] = SWAP_BYTE_ORDER(uint32Ptr[1]);
        SaSi_PalMemCopy(&bufferPtr[upperBoundOffset + (regIndex * DX_SECURE_KEY_LOWER_AND_UPPER_SIZE_IN_BYTES)],
                        &(skeyRegBounds[regIndex].skeyUpperBound), DX_SECURE_KEY_RESTRICTED_ADDRESS_SIZE_IN_BYTES);
    }
}
