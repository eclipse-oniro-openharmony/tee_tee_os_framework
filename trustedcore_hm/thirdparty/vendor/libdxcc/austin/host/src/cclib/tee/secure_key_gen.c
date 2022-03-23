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

/* ************ Include Files ************** */
// #include <string.h>
#ifdef DEBUG
// #include <stdio.h>
#endif

#include "dx_pal_types.h"
#include "sym_adaptor_driver.h"
#include "dx_error.h"
#include "crys_context_relocation.h"
#include "sep_ctx.h"
#include "dx_macros.h"
#include "dx_util.h"
#include "dx_pal_mem.h"
#include "crys_aes.h"
#include "crys_aesccm.h"
#include "cc_acl.h"

#include "secure_key_defs.h"
#include "secure_key_int_defs.h"
#include "secure_key_gen.h"

/* *********************** Defines **************************** */

#ifdef __BIG_ENDIAN__
#define SWAP_BYTE_ORDER(val) \
    (((val)&0xFF) << 24 | ((val)&0xFF00) << 8 | ((val)&0xFF0000) >> 8 | ((val)&0xFF000000) >> 24)
#else
#define SWAP_BYTE_ORDER(val) val
#endif
static uint32_t DX_UTIL_encrypt_blob(skeyNonceBuf_t skeyNonceBuf, uint8_t *dataIn, uint8_t *plainText,
                                     CRYS_AESCCM_Mac_Res_t macBlob);

/* !
 * @brief Create a secured crypto package in the CC441 secure environment with the session key.
 *  It is built of the AES/Multi2 encrypted key and the restriction data with authentication (by AES-CCM).
 *
 * @param[in] skeyDirection      - An enum parameter, defines Encrypt operation or a Decrypt operation.
 * @param[in] skeyMode        - An enum parameter, defines cipher operation mode (cbc / ctr / ofb / cbc_cts).
 * @param[in] skeyLowerBound    - The restricted lower bound address.
 * @param[in] skeyUpperBound     - The restricted upper bound address.
 * @param[in] skeyNonceBuf       - A pointer to Nonce - unique value assigned to all data passed into CCM.
 *                NOTE: it should be different for each call to this API.
 * @param[in] skeyBuf            - A pointer to the input secured key data buffer. The pointer does not need to be
 * aligned.
 * @param[in] skeyType           - An enum parameter, defines key type (aes128 / aes256 / multi2).
 * @param[in] skeyNumRounds      - Number of rounds (for Multi2 only).
 * @param[out] skeyPackageBuf    - A pointer to the generated secured key package:
 *                        Word No.    Bits        Field Name
 *                0        31:0        Token
 *                1        31:0        Sw version
 *                2-4                     Nonce
 *                5           2:0         Secure key type (aes128 / aes256 / multi2)
 *                            3           Direction (enc / dec)
 *                                   7:4         Cipher mode (cbc / ctr / ofb / cbc_cts)
 *                                   15:8        Number of rounds (only for Multi2)
 *                                    31:16       reserved
 *                       6-7         63:0        Lower bound address
 *                   8-9         63:0        Upper bound address
 *                   10-19                   Restricted key  (encryption of the secured key padded with zeroes)
 *                   20-23                   mac results
 *
 * \return DxUTILError_t one of the error codes defined in dx_util.h
 */
uint32_t DX_UTIL_GenerateSecureKeyPackage(enum secure_key_direction skeyDirection, enum secure_key_cipher_mode skeyMode,
                                          uint64_t skeyLowerBound, uint64_t skeyUpperBound, skeyNonceBuf_t skeyNonceBuf,
                                          uint8_t *skeyBuf, enum secure_key_type skeyType, uint32_t skeyNumRounds,
                                          struct DX_UTIL_NonceCtrProtParams_t *skeyProtParams,
                                          skeyPackageBuf_t skeyPackageBuf)
{
    DxError_t rc                                          = DX_UTIL_OK;
    uint8_t dataFormatPtr[DX_SECURE_KEY_CCM_BUF_IN_BYTES] = { 0 };
    CRYS_AESCCM_Mac_Res_t macBlob;
    uint32_t skConfig;
    uint32_t token     = DX_SECURE_KEY_TOKEN_VALUE;
    uint32_t skVersion = DX_SECURE_KEY_VERSION_NUM;
    uint32_t keySizeInBytes;
    uint32_t *uint32Ptr;
    uint8_t *lNonceCtrBuff = DX_NULL;
    uint32_t dataRange     = 0;

    /* check input variables */
    if ((skeyDirection != DX_SECURE_KEY_DIRECTION_DECRYPT) && (skeyDirection != DX_SECURE_KEY_DIRECTION_ENCRYPT)) {
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    }
    if ((skeyMode != DX_SECURE_KEY_CIPHER_CBC) && (skeyMode != DX_SECURE_KEY_CIPHER_CTR) &&
        (skeyMode != DX_SECURE_KEY_CIPHER_OFB) && (skeyMode != DX_SECURE_KEY_CIPHER_CTR_NONCE_PROT) &&
        (skeyMode != DX_SECURE_KEY_CIPHER_CTR_NONCE_CTR_PROT_NSP) && (skeyMode != DX_SECURE_KEY_CIPHER_CBC_CTS))
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyNonceBuf == DX_NULL)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyBuf == DX_NULL)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyPackageBuf == DX_NULL)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyLowerBound >= skeyUpperBound)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;

    if ((skeyMode == DX_SECURE_KEY_CIPHER_CTR_NONCE_PROT) ||
        (skeyMode == DX_SECURE_KEY_CIPHER_CTR_NONCE_CTR_PROT_NSP)) {
        if (skeyProtParams == DX_NULL)
            return DX_UTIL_ILLEGAL_PARAMS_ERROR;
        if (skeyProtParams->nonceCtrBuff == DX_NULL)
            return DX_UTIL_ILLEGAL_PARAMS_ERROR;
        lNonceCtrBuff = skeyProtParams->nonceCtrBuff;

        if (!skeyProtParams->nonceLen) {
            if (!skeyProtParams->ctrLen) {
                return DX_UTIL_ILLEGAL_PARAMS_ERROR;
            } else if (skeyProtParams->ctrLen >= SEP_AES_IV_SIZE) {
                return DX_UTIL_ILLEGAL_PARAMS_ERROR;
            }
        } else {
            if (!skeyProtParams->ctrLen) {
                if (skeyProtParams->nonceLen >= SEP_AES_IV_SIZE) {
                    return DX_UTIL_ILLEGAL_PARAMS_ERROR;
                }
            } else if ((skeyProtParams->nonceLen + skeyProtParams->ctrLen) != SEP_AES_IV_SIZE) {
                return DX_UTIL_ILLEGAL_PARAMS_ERROR;
            }
        }

        if (skeyProtParams->dataRange > DX_SECURE_KEY_MAX_CTR_RANGE_VALUE)
            return DX_UTIL_ILLEGAL_PARAMS_ERROR;

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
            return DX_UTIL_ILLEGAL_PARAMS_ERROR;
        }
        if ((skeyMode != DX_SECURE_KEY_CIPHER_CBC) && (skeyMode != DX_SECURE_KEY_CIPHER_OFB)) {
            return DX_UTIL_ILLEGAL_PARAMS_ERROR;
        }
        keySizeInBytes = SEP_MULTI2_SYSTEM_N_DATA_KEY_SIZE;
        break;
    case DX_SECURE_KEY_BYPASS:
        keySizeInBytes = SEP_MULTI2_SYSTEM_N_DATA_KEY_SIZE;
        break;

    default:
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    skConfig =
        ((skeyType << DX_SECURE_KEY_RESTRICT_KEY_TYPE_BIT_SHIFT) |
         (skeyDirection << DX_SECURE_KEY_RESTRICT_DIR_BIT_SHIFT) | (skeyMode << DX_SECURE_KEY_RESTRICT_MODE_BIT_SHIFT));

    /* Format the message */
    /* B0 */
    dataFormatPtr[DX_SECURE_KEY_B0_FLAGS_OFFSET] = DX_SECURE_KEY_B0_FLAGS_VALUE;
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_B0_NONCE_OFFSET], skeyNonceBuf, DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    dataFormatPtr[DX_SECURE_KEY_B0_DATA_LEN_OFFSET] = DX_SECURE_KEY_RESTRICT_KEY_SIZE_IN_BYTES;
    /* A */
    dataFormatPtr[DX_SECURE_KEY_ADATA_LEN_OFFSET]     = DX_SECURE_KEY_ADATA_LEN_IN_BYTES;
    dataFormatPtr[DX_SECURE_KEY_ADATA_CONFIG_OFFSET]  = skConfig;
    dataFormatPtr[DX_SECURE_KEY_ADATA_NROUNDS_OFFSET] = skeyNumRounds;
    uint32Ptr                                         = (uint32_t *)&skeyLowerBound;
    uint32Ptr[0]                                      = SWAP_BYTE_ORDER(uint32Ptr[0]);
    uint32Ptr[1]                                      = SWAP_BYTE_ORDER(uint32Ptr[1]);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_LOWER_BOUND_OFFSET], &skeyLowerBound, sizeof(skeyLowerBound));
    uint32Ptr    = (uint32_t *)&skeyUpperBound;
    uint32Ptr[0] = SWAP_BYTE_ORDER(uint32Ptr[0]);
    uint32Ptr[1] = SWAP_BYTE_ORDER(uint32Ptr[1]);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_UPPER_BOUND_OFFSET], &skeyUpperBound, sizeof(skeyLowerBound));
    token = SWAP_BYTE_ORDER(token);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_TOKEN_OFFSET], &token, sizeof(uint32_t));
    skVersion = SWAP_BYTE_ORDER(skVersion);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_VERSION_OFFSET], &skVersion, sizeof(uint32_t));

    if (lNonceCtrBuff != DX_NULL)
        DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_IV_CTR_OFFSET], lNonceCtrBuff, SEP_AES_IV_SIZE);
    else
        DX_PAL_MemSet(&dataFormatPtr[DX_SECURE_KEY_ADATA_IV_CTR_OFFSET], 0, SEP_AES_IV_SIZE);

    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_CTR_RANGE_OFFSET], &dataRange, sizeof(uint32_t));
    if (skeyType != DX_SECURE_KEY_BYPASS) {
        /* key */
        DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], skeyBuf, keySizeInBytes);
    } else {
        DX_PAL_MemSet(&dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], 0, keySizeInBytes);
    }

    /* build the blob configuration word */
    skConfig = skConfig | (skeyNumRounds << DX_SECURE_KEY_RESTRICT_NROUNDS_BIT_SHIFT);
    skConfig = skConfig | (dataRange << DX_SECURE_KEY_RESTRICT_CTR_RANGE_BIT_SHIFT);
    skConfig = SWAP_BYTE_ORDER(skConfig);

    rc = DX_UTIL_encrypt_blob(skeyNonceBuf, dataFormatPtr, &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], macBlob);
    if (rc)
        return rc;
    DX_PAL_MemSet(skeyPackageBuf, 0, sizeof(skeyPackageBuf_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_TOKEN_OFFSET * sizeof(uint32_t)], &token, sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_VERSION_OFFSET * sizeof(uint32_t)], &skVersion, sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_NONCE_OFFSET * sizeof(uint32_t)], skeyNonceBuf,
                   DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_CONFIG_OFFSET * sizeof(uint32_t)], &skConfig,
                   sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_LOWER_BOUNND_OFFSET * sizeof(uint32_t)], &skeyLowerBound,
                   sizeof(uint64_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_UPPER_BOUND_OFFSET * sizeof(uint32_t)], &skeyUpperBound,
                   sizeof(uint64_t));
    if (lNonceCtrBuff != DX_NULL)
        DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_IV_CTR_OFFSET * sizeof(uint32_t)], lNonceCtrBuff,
                       SEP_AES_IV_SIZE);
    else
        DX_PAL_MemSet(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_IV_CTR_OFFSET * sizeof(uint32_t)], 0, SEP_AES_IV_SIZE);
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_KEY_OFFSET * sizeof(uint32_t)],
                   &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_MAC_OFFSET * sizeof(uint32_t)], macBlob, sizeof(macBlob));

    return CRYS_OK;
}

uint32_t DX_UTIL_GenerateSecureKeyMaintenance(skeyNonceBuf_t skeyNonceBuf, uint8_t *skeyBuf,
                                              enum secure_key_type skeyType, uint32_t skeyNumPairs,
                                              skeyPackageBuf_t skeyPackageBuf)
{
    DxError_t rc = DX_UTIL_OK;
    uint8_t dataFormatPtr[DX_SECURE_KEY_CCM_BUF_IN_WORDS * sizeof(uint32_t)];
    CRYS_AESCCM_Mac_Res_t macBlob;
    uint32_t skConfig;
    uint32_t token     = DX_SECURE_KEY_TOKEN_VALUE;
    uint32_t skVersion = DX_SECURE_KEY_VERSION_NUM;
    uint32_t keySizeInBytes;

    /* set constant parameters for dk format */
    enum secure_key_cipher_mode skeyMode    = SEP_CIPHER_CBC;
    enum secure_key_direction skeyDirection = SEP_CRYPTO_DIRECTION_ENCRYPT;
    uint32_t skeyLowerBound                 = 0;
    uint32_t skeyUpperBound                 = 0;

    if (skeyNonceBuf == DX_NULL)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyBuf == DX_NULL)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyPackageBuf == DX_NULL)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if (skeyType != DX_SECURE_KEY_MAINTENANCE)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    if ((skeyNumPairs < DX_SECURE_KEY_MAINTENANCE_MIN_PAIRS) || (skeyNumPairs > DX_SECURE_KEY_MAINTENANCE_MAX_PAIRS))
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;

    keySizeInBytes = 2 * skeyNumPairs * sizeof(uint32_t);

    skConfig = (skeyType << DX_SECURE_KEY_RESTRICT_KEY_TYPE_BIT_SHIFT) |
               (skeyDirection << DX_SECURE_KEY_RESTRICT_DIR_BIT_SHIFT) |
               (skeyMode << DX_SECURE_KEY_RESTRICT_MODE_BIT_SHIFT);

    /* Format the message */
    DX_PAL_MemSet(&dataFormatPtr[DX_SECURE_KEY_B0_FLAGS_OFFSET], 0, DX_SECURE_KEY_CCM_BUF_IN_WORDS * sizeof(uint32_t));
    /* B0 */
    dataFormatPtr[DX_SECURE_KEY_B0_FLAGS_OFFSET] = DX_SECURE_KEY_B0_FLAGS_VALUE;
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_B0_NONCE_OFFSET], skeyNonceBuf, DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    dataFormatPtr[DX_SECURE_KEY_B0_DATA_LEN_OFFSET] = DX_SECURE_KEY_RESTRICT_KEY_SIZE_IN_BYTES;
    /* A */
    dataFormatPtr[DX_SECURE_KEY_ADATA_LEN_OFFSET]     = DX_SECURE_KEY_ADATA_LEN_IN_BYTES;
    dataFormatPtr[DX_SECURE_KEY_ADATA_CONFIG_OFFSET]  = skConfig;
    dataFormatPtr[DX_SECURE_KEY_ADATA_NROUNDS_OFFSET] = skeyNumPairs;
    skeyLowerBound                                    = SWAP_BYTE_ORDER(skeyLowerBound);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_LOWER_BOUND_OFFSET], &skeyLowerBound, sizeof(uint32_t));
    skeyUpperBound = SWAP_BYTE_ORDER(skeyUpperBound);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_UPPER_BOUND_OFFSET], &skeyUpperBound, sizeof(uint32_t));
    token = SWAP_BYTE_ORDER(token);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_TOKEN_OFFSET], &token, sizeof(uint32_t));
    skVersion = SWAP_BYTE_ORDER(skVersion);
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_ADATA_VERSION_OFFSET], &skVersion, sizeof(uint32_t));
    /* key */
    DX_PAL_MemCopy(&dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], skeyBuf, keySizeInBytes);

    /* build the blob configuration word */
    skConfig = skConfig | (skeyNumPairs << DX_SECURE_KEY_RESTRICT_NROUNDS_BIT_SHIFT);
    skConfig = SWAP_BYTE_ORDER(skConfig);

    rc = DX_UTIL_encrypt_blob(skeyNonceBuf, dataFormatPtr, &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], macBlob);
    if (rc)
        return rc;

    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_TOKEN_OFFSET * sizeof(uint32_t)], &token, sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_VERSION_OFFSET * sizeof(uint32_t)], &skVersion, sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_NONCE_OFFSET * sizeof(uint32_t)], skeyNonceBuf,
                   DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_CONFIG_OFFSET * sizeof(uint32_t)], &skConfig,
                   sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_LOWER_BOUNND_OFFSET * sizeof(uint32_t)], &skeyLowerBound,
                   sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_UPPER_BOUND_OFFSET * sizeof(uint32_t)], &skeyUpperBound,
                   sizeof(uint32_t));
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_RESTRICT_KEY_OFFSET * sizeof(uint32_t)],
                   &dataFormatPtr[DX_SECURE_KEY_CCM_KEY_OFFSET], DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);
    DX_PAL_MemCopy(&skeyPackageBuf[DX_SECURE_KEY_MAC_OFFSET * sizeof(uint32_t)], macBlob, sizeof(macBlob));

    return CRYS_OK;
}

static uint32_t DX_UTIL_encrypt_blob(skeyNonceBuf_t skeyNonceBuf, uint8_t *dataIn, uint8_t *plainText,
                                     CRYS_AESCCM_Mac_Res_t macBlob)
{
    struct sep_ctx_cipher *pAesContext;
    CRYS_AESCCM_Mac_Res_t macRes;
    uint8_t counter[SEP_AES_IV_SIZE];
    uint32_t rc;
    uint32_t ctxBuff[CRYS_AES_USER_CTX_SIZE_IN_WORDS] = { 0x0 };

    /* Get pointer to contiguous context in the HOST buffer */
    pAesContext = (struct sep_ctx_cipher *)DX_InitUserCtxLocation(ctxBuff, sizeof(CRYS_AESUserContext_t),
                                                                  sizeof(struct sep_ctx_cipher));
    if (pAesContext == DX_NULL)
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;

    /* A. Perform MAC operation on B0 format, A format, and user key */
    pAesContext->key_size        = SEP_AES_BLOCK_SIZE;
    pAesContext->alg             = SEP_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_CBC_MAC;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_ENCRYPT;
    pAesContext->crypto_key_type = SEP_SESSION_KEY;

    rc = SymDriverAdaptorFinalize((struct sep_ctx_generic *)pAesContext, dataIn, macRes,
                                  DX_SECURE_KEY_CCM_KEY_OFFSET + DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);
    if (rc)
        return rc;
    /* B. Encrypt user key with AES-CTR */
    counter[0] = 0x2;
    DX_PAL_MemCopy(&counter[1], skeyNonceBuf, DX_SECURE_KEY_NONCE_SIZE_IN_BYTES);
    counter[13] = 0x0;
    counter[14] = 0x0;
    counter[15] = 0x1;
    DX_PAL_MemCopy(pAesContext->block_state, counter, SEP_AES_IV_SIZE);
    pAesContext->key_size        = SEP_AES_BLOCK_SIZE;
    pAesContext->alg             = SEP_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_CTR;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_ENCRYPT;
    pAesContext->crypto_key_type = SEP_SESSION_KEY;

    rc = SymDriverAdaptorFinalize((struct sep_ctx_generic *)pAesContext, plainText, plainText,
                                  DX_SECURE_KEY_CCM_KEY_SIZE_IN_BYTES);

    if (rc)
        return rc;

    /* C. Encrypt mac result with AES-CTR */
    counter[15] = 0x0;
    DX_PAL_MemCopy(pAesContext->block_state, counter, SEP_AES_IV_SIZE);

    rc = SymDriverAdaptorFinalize((struct sep_ctx_generic *)pAesContext, macRes, macBlob, sizeof(macRes));

    return rc;
}
