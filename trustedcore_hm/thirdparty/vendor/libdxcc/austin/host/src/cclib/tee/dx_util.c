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
#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "dx_util.h"
#include "dx_util_defs.h"
#include "dx_pal_mutex.h"
#include "dx_pal_abort.h"
#include "sym_adaptor_driver.h"
#include "dx_error.h"
#include "crys_context_relocation.h"
#include "crys_ecpki_types.h"
#include "llf_ecpki.h"
#include "llf_ecpki_export.h"
#include "crys_common.h"
#include "crys_common_math.h"
#include "crys_rnd.h"

extern DX_PAL_MUTEX dxSymCryptoMutex;

/* !
 * Converts Symmetric Adaptor return code to CRYS error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CRYSError_t one of CRYS_* error codes defined in crys_error.h
 */
static DxUTILError_t SymAdaptor2CmacDeriveKeyErr(int symRetCode)
{
    switch (symRetCode) {
    case DX_RET_INVARG:
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    case DX_RET_INVARG_BAD_ADDR:
        return DX_UTIL_BAD_ADDR_ERROR;
    case DX_RET_INVARG_CTX:
    case DX_RET_UNSUPP_ALG:
    default:
        return DX_UTIL_FATAL_ERROR;
    }
}

/* ********************************************************************************* */
/* ***************         CMAC key derivation    ********************************** */
/* ********************************************************************************* */

/* !
 * This function is used to generate bytes stream for key derivation purposes.
 * The function gets an input data and can use use one of the following keys: KDR, Session.
 *
 * @param[in] aesKeyType     - 1 (KDR); 0 (Session)
 * @param[in] pDataIn         - a pointer to input buffer
 * @param[in] dataInSize     - size of data in bytes(min = DX_UTIL_CMAC_DERV_MIN_DATA_IN_SIZE,
 *                             max = DX_UTIL_CMAC_DERV_MAX_DATA_IN_SIZE)
 * @param[out] pCmacResult     - a pointer to output buffer 16 bytes array
 *
 * @return DX_UTIL_OK on success, otherwise failure
 *
 */
DxUTILError_t DX_UTIL_CmacDeriveKey(DX_UTIL_KeyType_t aesKeyType, uint8_t *pDataIn, uint32_t dataInSize,
                                    DX_UTIL_AES_CmacResult_t pCmacResult)
{
    int symRc;
    uint32_t retCode        = 0;
    uint32_t kdrError       = 0;
    uint32_t keySizeInBytes = 0;
    uint32_t ctxBuff[DX_UTIL_BUFF_IN_WORDS];
    struct sep_ctx_cipher *pAesContext =
        (struct sep_ctx_cipher *)DX_InitUserCtxLocation(ctxBuff, DX_UTIL_BUFF_IN_BYTES, sizeof(struct sep_ctx_cipher));
    if (pAesContext == DX_NULL) {
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;
    }
    retCode = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (retCode != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }

    /* Check RKEK error bit */
    DX_UTIL_IS_OTP_KDR_ERROR(kdrError);
    if (kdrError != 0) {
        if (DX_PAL_MutexUnlock(&dxSymCryptoMutex) != DX_SUCCESS) {
            DX_PAL_Abort("Fail to release mutex\n");
        }
        return DX_UTIL_KDR_INVALID_ERROR;
    }

    retCode = DX_PAL_MutexUnlock(&dxSymCryptoMutex);
    if (retCode != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
    }

    /* check inputs */
    if (aesKeyType == DX_UTIL_SESSION_KEY) {
        keySizeInBytes = SEP_AES_128_BIT_KEY_SIZE;
    } else if (aesKeyType != DX_UTIL_KDR_KEY) {
        return DX_UTIL_INVALID_KEY_TYPE;
    }

    if (pDataIn == NULL) {
        return DX_UTIL_DATA_IN_POINTER_INVALID_ERROR;
    }
    if (pCmacResult == NULL) {
        return DX_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    }
    if ((dataInSize < DX_UTIL_CMAC_DERV_MIN_DATA_IN_SIZE) || (dataInSize > DX_UTIL_CMAC_DERV_MAX_DATA_IN_SIZE)) {
        return DX_UTIL_DATA_IN_SIZE_INVALID_ERROR;
    }

    /* ********************************* */
    /* eqviv to CRYS_AES_Init with CMAC */
    /* ********************************* */
    pAesContext->alg             = SEP_CRYPTO_ALG_AES;
    pAesContext->mode            = SEP_CIPHER_CMAC;
    pAesContext->direction       = SEP_CRYPTO_DIRECTION_ENCRYPT;
    pAesContext->crypto_key_type = (aesKeyType == DX_UTIL_SESSION_KEY) ? SEP_SESSION_KEY : SEP_ROOT_KEY;
    pAesContext->key_size =
        keySizeInBytes; // in case of root key, key size is updated in driver init code (InitCipher())
    DX_PAL_MemSetZero(pAesContext->block_state, SEP_AES_BLOCK_SIZE);

    symRc = SymDriverAdaptorInit((struct sep_ctx_generic *)pAesContext);
    if (symRc != 0) {
        return SymAdaptor2CmacDeriveKeyErr(symRc);
    }

    /* ************************************ */
    /* eqviv to CRYS_AES_Finish with CMAC  */
    /* ************************************ */
    /* set the data unit size if first block */
    pAesContext->data_unit_size = dataInSize;
    symRc = SymDriverAdaptorFinalize((struct sep_ctx_generic *)pAesContext, pDataIn, (void *)pCmacResult, dataInSize);

    if (symRc != 0) {
        return SymAdaptor2CmacDeriveKeyErr(symRc);
    }

    return DX_UTIL_OK;
}

/* ********************************************************************************* */
/* ***************         Endorsement key derivation    *************************** */
/* ********************************************************************************* */

extern const CRYS_ECPKI_Domain_t LLF_EC_DOMAINS_ARRAY[];

/* !
 * Derive an ECC256 key-pair from the device root key (KDR)
 *
 * @param[in] domainID         - 1 (DX_UTIL_EK_DomainID_secp256k1); 2 (DX_UTIL_EK_DomainID_secp256r1)
 * @param[out] pPrivKey_ptr     - a pointer to derived ECC256 private key,
 * @param[out] pPublKey_ptr     - a pointer to derived ECC256 public key
 *
 * @return DX_UTIL_OK on success, otherwise failure
 *
 */
DxUTILError_t DX_UTIL_DeriveEndorsementKey(DX_UTIL_EK_DomainID_t domainID, DX_UTIL_EK_Privkey_t *pPrivKey_ptr,
                                           DX_UTIL_EK_Pubkey_t *pPublKey_ptr)
{
    /* reached the stack allowed limit of 1/2K     */
    CRYS_ECPKI_UserPrivKey_t privlKeyBuf;
    CRYS_ECPKI_UserPublKey_t publKeyBuf;
    CRYS_ECPKI_KG_TempData_t tempDataBuf;
    uint8_t cmacResults[DX_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES * DX_UTIL_EK_CMAC_COUNT];
    uint8_t dataIn[DX_UTIL_EK_DATA_IN_CMAC_LENGTH] = { 0 };
    CRYS_ECPKI_DomainID_t crysDomainID;
    uint32_t *tempS_ptr;
    CRYS_ECPKI_PrivKey_t *tempPrivKey_ptr;
    CRYS_ECPKI_PublKey_t *tempPubKey_ptr;
    uint32_t rc;
    uint8_t i = 0;
    uint8_t j;
    uint32_t tmp;

    /* check parameters validity: valid domain and buffer pointers are not NULL */
    if (domainID >= DX_UTIL_EK_DomainID_Max) {
        return DX_UTIL_EK_DOMAIN_INVALID_ERROR;
    }
    if ((pPrivKey_ptr == NULL) || (pPublKey_ptr == NULL)) {
        return DX_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    }
    /* clear outputs */
    DX_PAL_MemSetZero(pPrivKey_ptr, sizeof(DX_UTIL_EK_Privkey_t));
    DX_PAL_MemSetZero(pPublKey_ptr, sizeof(DX_UTIL_EK_Pubkey_t));

    crysDomainID =
        (DX_UTIL_EK_DomainID_secp256k1 == domainID) ? CRYS_ECPKI_DomainID_secp256k1 : CRYS_ECPKI_DomainID_secp256r1;
    /* 1. build data input for aes-cmac 0x01 || 0x45 || 0x00 || domain order || 0x80; and call DX_UTIL_CmacDeriveKey */

    dataIn[i++] = DX_UTIL_EK_PREFIX1_DATA0;
    dataIn[i++] = DX_UTIL_EK_PREFIX_DATA1;
    dataIn[i++] = DX_UTIL_EK_PREFIX_DATA2;
    /* Reverse words order and bytes in each word */
    for (j = DX_UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS; j > 0; j--) {
        tmp         = CRYS_SET_WORD_ENDIANESS(LLF_EC_DOMAINS_ARRAY[crysDomainID].EC_GenerOrder[j - 1]);
        dataIn[i++] = (tmp & 0xFF000000) >> 24;
        dataIn[i++] = (tmp & 0x00FF0000) >> 16;
        dataIn[i++] = (tmp & 0x0000FF00) >> 8;
        dataIn[i++] = (tmp & 0x000000FF);
    }

    dataIn[i] = DX_UTIL_EK_SUFIX_DATA;
    rc        = DX_UTIL_CmacDeriveKey(DX_UTIL_KDR_KEY, dataIn, DX_UTIL_EK_DATA_IN_CMAC_LENGTH, &cmacResults[0]);
    if (rc != DX_UTIL_OK) {
        return rc;
    }
    /* 2. build data input for aes-cmac 0x02 || 0x45 || 0x00 || domain order || 0x80; and call DX_UTIL_CmacDeriveKey */
    dataIn[0] = 0x02;
    rc        = DX_UTIL_CmacDeriveKey(DX_UTIL_KDR_KEY, dataIn, DX_UTIL_EK_DATA_IN_CMAC_LENGTH,
                               &cmacResults[DX_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES]);
    if (rc != DX_UTIL_OK) {
        return rc;
    }
    /* 3. build data input for aes-cmac 0x03 || 0x45 || 0x00 || domain order || 0x80; and call DX_UTIL_CmacDeriveKey */
    dataIn[0] = 0x03;
    rc        = DX_UTIL_CmacDeriveKey(DX_UTIL_KDR_KEY, dataIn, DX_UTIL_EK_DATA_IN_CMAC_LENGTH,
                               &cmacResults[2 * DX_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES]);
    if (rc != DX_UTIL_OK) {
        return rc;
    }

    /* 4. copy  cmacResults into ((LLF_ecpki_key_gen_db_t*)tempDataBuf->crysKGIntBuff)->s; to be used later by
     * LLF_ECPKI_GenKeyPair() */
    tempS_ptr = ((LLF_ecpki_key_gen_db_t *)(&tempDataBuf.crysKGIntBuff[0]))->s;
    /* converts big endianness bytes array (cmacResults) to little endian word array (tempS_ptr) */
    rc = CRYS_COMMON_ConvertMsbLsbBytesToLswMswWords(tempS_ptr, CRYS_ECPKI_ORDER_MAX_LENGTH_IN_WORDS * sizeof(uint32_t),
                                                     cmacResults, sizeof(cmacResults));
    if (rc != 0) {
        return rc;
    }

    /* 5. call LLF_ECPKI_GenKeyPairCall() */
    rc = LLF_ECPKI_GenKeyPairCall(crysDomainID, 0, &privlKeyBuf, &publKeyBuf, &tempDataBuf);
    if (rc != 0) {
        return rc;
    }

    /* 6. copy back results from privlKeyBuf and publKeyBuf to pPrivKey_ptr pPublKey_ptr
     copy private key point */
    tempPrivKey_ptr = ((CRYS_ECPKI_PrivKey_t *)(&privlKeyBuf.PrivKeyDbBuff[0]));
    rc              = CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes((uint8_t *)pPrivKey_ptr, sizeof(DX_UTIL_EK_Privkey_t),
                                                     tempPrivKey_ptr->PrivKey, sizeof(DX_UTIL_EK_Privkey_t));
    if (rc != 0) {
        return rc;
    }
    /* copy public key points X and Y */
    tempPubKey_ptr = ((CRYS_ECPKI_PublKey_t *)(&publKeyBuf.PublKeyDbBuff[0]));
    /* converts little endianness word array (tempPubKey_ptr->PublKeyX) to big endian byte array
     * (pPublKey_ptr->PublKeyX) */
    rc = CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes(pPublKey_ptr->PublKeyX, sizeof(pPublKey_ptr->PublKeyX),
                                                     tempPubKey_ptr->PublKeyX, sizeof(pPublKey_ptr->PublKeyX));
    if (rc != 0) {
        return rc;
    }

    /* converts little endianness word array (tempPubKey_ptr->PublKeyY) to big endian byte array
     * (pPublKey_ptr->PublKeyY) */
    rc = CRYS_COMMON_ConvertLswMswWordsToMsbLsbBytes(pPublKey_ptr->PublKeyY, sizeof(pPublKey_ptr->PublKeyY),
                                                     tempPubKey_ptr->PublKeyY, sizeof(pPublKey_ptr->PublKeyY));
    if (rc != 0) {
        return rc;
    }

    return DX_UTIL_OK;
}

/* ********************************************************************************* */
/* ***************         Session key setting           *************************** */
/* ********************************************************************************* */

/* !
 * @brief This function derives the session key based on random data & Kdr
 *       The output is written to the session key registers.
 *
 *
 * @return DX_UTIL_OK on success, otherwise failure
 */
DxUTILError_t DX_UTIL_SetSessionKey(void)
{
    DxError_t rc = DX_UTIL_OK;
    uint8_t dataIn[DX_UTIL_SK_DATA_IN_CMAC_LENGTH];
    uint32_t cmacResults[DX_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS];
    uint32_t i;

    /* 1. build data input for aes-cmac 0x01 || 0x53 || 0x00 || random data || 0x80 */
    i           = 0;
    dataIn[i++] = DX_UTIL_SK_PREFIX_DATA0;
    dataIn[i++] = DX_UTIL_SK_PREFIX_DATA1;
    dataIn[i++] = DX_UTIL_SK_PREFIX_DATA2;
    rc          = CRYS_RND_GenerateVector(DX_UTIL_SK_RND_DATA_LENGTH, &(dataIn[i]));
    if (rc != CRYS_OK) {
        return rc;
    }
    dataIn[i + DX_UTIL_SK_RND_DATA_LENGTH] = DX_UTIL_SK_SUFIX_DATA;

    /* 2. call DX_UTIL_CmacDeriveKey with generated data */
    rc = DX_UTIL_CmacDeriveKey(DX_UTIL_KDR_KEY, dataIn, DX_UTIL_SK_DATA_IN_CMAC_LENGTH, (uint8_t *)&cmacResults[0]);
    if (rc != DX_UTIL_OK) {
        return rc;
    }
    rc = DX_PAL_MutexLock(&dxSymCryptoMutex, DX_INFINITE);
    if (rc != DX_SUCCESS) {
        DX_PAL_Abort("Fail to acquire mutex\n");
    }
    /* 3. copy cmac results to session key registers */
    for (i = 0; i < DX_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS; i++) {
        DX_HAL_WriteCcRegister((DX_HOST_SESSION_KEY0_REG_OFFSET + 4 * i), CRYS_SET_WORD_ENDIANESS(*(&cmacResults[i])));
    }

    rc = DX_PAL_MutexUnlock(&dxSymCryptoMutex);
    if (rc != DX_SUCCESS) {
        DX_PAL_Abort("Fail to release mutex\n");
    }

    return DX_UTIL_OK;
}
