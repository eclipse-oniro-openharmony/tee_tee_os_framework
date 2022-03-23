/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "ssi_util_int_defs.h"
#include "ssi_util_key_derivation.h"
#include "ssi_util_defs.h"
#include "ssi_util_cmac.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "sym_adaptor_driver.h"
#include "ssi_util.h"
#include "ssi_util_error.h"
#include "ssi_error.h"
#include "sasi_context_relocation.h"
#include "sasi_ecpki_domain.h"
#include "sasi_ecpki_types.h"
#include "sasi_fips_defs.h"
#include "sasi_common.h"
#include "sasi_common_math.h"
#include "sasi_rnd.h"
#include "sasi_rnd_error.h"
#include "pka_ecc_export.h"
#include "ssi_hal.h"

extern SaSi_PalMutex sasiSymCryptoMutex;

/* ********************************************************************************* */
/* ***************         Endorsement key derivation    *************************** */
/* ********************************************************************************* */

/* !
 * Derive an ECC256 key-pair from the device root key (KDR)
 *
 * @param[in] domainID         - 1 (SASI_UTIL_EK_DomainID_secp256k1); 2 (SASI_UTIL_EK_DomainID_secp256r1)
 * @param[out] pPrivKey_ptr     - a pointer to derived ECC256 private key,
 * @param[out] pPublKey_ptr     - a pointer to derived ECC256 public key
 *
 * @return SASI_UTIL_OK on success, otherwise failure
 *
 */

SaSiUtilError_t SaSi_UtilDeriveEndorsementKey(SASI_UTIL_EK_DomainID_t domainID, SASI_UTIL_EK_Privkey_t *pPrivKey_ptr,
                                              SASI_UTIL_EK_Pubkey_t *pPublKey_ptr,
                                              SASI_UTIL_EK_TempData_t *pTempDataBuf, SaSi_RND_Context_t *pRndContext,
                                              SASI_UTIL_EK_FipsContext_t *pEkFipsCtx)
{
    /* reached the stack allowed limit of 1/2K */
    SaSi_ECPKI_UserPrivKey_t privlKeyBuf;
    SaSi_ECPKI_UserPublKey_t publKeyBuf;
    uint8_t cmacResults[SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES * SASI_UTIL_EK_CMAC_COUNT];
    SaSi_ECPKI_DomainID_t sasiDomainID;
    uint32_t *tempS_ptr;
    SaSi_ECPKI_PrivKey_t *tempPrivKey_ptr;
    struct SaSi_ECPKI_PublKey_t *tempPubKey_ptr;
    uint32_t rc;
    uint8_t i = 0;
    uint8_t j;
    uint32_t tmp;
    const SaSi_ECPKI_Domain_t *Domain_ptr;
    uint8_t label[] = { SASI_UTIL_EK_LABEL };
    uint8_t context[SASI_UTIL_EK_ECC256_ORDER_LENGTH];

    /* check parameters validity: valid domain and buffer pointers are not NULL */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (domainID >= SASI_UTIL_EK_DomainID_Max) {
        return SASI_UTIL_EK_DOMAIN_INVALID_ERROR;
    }
    if ((pPrivKey_ptr == NULL) || (pPublKey_ptr == NULL)) {
        return SASI_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    }
    if (pTempDataBuf == NULL) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }
    /* clear outputs */
    SaSi_PalMemSetZero(pPrivKey_ptr, sizeof(SASI_UTIL_EK_Privkey_t));
    SaSi_PalMemSetZero(pPublKey_ptr, sizeof(SASI_UTIL_EK_Pubkey_t));

    sasiDomainID =
        (SASI_UTIL_EK_DomainID_secp256k1 == domainID) ? SaSi_ECPKI_DomainID_secp256k1 : SaSi_ECPKI_DomainID_secp256r1;
    Domain_ptr = SaSi_ECPKI_GetEcDomain(sasiDomainID);
    if (Domain_ptr == NULL) {
        return SASI_UTIL_EK_DOMAIN_INVALID_ERROR;
    }

    /* 1. build data input for aes-cmac 0x01 || 0x45 || 0x00 || domain order || 0x80 */
    /* Reverse words order and bytes in each word */
    for (j = SASI_UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS; j > 0; j--) {
        tmp          = SaSi_SET_WORD_ENDIANESS(Domain_ptr->ecR[j - 1]);
        context[i++] = (tmp & 0xFF000000) >> 24;
        context[i++] = (tmp & 0x00FF0000) >> 16;
        context[i++] = (tmp & 0x0000FF00) >> 8;
        context[i++] = (tmp & 0x000000FF);
    }

    rc = SaSi_UtilKeyDerivation(SASI_UTIL_ROOT_KEY, NULL, (const uint8_t *)&label, sizeof(label),
                                (const uint8_t *)&context, (size_t)SASI_UTIL_EK_ECC256_ORDER_LENGTH, cmacResults,
                                sizeof(cmacResults));
    if (rc != SASI_UTIL_OK) {
        return rc;
    }

    /* 4. copy  cmacResults into ((LLF_ecpki_key_gen_db_t*)tempDataBuf->sasiKGIntBuff)->s; to be used later by
     * LLF_ECPKI_GenKeyPair() */
    tempS_ptr = ((SaSi_ECPKI_PrivKey_t *)(&privlKeyBuf.PrivKeyDbBuff))->PrivKey;
    /* converts big endianness bytes array (cmacResults) to little endian word array (tempS_ptr) */
    rc = SaSi_COMMON_ConvertMsbLsbBytesToLswMswWords(tempS_ptr, SaSi_ECPKI_ORDER_MAX_LENGTH_IN_WORDS * sizeof(uint32_t),
                                                     cmacResults, sizeof(cmacResults));
    if (rc != 0) {
        return rc;
    }

    /* 5. call LLF_ECPKI_GenKeyPairCall() */
    rc = LLF_ECPKI_GenKeyPair(SaSi_ECPKI_GetEcDomain(sasiDomainID), &privlKeyBuf, &publKeyBuf, pTempDataBuf);
    if (rc != 0) {
        return rc;
    }

    rc = FIPS_ECC_VALIDATE(pRndContext, &privlKeyBuf, &publKeyBuf, pEkFipsCtx);
    if (rc != 0) {
        goto End;
    }

    /* 6. copy back results from privlKeyBuf and publKeyBuf to pPrivKey_ptr pPublKey_ptr
     copy private key point */
    tempPrivKey_ptr = ((SaSi_ECPKI_PrivKey_t *)(&privlKeyBuf.PrivKeyDbBuff[0]));
    rc = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes((uint8_t *)pPrivKey_ptr, sizeof(SASI_UTIL_EK_Privkey_t),
                                                     tempPrivKey_ptr->PrivKey, sizeof(SASI_UTIL_EK_Privkey_t));
    if (rc != 0) {
        goto End;
    }
    /* copy public key points X and Y */
    tempPubKey_ptr = ((struct SaSi_ECPKI_PublKey_t *)(&publKeyBuf.PublKeyDbBuff[0]));
    /* converts little endianness word array (tempPubKey_ptr->PublKeyX) to big endian byte array
     * (pPublKey_ptr->PublKeyX) */
    rc = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(pPublKey_ptr->PublKeyX, sizeof(pPublKey_ptr->PublKeyX),
                                                     tempPubKey_ptr->x, sizeof(pPublKey_ptr->PublKeyX));
    if (rc != 0) {
        goto End;
    }

    /* converts little endianness word array (tempPubKey_ptr->PublKeyY) to big endian byte array
     * (pPublKey_ptr->PublKeyY) */
    rc = SaSi_COMMON_ConvertLswMswWordsToMsbLsbBytes(pPublKey_ptr->PublKeyY, sizeof(pPublKey_ptr->PublKeyY),
                                                     tempPubKey_ptr->y, sizeof(pPublKey_ptr->PublKeyY));

End:
    SaSi_PalMemSetZero(pTempDataBuf, sizeof(SASI_UTIL_EK_TempData_t));
    if (pEkFipsCtx != NULL) {
        SaSi_PalMemSetZero(pEkFipsCtx, sizeof(SASI_UTIL_EK_FipsContext_t));
    }
    if (rc != 0) {
        SaSi_PalMemSetZero(pPrivKey_ptr, sizeof(SASI_UTIL_EK_Privkey_t));
        SaSi_PalMemSetZero(pPublKey_ptr, sizeof(SASI_UTIL_EK_Pubkey_t));
    }

    return rc;
}

/* ********************************************************************************* */
/* ***************         Session key setting           *************************** */
/* ********************************************************************************* */

/* !
 * @brief This function derives the session key based on random data & Kdr
 *       The output is written to the session key registers.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 *
 * @return SASI_UTIL_OK on success, otherwise failure
 */

SaSiUtilError_t SaSi_UtilSetSessionKey(SaSi_RND_Context_t *pRndContext)
{
    SaSiError_t rc = SASI_UTIL_OK;
    uint32_t cmacResults[SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS];
    uint32_t i;
    SaSi_RND_State_t *rndState_ptr;
    SaSiRndGenerateVectWorkFunc_t RndGenerateVectFunc;

    uint8_t label[] = { SASI_UTIL_SK_LABEL };
    uint8_t context[SASI_UTIL_SK_RND_DATA_LENGTH];

    /* check parameters */

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    if (pRndContext == NULL)
        return SaSi_RND_CONTEXT_PTR_INVALID_ERROR;

    rndState_ptr        = &(pRndContext->rndState);
    RndGenerateVectFunc = pRndContext->rndGenerateVectFunc;

    if (RndGenerateVectFunc == NULL)
        return SaSi_RND_GEN_VECTOR_FUNC_ERROR;

    /* 1. build data input for aes-cmac 0x01 || 0x53 || 0x00 || random data || 0x80 */
    rc = RndGenerateVectFunc(rndState_ptr, SASI_UTIL_SK_RND_DATA_LENGTH, context);
    if (rc != SaSi_OK) {
        return rc;
    }

    rc = SaSi_UtilKeyDerivation(SASI_UTIL_ROOT_KEY, NULL, (const unsigned char *)&label, sizeof(label),
                                (const uint8_t *)&context, SASI_UTIL_SK_RND_DATA_LENGTH, (uint8_t *)&cmacResults[0],
                                SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);

    rc = SaSi_PalMutexLock(&sasiSymCryptoMutex, SASI_INFINITE);
    if (rc != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }
    /* 3. copy cmac results to session key registers */
    for (i = 0; i < SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS; i++) {
        SASI_HAL_WRITE_REGISTER((DX_HOST_SESSION_KEY0_REG_OFFSET + 4 * i), SaSi_SET_WORD_ENDIANESS(*(&cmacResults[i])));
    }

    rc = SaSi_PalMutexUnlock(&sasiSymCryptoMutex);
    if (rc != SASI_SUCCESS) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return SASI_UTIL_OK;
}

SaSiUtilError_t SaSi_UtilSetSecurityDisable(void)
{
    uint32_t regVal   = 0;
    SaSiError_t error = SASI_OK;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    SASI_UTIL_GET_LCS(regVal);
    if (regVal == SASI_LCS_SECURITY_DISABLED_LCS)
        return error;

    if (regVal == SASI_LCS_RMA_LCS) {
        return SASI_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR;
    }

    /* Write the zeroes to the session key registers */
    regVal = 0;
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_SESSION_KEY0), regVal);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_SESSION_KEY1), regVal);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_SESSION_KEY2), regVal);
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_SESSION_KEY3), regVal);

    /* Sets the security disabled register */
    SASI_HAL_WRITE_REGISTER(SASI_REG_OFFSET(HOST_RGF, HOST_CPC_SECURITY_DISABLE), regVal);

    /* Verify new LCS */
    SASI_UTIL_GET_LCS(regVal);
    if (regVal != SASI_LCS_SECURITY_DISABLED_LCS)
        return SASI_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR;

    return SASI_UTIL_OK;
}
