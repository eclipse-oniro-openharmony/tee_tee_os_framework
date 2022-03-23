/****************************************************************************
* The confidential and proprietary information contained in this file may    *
* only be used by a person authorised under and to the extent permitted      *
* by a subsisting licensing agreement from ARM Limited or its affiliates.    *
* 	(C) COPYRIGHT [2001-2017] ARM Limited or its affiliates.	     *
*	    ALL RIGHTS RESERVED						     *
* This entire notice must be reproduced on all copies of this file           *
* and copies of this file may only be made by a person if such person is     *
* permitted to do so under the terms of a subsisting license agreement       *
* from ARM Limited or its affiliates.					     *
*****************************************************************************/


/************* Include Files ****************/
#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_util_int_defs.h"
#include "cc_util_key_derivation.h"
#include "cc_util_defs.h"
#include "cc_util_cmac.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "sym_adaptor_driver.h"
#include "cc_util.h"
#include "cc_util_error.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_ecpki_domain.h"
#include "cc_ecpki_types.h"
#include "cc_fips_defs.h"
#include "cc_common.h"
#include "cc_common_math.h"
#include "cc_rnd.h"
#include "cc_rnd_error.h"
#include "ec_wrst.h"
#include "cc_hal.h"
#include "cc_fips.h"
#include "pki.h"

extern CC_PalMutex CCSymCryptoMutex;

/************************************************************************************/
/****************         Endorsement key derivation    *****************************/
/************************************************************************************/


/*!
 * Derive an ECC256 key-pair from the device root key (KDR)
 *
 * @param[in] domainID 		- 1 (CC_UTIL_EK_DomainID_secp256k1); 2 (CC_UTIL_EK_DomainID_secp256r1)
 * @param[out] pPrivKey_ptr 	- a pointer to derived ECC256 private key,
 * @param[out] pPublKey_ptr 	- a pointer to derived ECC256 public key
 *
 * @return CC_UTIL_OK on success, otherwise failure
 *
 */

CCUtilError_t CC_UtilDeriveEndorsementKey(CCUtilEkDomainID_t  	  domainID,
					  CCUtilEkPrivkey_t      *pEkPrivKey,
					  CCUtilEkPubkey_t       *pEkPublKey,
					  CCUtilEkTempData_t     *pTempDataBuf,
					  CCRndContext_t         *pRndContext,
					  CCUtilEkFipsContext_t  *pEkFipsCtx)
{
	/* ??? reached the stack allowed limit of 1/2K */
        /* pointers to Ecc Keys buffers */
	CCEcpkiUserPrivKey_t  *pUserPrivKey = &pTempDataBuf->privKeyBuf;
	CCEcpkiUserPublKey_t  *pUserPublKey = &pTempDataBuf->publKeyBuf;
        /* pointers to inner data of key structures */
	CCEcpkiPrivKey_t      *pPrivKey = ((CCEcpkiPrivKey_t*)&pUserPrivKey->PrivKeyDbBuff[0]);
	CCEcpkiPublKey_t      *pPublKey  = ((CCEcpkiPublKey_t *)&pUserPublKey->PublKeyDbBuff[0]);
	uint32_t               cmacResults[UTIL_EK_ECC256_FULL_RANDOM_LENGTH_IN_WORDS];
	CCEcpkiDomainID_t      ccDomainID;
	uint32_t               rc;
	uint32_t               i = 0, j;
	const CCEcpkiDomain_t *pDomain;
	uint8_t label[] = {UTIL_EK_LABEL};
	uint8_t context[UTIL_EK_ECC256_ORDER_LENGTH];


	/* check parameters validity: valid domain and buffer pointers are not NULL */

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	if ((NULL == pEkPrivKey) ||
	    (NULL == pEkPublKey)) {
		return CC_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
	}
	if (NULL == pTempDataBuf) {
		return CC_UTIL_ILLEGAL_PARAMS_ERROR;
	}

	switch(domainID){
	case CC_UTIL_EK_DomainID_secp256k1:
		ccDomainID = CC_ECPKI_DomainID_secp256k1;
		break;
	case CC_UTIL_EK_DomainID_secp256r1:
		ccDomainID = CC_ECPKI_DomainID_secp256r1;
		break;
	default:
		return CC_UTIL_EK_DOMAIN_INVALID_ERROR;
	}


        /* The key can't be derived in RMA, SD and temporary SD as the Kdr is being mask or random. */
	CC_UTIL_GET_LCS(rc);
	if( (rc == CC_LCS_SECURITY_DISABLED_LCS) || (rc == CC_LCS_RMA_LCS) )
		return CC_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR;

	pDomain = CC_EcpkiGetEcDomain(ccDomainID);
	if (pDomain == NULL) {
		return CC_UTIL_EK_DOMAIN_INVALID_ERROR;
        }


        /* 1. build data input for aes-cmac 0x01 || 0x45 || 0x00 || domain order || 0x80 */
	/* Reverse words order and bytes in each word */
	for (j = UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS; j > 0; j--) {
		uint32_t tmp = CC_SET_WORD_ENDIANESS(pDomain->ecR[j-1]);
		context[i++] = (tmp & 0xFF000000)>>24;
		context[i++] = (tmp & 0x00FF0000)>>16;
		context[i++] = (tmp & 0x0000FF00)>>8;
		context[i++] = (tmp & 0x000000FF);
	}

        /* 2.  generate pseudorandom bytes of size EC order + addit. 8 bytes (according to FIPS 186-3, B.4.1) */
        rc = CC_UtilKeyDerivation(CC_UTIL_ROOT_KEY, NULL,
                                (const uint8_t *)&label, sizeof(label),
                                (const uint8_t *)&context,
                                (size_t)UTIL_EK_ECC256_ORDER_LENGTH,
                                (uint8_t*)cmacResults,
                                (size_t)UTIL_EK_ECC256_FULL_RANDOM_LENGTH);
	if (rc != CC_UTIL_OK) {
		return rc;
	}

        /* convert big endianness bytes array cmacResults to little endian words array */
        CC_CommonInPlaceConvertBytesWordsAndArrayEndianness(cmacResults, UTIL_EK_ECC256_FULL_RANDOM_LENGTH_IN_WORDS);


        /* using ecpkiKgTempData temp buff. for EC order n */
        CC_PalMemCopy((uint8_t*)&pTempDataBuf->ecpkiKgTempData, (uint8_t*)&pDomain->ecR, UTIL_EK_ECC256_ORDER_LENGTH);
        ((uint32_t*)&pTempDataBuf->ecpkiKgTempData)[0] &= ~1; /* n -= 1 */

        /* 3. modular reduction of full pseudorandom number to be in range [1, n-1] (FIPS 186-3, B.4.1) */
        rc = PkiLongNumDiv(cmacResults/*numerator*/,
                           UTIL_EK_ECC256_FULL_RANDOM_LENGTH_IN_WORDS,
                           (uint32_t*)&pTempDataBuf->ecpkiKgTempData/*divider: n-1*/,
                           UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS,
                           pPrivKey->PrivKey/*modular result)*/,
                           NULL); /*not need*/

        if (rc != CC_UTIL_OK) {
                return rc;
        }

        /* increment the modular result */
        rc = CC_CommonIncLsbUnsignedCounter(pPrivKey->PrivKey, 1, UTIL_EK_ECC256_ORDER_LENGTH_IN_WORDS);
        if (rc != 0) {
                goto End;
        }

	/* 4. ECC key pair generation */
	rc = EcWrstGenKeyPair(pDomain,
			      pUserPrivKey,
			      pUserPublKey,
			      &pTempDataBuf->ecpkiKgTempData);
	if (rc != 0) {
		return rc;
	}

        rc = FIPS_ECC_VALIDATE(pRndContext, pUserPrivKey, pUserPublKey, pEkFipsCtx);
	if (rc != 0) {
		goto End;
	}

	/* 5. output result privlKeyBuf and publKeyBuf in BE bytes form  */
	rc = CC_CommonConvertLswMswWordsToMsbLsbBytes(pEkPrivKey->PrivKey, UTIL_EK_ECC256_ORDER_LENGTH,
                                                pPrivKey->PrivKey, UTIL_EK_ECC256_ORDER_LENGTH);
	if (rc != 0) {
		goto End;
	}
	/* copy public key point (X,Y) */
	rc = CC_CommonConvertLswMswWordsToMsbLsbBytes(pEkPublKey->PublKeyX, CC_UTIL_EK_BUFF_MAX_LENGTH,
						pPublKey->x, CC_UTIL_EK_BUFF_MAX_LENGTH);
	if (rc != 0) {
		goto End;
	}

	/* convert to little endianness word array (tempPubKey_ptr->PublKeyY) to big endian byte array (pPublKey_ptr->PublKeyY) */
	rc = CC_CommonConvertLswMswWordsToMsbLsbBytes(pEkPublKey->PublKeyY, CC_UTIL_EK_BUFF_MAX_LENGTH,
						pPublKey->y, CC_UTIL_EK_BUFF_MAX_LENGTH);
	if (rc != 0) {
		goto End;
	}

End:
	CC_PalMemSetZero(pTempDataBuf, sizeof(CCUtilEkTempData_t));
	if (pEkFipsCtx != NULL) {
		CC_PalMemSetZero(pEkFipsCtx, sizeof(CCUtilEkFipsContext_t));
	}
	if (rc != 0) {
		CC_PalMemSetZero(pEkPrivKey, sizeof(CCUtilEkPrivkey_t));
		CC_PalMemSetZero(pEkPublKey, sizeof(CCUtilEkPubkey_t));
	}

	return rc;
}


/************************************************************************************/
/****************         Session key setting           *****************************/
/************************************************************************************/

/*!
 * @brief This function derives the session key based on random data & Kdr
 * 	  The output is written to the session key registers.
 *
 * @param[in/out] rndContext_ptr  - Pointer to the RND context buffer.
 *
 * @return CC_UTIL_OK on success, otherwise failure
 */

CCUtilError_t CC_UtilSetSessionKey(CCRndContext_t *pRndContext)
{
	CCError_t  rc = CC_UTIL_OK;
	uint32_t cmacResults[CC_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS];
	uint32_t i;
	CCRndState_t   *rndState_ptr;
	CCRndGenerateVectWorkFunc_t RndGenerateVectFunc;

	uint8_t label[] = {UTIL_SK_LABEL};
	uint8_t context[UTIL_SK_RND_DATA_BYTE_LENGTH];

	/* check parameters */

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	if (pRndContext == NULL)
		return CC_RND_CONTEXT_PTR_INVALID_ERROR;

	rndState_ptr = &(pRndContext->rndState);
	RndGenerateVectFunc = pRndContext->rndGenerateVectFunc;

	if (RndGenerateVectFunc == NULL)
		return CC_RND_GEN_VECTOR_FUNC_ERROR;

	/* 1. build data input for aes-cmac 0x01 || 0x53 || 0x00 || 96bit random data || 0x80 */
	rc = RndGenerateVectFunc(rndState_ptr, UTIL_SK_RND_DATA_BYTE_LENGTH, context);
	if (rc != CC_OK) {
		return rc;
	}

	/* 2. derived new key based on Kdr */
	rc = CC_UtilKeyDerivation(CC_UTIL_ROOT_KEY, NULL,
				    (const unsigned char *)&label, sizeof(label),
				    (const uint8_t *)&context, UTIL_SK_RND_DATA_BYTE_LENGTH,
				    (uint8_t*)&cmacResults[0], CC_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);


	rc = CC_PalMutexLock(&CCSymCryptoMutex, CC_INFINITE);
	if (rc != CC_SUCCESS) {
		CC_PalAbort("Fail to acquire mutex\n");
	}
	/* 3. copy cmac results to session key registers */
	for (i=0 ; i<CC_UTIL_AES_CMAC_RESULT_SIZE_IN_WORDS ; i++) {
		CC_HAL_WRITE_REGISTER((DX_HOST_SESSION_KEY0_REG_OFFSET + 4*i),CC_SET_WORD_ENDIANESS(*(&cmacResults[i])));
	}

	rc = CC_PalMutexUnlock(&CCSymCryptoMutex);
	if (rc != CC_SUCCESS) {
		CC_PalAbort("Fail to release mutex\n");
	}

	return CC_UTIL_OK;
}


CCUtilError_t CC_UtilSetSecurityDisable(void)
{

	uint32_t regVal = 0;
	CCError_t error = CC_OK;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	CC_UTIL_GET_LCS(regVal);
	if (regVal == CC_LCS_SECURITY_DISABLED_LCS)
		return error;

	if (regVal == CC_LCS_RMA_LCS) {
		return CC_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR;
	}

	/* Write the zeroes to the session key registers */
	regVal = 0;
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_SESSION_KEY0), regVal);
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_SESSION_KEY1), regVal);
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_SESSION_KEY2), regVal);
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_SESSION_KEY3), regVal);

	/* Sets the security disabled register */
	CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF,HOST_CPC_SECURITY_DISABLE), regVal);

	/* Poll on the LCS valid register */
	CC_UTIL_WAIT_ON_LCS_VALID_BIT(regVal);							\

	/* Verify new LCS */
	CC_UTIL_GET_LCS(regVal);
	if (regVal != CC_LCS_SECURITY_DISABLED_LCS)
		return CC_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR;

	return CC_UTIL_OK;
}


