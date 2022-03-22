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

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_CC_API

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_hal.h"
#include "cc_aes.h"
#include "cc_aes_error.h"
#include "sym_adaptor_driver.h"
#include "cipher.h"
#include "cc_crypto_ctx.h"
#include "dma_buffer.h"
#include "cc_sym_error.h"
#include "cc_crypto_ctx.h"
#include "cc_context_relocation.h"
#include "cc_pal_perf.h"
#include "cc_fips_defs.h"


#define CC_AES_REQUIRED_CTX_SIZE  2*CC_DRV_CTX_SIZE_WORDS+3
#define AES_XTS_MAX_BLOCK_SIZE          0x100000

CC_PAL_COMPILER_ASSERT(CC_AES_REQUIRED_CTX_SIZE == CC_AES_USER_CTX_SIZE_IN_WORDS, "CC_AES_USER_CTX_SIZE_IN_WORDS is not defined correctly!");

CC_PAL_COMPILER_ASSERT((uint32_t)CC_AES_PADDING_NONE == (uint32_t)DRV_PADDING_NONE, "Aes padding type enum mismatch!");
CC_PAL_COMPILER_ASSERT((uint32_t)CC_AES_PADDING_PKCS7 == (uint32_t)DRV_PADDING_PKCS7, "Aes padding type enum mismatch!");

CC_PAL_COMPILER_ASSERT((uint32_t)CC_AES_ENCRYPT == (uint32_t)DRV_CRYPTO_DIRECTION_ENCRYPT, "Aes direction enum mismatch!");
CC_PAL_COMPILER_ASSERT((uint32_t)CC_AES_DECRYPT == (uint32_t)DRV_CRYPTO_DIRECTION_DECRYPT, "Aes direction enum mismatch!");


#define CC_LIB_IS_KCST_DISABLE(regVal) 							\
	do { 											\
		regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_KCST_DISABLE)); 	\
		regVal = CC_REG_FLD_GET(0, HOST_KCST_DISABLE, VALUE, regVal); 		\
	}while(0)

#define CC_LIB_IS_KPLT_VALID(regVal) 								\
	do { 											\
		regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_KPLT_VALID)); 	\
		regVal = CC_REG_FLD_GET(0, HOST_KPLT_VALID, VALUE, regVal); 			\
	}while(0)

#define CC_LIB_IS_KCST_VALID(regVal) 								\
	do { 											\
		regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_KCST_VALID)); 	\
		regVal = CC_REG_FLD_GET(0, HOST_KCST_VALID, VALUE, regVal); 			\
	}while(0)

/*!
 * Converts Symmetric Adaptor return code to CryptoCell error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_aes_error.h
 */
static CCError_t SymAdaptor2CCAesErr(int symRetCode, uint32_t errorInfo)
{
	errorInfo = errorInfo;
	switch (symRetCode) {
	case CC_RET_UNSUPP_ALG:
		return CC_AES_IS_NOT_SUPPORTED;
	case CC_RET_UNSUPP_ALG_MODE:
	case CC_RET_UNSUPP_OPERATION:
		return CC_AES_ILLEGAL_OPERATION_MODE_ERROR;
	case CC_RET_INVARG:
		return CC_AES_ILLEGAL_PARAMS_ERROR;
	case CC_RET_INVARG_KEY_SIZE:
		return CC_AES_ILLEGAL_KEY_SIZE_ERROR;
	case CC_RET_INVARG_CTX_IDX:
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	case CC_RET_INVARG_CTX:
		return CC_AES_USER_CONTEXT_CORRUPTED_ERROR;
	case CC_RET_INVARG_BAD_ADDR:
		return CC_AES_DATA_IN_POINTER_INVALID_ERROR;
	case CC_RET_NOMEM:
		return CC_OUT_OF_RESOURCE_ERROR;
	case CC_RET_INVARG_INCONSIST_DMA_TYPE:
		return CC_ILLEGAL_RESOURCE_VAL_ERROR;
	case CC_RET_PERM:
	case CC_RET_NOEXEC:
	case CC_RET_BUSY:
	case CC_RET_OSFAULT:
	default:
		return CC_FATAL_ERROR;
	}
}

static enum drv_cipher_mode MakeSepAesMode(CCAesOperationMode_t operationMode)
{
	switch (operationMode) {
	case CC_AES_MODE_ECB:
		return DRV_CIPHER_ECB;
	case CC_AES_MODE_CBC:
		return DRV_CIPHER_CBC;
	case CC_AES_MODE_CBC_MAC:
		return DRV_CIPHER_CBC_MAC;
	case CC_AES_MODE_CTR:
		return DRV_CIPHER_CTR;
	case CC_AES_MODE_XCBC_MAC:
		return DRV_CIPHER_XCBC_MAC;
	case CC_AES_MODE_CMAC:
		return DRV_CIPHER_CMAC;
	case CC_AES_MODE_XTS:
		return DRV_CIPHER_XTS;
	case CC_AES_MODE_OFB:
		return DRV_CIPHER_OFB;
	case CC_AES_MODE_CBC_CTS:
		return DRV_CIPHER_CBC_CTS;
	default:
		return DRV_CIPHER_NULL_MODE;
	}

}

static enum drv_crypto_padding_type MakeSepCryptoPaddingType(CCAesPaddingType_t type)
{
	// Conversion is not required
	// We force both enums to have the same values using CC_PAL_COMPILER_ASSERT
	return (enum drv_crypto_padding_type)type;
}

static enum drv_crypto_direction MakeSepCryptoDirection(CCAesEncryptMode_t direction)
{
	// Conversion is not required
	// We force both enums to have the same values using CC_PAL_COMPILER_ASSERT
	return (enum drv_crypto_direction)direction;
}

static enum drv_crypto_key_type MakeSepAesKeyType(CCAesKeyType_t keyType)
{
	switch (keyType) {
	case CC_AES_USER_KEY:
		return DRV_USER_KEY;
	case CC_AES_PLATFORM_KEY:
		return DRV_PLATFORM_KEY;
	case CC_AES_CUSTOMER_KEY:
		return DRV_CUSTOMER_KEY;
	default:
		return DRV_NULL_KEY;
	}
}


CIMPORT_C CCError_t  CC_AesInit(
	CCAesUserContext_t * pContext,
	CCAesEncryptMode_t   encryptDecryptFlag,
	CCAesOperationMode_t operationMode,
	CCAesPaddingType_t   paddingType )
{
	struct drv_ctx_cipher *pAesCtx;

	CCPalPerfData_t perfIdx = 0;
	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_AES_INIT);

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* checking validity of the input parameters */

	/* if the users context ID pointer is NULL return an error */
	if (pContext == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* check if the operation mode is legal */
	if (operationMode >= CC_AES_NUM_OF_OPERATION_MODES) {
		return CC_AES_ILLEGAL_OPERATION_MODE_ERROR;
	}

	/* check the Encrypt / Decrypt flag validity */
	if (encryptDecryptFlag >= CC_AES_NUM_OF_ENCRYPT_MODES) {
		return CC_AES_INVALID_ENCRYPT_MODE_ERROR;
	}

	/* check if the padding type is legal */
	if (paddingType >= CC_AES_NUM_OF_PADDING_TYPES) {
		return CC_AES_ILLEGAL_PADDING_TYPE_ERROR;
	}
	/* we support pkcs7 padding only for ECB, CBC, MAC operation modes. */
	if ( (paddingType ==  CC_AES_PADDING_PKCS7) &&
	     ((operationMode != CC_AES_MODE_ECB) &&
	      (operationMode != CC_AES_MODE_CBC) &&
	      (operationMode != CC_AES_MODE_CBC_MAC)) ) {
		return CC_AES_ILLEGAL_PADDING_TYPE_ERROR;
	}

	/* in MAC,XCBC,CMAC modes enable only encrypt mode  */
	if ( ((operationMode == CC_AES_MODE_XCBC_MAC) ||
	      (operationMode == CC_AES_MODE_CMAC) ||
	      (operationMode == CC_AES_MODE_CBC_MAC)) &&
	     (encryptDecryptFlag != CC_AES_ENCRYPT) ) {
		return CC_AES_DECRYPTION_NOT_ALLOWED_ON_THIS_MODE;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAesCtx = (struct drv_ctx_cipher *)RcInitUserCtxLocation(pContext->buff,
								    sizeof(CCAesUserContext_t),
								    sizeof(struct drv_ctx_cipher));
	if (pAesCtx == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}
	CC_PalMemSetZero(pAesCtx, sizeof(struct drv_ctx_cipher));

	pAesCtx->alg = DRV_CRYPTO_ALG_AES;
	pAesCtx->mode = MakeSepAesMode(operationMode);
	pAesCtx->padding_type = MakeSepCryptoPaddingType(paddingType);
	pAesCtx->direction = MakeSepCryptoDirection(encryptDecryptFlag);

	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_AES_INIT);

	return CC_OK;
}


CIMPORT_C CCError_t  CC_AesSetKey(
	CCAesUserContext_t *  pContext,
	CCAesKeyType_t        keyType,
	void *                  pKeyData,
	size_t                  keyDataSize )
{
	int symRc;
	struct drv_ctx_cipher *pAesCtx;
	CCAesUserKeyData_t *pUserKeyData;
	uint32_t regVal;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	CCPalPerfData_t perfIdx = 0;
	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_AES_SET_KEY);

	/* if the users context ID pointer is NULL return an error */
	if (pContext == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAesCtx = (struct drv_ctx_cipher *)RcGetUserCtxLocation(pContext->buff);
	if (pAesCtx == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* TODO: check that AesInit was already called */


	/* update key information in the context */
	pAesCtx->crypto_key_type = MakeSepAesKeyType(keyType);
	if (pAesCtx->crypto_key_type == DRV_NULL_KEY)
		return CC_AES_KEY_TYPE_NOT_SUPPORTED_ERROR;


	/* case of CC_AES_USER_KEY */
	if (keyType == CC_AES_USER_KEY) {

		/* check the validity of the key data pointer */
		if (pKeyData == NULL) {
			return CC_AES_INVALID_KEY_POINTER_ERROR;
		}

		if (keyDataSize != sizeof(CCAesUserKeyData_t)) {
			return CC_AES_INVALID_KEY_POINTER_ERROR;
		}

		/* casting from void* to CCAesUserKeyData_t* */
		pUserKeyData = (CCAesUserKeyData_t*)pKeyData;

		/* check key size validity in various modes */
		if (pAesCtx->mode == DRV_CIPHER_XCBC_MAC) {
			if (pUserKeyData->keySize != CC_AES_128_BIT_KEY_SIZE){
				/* in XCBC_MAC mode, key size should be only 128 bit */
				return CC_AES_ILLEGAL_KEY_SIZE_ERROR;
			}
		} else if (pAesCtx->mode == DRV_CIPHER_XTS) {
			if ( (pUserKeyData->keySize != CC_AES_256_BIT_KEY_SIZE) &&
			     (pUserKeyData->keySize != 2*CC_AES_256_BIT_KEY_SIZE) ) {
				/* in XTS mode, key size should be only 256/512 bit */
				return CC_AES_ILLEGAL_KEY_SIZE_ERROR;
			}
                        /* xts weak keys verification */
                        if ((pUserKeyData->keySize == CC_AES_256_BIT_KEY_SIZE) && (CC_PalMemCmp(pUserKeyData->pKey, ((uint8_t*)pUserKeyData->pKey) + (CC_AES_256_BIT_KEY_SIZE >> 1), CC_AES_256_BIT_KEY_SIZE >> 1) == 0)) {
                                return CC_AES_ILLEGAL_PARAMS_ERROR;
                        }
                        if ((pUserKeyData->keySize == 2 * CC_AES_256_BIT_KEY_SIZE) && (CC_PalMemCmp(pUserKeyData->pKey, ((uint8_t*)pUserKeyData->pKey) + CC_AES_256_BIT_KEY_SIZE, CC_AES_256_BIT_KEY_SIZE) == 0)) {
                                return CC_AES_ILLEGAL_PARAMS_ERROR;
                        }

		} else if ( (pUserKeyData->keySize != CC_AES_128_BIT_KEY_SIZE) &&
			    (pUserKeyData->keySize != CC_AES_192_BIT_KEY_SIZE) &&
			    (pUserKeyData->keySize != CC_AES_256_BIT_KEY_SIZE) ) {
			/* in all other modes, key size should be only 128/192/256 bit */
			return CC_AES_ILLEGAL_KEY_SIZE_ERROR;
		}

		/* check key pointer validity */
		if (pUserKeyData->pKey == NULL) {
			return CC_AES_INVALID_KEY_POINTER_ERROR;
		}

		/* Copy the key to the context */
		if (pAesCtx->mode == DRV_CIPHER_XTS ) {
			/* Divide by two (we have two keys of the same size) */
			pAesCtx->key_size = pUserKeyData->keySize >> 1;
			CC_PalMemCopy(pAesCtx->key, pUserKeyData->pKey, pAesCtx->key_size);
			/* copy second half of the double-key as XEX-key */
			CC_PalMemCopy(pAesCtx->xex_key, pUserKeyData->pKey + pAesCtx->key_size, pAesCtx->key_size);
		}
		else{
			pAesCtx->key_size = pUserKeyData->keySize;
			/* just eliminate KW issue (pAesCtx->key_size is max 32 bytes anyway) */
			pAesCtx->key_size = min(pAesCtx->key_size, CC_AES_256_BIT_KEY_SIZE);
			/* Copy the key to the context */
			CC_PalMemCopy(pAesCtx->key, pUserKeyData->pKey, pAesCtx->key_size);
		}
	} else {

		/* set hw key size to 128b */
		pAesCtx->key_size = CC_AES_128_BIT_KEY_SIZE;

		/* Verify that devise support hw keys */
		CC_LIB_IS_KCST_DISABLE(regVal);
		if (regVal) {
			return CC_RET_UNSUPP_HWKEY;
		}

		switch (keyType) {
		case CC_AES_PLATFORM_KEY:
			CC_LIB_IS_KPLT_VALID(regVal);
			if (regVal == 0) {
				return CC_RET_INV_HWKEY;
			}
			break;
		case CC_AES_CUSTOMER_KEY:
			CC_LIB_IS_KCST_VALID(regVal);
			if (regVal == 0) {
				return CC_RET_INV_HWKEY;
			}
			break;
		default:
			break;
		}

	}

    symRc = SymDriverAdaptorInit((uint32_t *)pAesCtx, pAesCtx->alg, pAesCtx->mode);

	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_AES_SET_KEY);

	return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesErr);
}


CIMPORT_C CCError_t CC_AesSetIv(
	CCAesUserContext_t * pContext,
	CCAesIv_t            pIV )
{
	struct drv_ctx_cipher *pAesCtx;

	CCPalPerfData_t perfIdx = 0;
	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_CC_AES_SET_IV);

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	if (pContext == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAesCtx = (struct drv_ctx_cipher *)RcGetUserCtxLocation(pContext->buff);

	/* TODO: check that AesInit was already called */

	if ( (pAesCtx == NULL) ||
	     (pAesCtx->mode != DRV_CIPHER_CBC) &&
	     (pAesCtx->mode != DRV_CIPHER_CTR) &&
	     (pAesCtx->mode != DRV_CIPHER_XTS) &&
	     (pAesCtx->mode != DRV_CIPHER_CBC_MAC) &&
	     (pAesCtx->mode != DRV_CIPHER_CBC_CTS) &&
	     (pAesCtx->mode != DRV_CIPHER_OFB) ) {
		return CC_AES_ILLEGAL_OPERATION_MODE_ERROR;
	}

	if (pIV == NULL) {
		return CC_AES_INVALID_IV_OR_TWEAK_PTR_ERROR;
	}

	CC_PalMemCopy(pAesCtx->block_state, pIV, sizeof(CCAesIv_t));

	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_CC_AES_SET_IV);

	return CC_OK;
}


CIMPORT_C CCError_t CC_AesGetIv(
	CCAesUserContext_t * pContext,
	CCAesIv_t            pIV )
{
	struct drv_ctx_cipher *pAesCtx;

	CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

	if (pContext == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAesCtx = (struct drv_ctx_cipher *)RcGetUserCtxLocation(pContext->buff);
	// TODO: check that AesInit was already called ??

	if ( (pAesCtx == NULL) ||
	     (pAesCtx->mode != DRV_CIPHER_CBC) &&
	     (pAesCtx->mode != DRV_CIPHER_CTR) &&
	     (pAesCtx->mode != DRV_CIPHER_XTS) &&
	     (pAesCtx->mode != DRV_CIPHER_CBC_MAC) &&
	     (pAesCtx->mode != DRV_CIPHER_CBC_CTS) &&
	     (pAesCtx->mode != DRV_CIPHER_OFB) ) {
		return CC_AES_ILLEGAL_OPERATION_MODE_ERROR;
	}

	if (pIV == NULL) {
		return CC_AES_INVALID_IV_OR_TWEAK_PTR_ERROR;
	}

	CC_PalMemCopy(pIV, pAesCtx->block_state, sizeof(CCAesIv_t));

	return CC_OK;
}


CIMPORT_C CCError_t  CC_AesBlock(
	CCAesUserContext_t * pContext,
	uint8_t *              pDataIn,
	size_t                 dataInSize,
	uint8_t *              pDataOut )
{
	int symRc;
	struct drv_ctx_cipher *pAesCtx;
	void *pOutData = NULL;

	CCPalPerfData_t perfIdx = 0;
	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_AES_BLOCK);

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        if (pContext == NULL) {
		 return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAesCtx = (struct drv_ctx_cipher *)RcGetUserCtxLocation(pContext->buff);
	if (pAesCtx == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* TODO: check that key and IV were already set */

	if (pDataIn == NULL) {
		return CC_AES_DATA_IN_POINTER_INVALID_ERROR;
	}

	if (dataInSize == 0) {
		/* Size zero is not a valid block operation */
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

	/* check the minimum data size according to mode */
	if ( (pAesCtx->mode == DRV_CIPHER_XTS) && (dataInSize < CC_AES_BLOCK_SIZE_IN_BYTES) ) {
		CC_PAL_LOG_ERR("Invalid XTS data size: %u\n", (unsigned int)dataInSize);
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

	if ( (pAesCtx->mode != DRV_CIPHER_XTS) && ((dataInSize % CC_AES_BLOCK_SIZE_IN_BYTES) != 0) ) {
		/* Only for XTS an intermediate data unit may be non aes block multiple */
		CC_PAL_LOG_ERR("Invalid data size: %u\n", (unsigned int)dataInSize);
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

	/* set the data unit size if first block */
	if (pAesCtx->data_unit_size == 0) {
		pAesCtx->data_unit_size = dataInSize;
	}

	/* In XTS mode, all the data units must be of the same size */
	if ( (pAesCtx->mode == DRV_CIPHER_XTS) && (pAesCtx->data_unit_size != dataInSize)) {
		CC_PAL_LOG_ERR("Invalid XTS data size: dataInSize=%u data_unit_size=%u\n",
				 (unsigned int)dataInSize, (unsigned int)pAesCtx->data_unit_size);
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

        /* max size validation in XTS mode */
        if ((pAesCtx->mode == DRV_CIPHER_XTS) && (dataInSize > AES_XTS_MAX_BLOCK_SIZE)) {
                return CC_AES_DATA_IN_SIZE_ILLEGAL;
        }

	if( (pAesCtx->mode == DRV_CIPHER_CMAC) ||
	    (pAesCtx->mode == DRV_CIPHER_XCBC_MAC) ||
	    (pAesCtx->mode == DRV_CIPHER_CBC_MAC) ) {
		pOutData = NULL;
	}
	else {
		if (pDataOut == NULL){
			return CC_AES_DATA_OUT_POINTER_INVALID_ERROR;
		}

		pOutData = pDataOut;
	}

	symRc = SymDriverAdaptorProcess((uint32_t *)pAesCtx, pDataIn, pOutData, dataInSize, pAesCtx->alg);

	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_AES_BLOCK);

	return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesErr);
}


CIMPORT_C CCError_t  CC_AesFinish(
	CCAesUserContext_t * pContext,
	size_t                 dataSize,
	uint8_t *              pDataIn,
	size_t                 dataInBuffSize,
	uint8_t *              pDataOut,
	size_t *               dataOutBuffSize )
{
	int symRc;
	struct drv_ctx_cipher *pAesCtx;
	size_t paddingSize = 0;

	CCPalPerfData_t perfIdx = 0;
	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_AES_FIN);

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        if (pContext == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	if ( (pDataIn == NULL) && (dataSize != 0) ) {
		return CC_AES_DATA_IN_POINTER_INVALID_ERROR;
	}

	if (dataInBuffSize < dataSize) {
		return CC_AES_DATA_IN_BUFFER_SIZE_ERROR;
	}

	if (dataOutBuffSize == NULL) {
		return CC_AES_DATA_OUT_SIZE_POINTER_INVALID_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAesCtx = (struct drv_ctx_cipher *)RcGetUserCtxLocation(pContext->buff);

	if ( (pAesCtx == NULL) ||
	     (pAesCtx->mode == DRV_CIPHER_CBC_MAC) ||
	     (pAesCtx->mode == DRV_CIPHER_XCBC_MAC) ||
	     (pAesCtx->mode == DRV_CIPHER_CMAC) ) {
		if (pDataOut == NULL) {
			return CC_AES_DATA_OUT_POINTER_INVALID_ERROR;
		}
		if (*dataOutBuffSize < CC_AES_BLOCK_SIZE_IN_BYTES) {
			return CC_AES_DATA_OUT_BUFFER_SIZE_ERROR;
		}
	}
	else {
		if ( (pDataOut == NULL) && (dataSize != 0) ) {
			return CC_AES_DATA_OUT_POINTER_INVALID_ERROR;
		}
		if (*dataOutBuffSize < dataSize) {
			return CC_AES_DATA_OUT_BUFFER_SIZE_ERROR;
		}
	}

	if ( ((dataSize % CC_AES_BLOCK_SIZE_IN_BYTES) != 0) &&
	     ((pAesCtx->mode == DRV_CIPHER_ECB) ||
	      (pAesCtx->mode == DRV_CIPHER_CBC) ||
	      (pAesCtx->mode == DRV_CIPHER_CBC_MAC)) &&
	     (pAesCtx->padding_type == DRV_PADDING_NONE) ) {
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

	/*Check, that in case of CTS mode data size is not less than CC_AES_BLOCK_SIZE_IN_BYTES */
	if ( (dataSize < CC_AES_BLOCK_SIZE_IN_BYTES) &&
	     (pAesCtx->mode == DRV_CIPHER_CBC_CTS) ) {
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

	/* set the data unit size if first block */
	if (pAesCtx->data_unit_size == 0) {
		pAesCtx->data_unit_size = dataSize;
	}

	if ( (pAesCtx->mode == DRV_CIPHER_XTS) && (dataSize != 0) ) {
		/* For XTS all the data units must be of the same size */
		if ( (dataSize < CC_AES_BLOCK_SIZE_IN_BYTES) ||
		     (pAesCtx->data_unit_size != dataSize) ) {
			CC_PAL_LOG_ERR("Invalid XTS data size: dataSize=%u data_unit_size=%u\n",
					 (unsigned int)dataSize, (unsigned int)pAesCtx->data_unit_size);
			return CC_AES_DATA_IN_SIZE_ILLEGAL;
		}
	}

	if (pAesCtx->padding_type == DRV_PADDING_PKCS7)
	{
		if (pDataOut == NULL) {
			return CC_AES_DATA_OUT_POINTER_INVALID_ERROR;
		}

		/* PKCS7 padding in case of encryption mode */
		if (pAesCtx->direction == DRV_CRYPTO_DIRECTION_ENCRYPT)
		{
			paddingSize = CC_AES_BLOCK_SIZE_IN_BYTES - (dataSize % CC_AES_BLOCK_SIZE_IN_BYTES);

			if (*dataOutBuffSize < (dataSize + paddingSize)) {
				return CC_AES_DATA_OUT_BUFFER_SIZE_ERROR;
			}

			if (dataInBuffSize < (dataSize + paddingSize)) {
				return CC_AES_DATA_IN_BUFFER_SIZE_ERROR;
			}

			CC_PalMemSet(pDataIn+dataSize, paddingSize, paddingSize);
			dataSize += paddingSize;
		}
	}

	/* For CBC_CTS mode : In case of data size aligned to 16 perform CBC operation */
	if ( (pAesCtx->mode == DRV_CIPHER_CBC_CTS) && ((dataSize % CC_AES_BLOCK_SIZE_IN_BYTES) == 0) ) {
		pAesCtx->mode = DRV_CIPHER_CBC;
		symRc = SymDriverAdaptorFinalize((uint32_t *)pAesCtx, pDataIn, pDataOut, dataSize, pAesCtx->alg);
		pAesCtx->mode = DRV_CIPHER_CBC_CTS;
	} else {
		symRc = SymDriverAdaptorFinalize((uint32_t *)pAesCtx, pDataIn, pDataOut, dataSize, pAesCtx->alg);
	}

	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_AES_FIN);

	if (symRc != CC_RET_OK) {
		return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesErr);
	}

	if ( (pAesCtx->padding_type == DRV_PADDING_PKCS7) &&
		 (pAesCtx->direction == DRV_CRYPTO_DIRECTION_DECRYPT) )
	{
		size_t i = 0;

		if (pDataOut == NULL) { // added for KW, already check previously
			return CC_AES_DATA_OUT_POINTER_INVALID_ERROR;
		}
		paddingSize = pDataOut[dataSize-1];

		if (paddingSize > CC_AES_BLOCK_SIZE_IN_BYTES ) {
			return CC_AES_INCORRECT_PADDING_ERROR;
		}

		/* check the padding correctness */
		for (i=0; i < paddingSize; ++i) {
			if (pDataOut[dataSize-paddingSize+i] != paddingSize) {
				return CC_AES_CORRUPTED_OUTPUT_ERROR;
			}
		}

		/* remove the padding */
		dataSize -= paddingSize;
		CC_PalMemSetZero(pDataOut+dataSize, paddingSize);
	}

	if ( (pAesCtx->mode == DRV_CIPHER_CBC_MAC) ||
	     (pAesCtx->mode == DRV_CIPHER_XCBC_MAC) ||
	     (pAesCtx->mode == DRV_CIPHER_CMAC) ) {
		*dataOutBuffSize = CC_AES_IV_SIZE_IN_BYTES;
	} else {
		*dataOutBuffSize = dataSize;
	}

 	return CC_OK;
}

CIMPORT_C CCError_t cc_aes_mac_mode(CCAesUserContext_t *context, CCBool_t *mac_mode)
{
    if (context == NULL || mac_mode == NULL)
        return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;

    struct drv_ctx_cipher *aes_ctx = (struct drv_ctx_cipher *)RcGetUserCtxLocation(context->buff);
    if (aes_ctx == NULL)
        return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;

    if ((aes_ctx->mode == DRV_CIPHER_CBC_MAC) ||
        (aes_ctx->mode == DRV_CIPHER_XCBC_MAC) ||
        (aes_ctx->mode == DRV_CIPHER_CMAC))
        *mac_mode = CC_TRUE;
    else
        *mac_mode = CC_FALSE;
    return CC_OK;
}


CIMPORT_C CCError_t  CC_AesFree( CCAesUserContext_t * pContext )
{
	struct drv_ctx_cipher *pAesCtx;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        if (pContext == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAesCtx = (struct drv_ctx_cipher *)RcGetUserCtxLocation(pContext->buff);
	if (pAesCtx == NULL) {
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* Zero the context */
	CC_PalMemSetZero(pAesCtx, sizeof(struct drv_ctx_cipher));

	return CC_OK;
}


