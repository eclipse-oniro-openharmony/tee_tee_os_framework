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

#include "cc_aesccm.h"
#include "cc_aesccm_error.h"
#include "aead.h"
#include "cc_crypto_ctx.h"
#include "sym_adaptor_driver.h"
#include "cc_pal_mem.h"
#include "dma_buffer.h"
#include "cc_sym_error.h"
#include "cc_context_relocation.h"
#include "cc_fips_defs.h"

/************************ Defines ******************************/
#if ( CC_DRV_CTX_SIZE_WORDS > CC_AESCCM_USER_CTX_SIZE_IN_WORDS )
#error CC_AESCCM_USER_CTX_SIZE_IN_WORDS is not defined correctly.
#endif

/* Since the user context in the TEE is doubled to allow it to be contiguous we must get */
/*  the real size of the context (SEP context) to get the private context pointer  */
#define CC_AESCCM_USER_CTX_ACTUAL_SIZE_IN_WORDS	((CC_AESCCM_USER_CTX_SIZE_IN_WORDS - 3)/2)

/************************ Type definitions **********************/
#define AESCCM_PRIVATE_CONTEXT_SIZE_WORDS 1

typedef struct CC_AesCcmPrivateContext {
	uint32_t isA0BlockProcessed;
} CCAesCcmPrivateContext_t;


/************************ Private Functions **********************/

/*!
 * Converts Symmetric Adaptor return code to CC error code.
 *
 * \param symRetCode Symmetric Adaptor return error.
 * \param errorInfo Ignored.
 *
 * \return CCError_t one of CC_* error codes defined in cc_error.h
 */
static CCError_t SymAdaptor2CCAesCcmErr(int symRetCode, uint32_t errorInfo)
{
	errorInfo = errorInfo;
	switch (symRetCode) {
	case CC_RET_UNSUPP_ALG:
	case CC_RET_UNSUPP_ALG_MODE:
		return CC_AESCCM_IS_NOT_SUPPORTED;
	case CC_RET_INVARG:
		return CC_AESCCM_ILLEGAL_PARAMS_ERROR;
	case CC_RET_INVARG_KEY_SIZE:
		return CC_AESCCM_ILLEGAL_KEY_SIZE_ERROR;
	case CC_RET_INVARG_CTX_IDX:
		return CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
	case CC_RET_INVARG_CTX:
		return CC_AESCCM_USER_CONTEXT_CORRUPTED_ERROR;
	case CC_RET_INVARG_BAD_ADDR:
		return CC_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR;
	case CC_RET_NOMEM:
		return CC_OUT_OF_RESOURCE_ERROR;
	case CC_RET_INVARG_INCONSIST_DMA_TYPE:
		return CC_AESCCM_ILLEGAL_DMA_BUFF_TYPE_ERROR;
	case CC_RET_UNSUPP_OPERATION:
	case CC_RET_PERM:
	case CC_RET_NOEXEC:
	case CC_RET_BUSY:
	case CC_RET_OSFAULT:
	default:
		return CC_FATAL_ERROR;
	}
}

/*!
 * Format AES-CCM Block A0 according to the given header length
 *
 * \param pA0Buff A0 block buffer
 * \param headerSize The actual header size
 *
 * \return uint32_t Number of bytes encoded
 */
static uint32_t FormatCcmA0(uint8_t *pA0Buff, size_t headerSize)
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

CCError_t CC_AesCcmInit(
	CCAesCcmUserContext_t *ContextID_ptr,
	CCAesEncryptMode_t EncrDecrMode,
	CCAesCcmKey_t CCM_Key,
	CCAesCcmKeySize_t KeySizeId,
	size_t AdataSize,
	size_t TextSize,
	uint8_t *N_ptr,
	uint8_t SizeOfN,
	uint8_t SizeOfT)
{
	uint32_t keySizeInBytes;
	struct drv_ctx_aead *pAeadContext;
	CCAesCcmPrivateContext_t *pAesCcmPrivContext;
	uint8_t QFieldSize = 15 - SizeOfN;
	int symRc = CC_RET_OK;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* if the users context ID pointer is NULL return an error */
	if ( ContextID_ptr == NULL ) {
		return CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* check key pointer (unless secret key is used) */
	if ( CCM_Key == NULL ) {
		return CC_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR;
	}

	/* check Nonce pointer */
	if ( N_ptr == NULL ) {
		return CC_AESCCM_ILLEGAL_PARAMETER_PTR_ERROR;
	}

	/* check the Q field size: according to our implementation QFieldSize <= 4*/
	if ( (QFieldSize < 2) || (QFieldSize > 8) ) {
		return CC_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
	}

	/* Check that TextSize fits into Q field (i.e., there are enough bits) */
	if ( (BITMASK(QFieldSize * 8) & TextSize) != TextSize ) {
		return CC_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
	}

	/* check Nonce size. Note: QFieldSize + SizeOfN == 15 */
	if ( (SizeOfN < 7) || (SizeOfN != (15 - QFieldSize)) ) {
		return CC_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
	}

	 /* check CCM MAC size: [4,6,8,10,12,14,16] */
	if ( (SizeOfT < 4) || (SizeOfT > 16) || ((SizeOfT & 1) != 0) ) {
		return CC_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
	}

	/* check Key size ID and get Key size in bytes */
	switch (KeySizeId) {
	case CC_AES_Key128BitSize:
		keySizeInBytes = 16;
		break;
	case CC_AES_Key192BitSize:
		keySizeInBytes = 24;
		break;
	case CC_AES_Key256BitSize:
		keySizeInBytes = 32;
		break;
	default:
		return CC_AESCCM_ILLEGAL_KEY_SIZE_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	 pAeadContext = (struct drv_ctx_aead *)RcInitUserCtxLocation(ContextID_ptr->buff,
						   sizeof(CCAesCcmUserContext_t),
						   sizeof(struct drv_ctx_aead));
	 if (pAeadContext == NULL){
		 return CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
	 }

	 pAesCcmPrivContext = (CCAesCcmPrivateContext_t *)
		&(((uint32_t*)pAeadContext)[CC_AESCCM_USER_CTX_ACTUAL_SIZE_IN_WORDS - AESCCM_PRIVATE_CONTEXT_SIZE_WORDS]);
	 /* clear private context fields */
	 pAesCcmPrivContext->isA0BlockProcessed = 0;

	 /* Verify Adata size is not bigger than 2^32 */
	 if (AdataSize > 0xFFFFFFFF){
		 return CC_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
	 }

	 /* init. CCM context */
	 pAeadContext->alg = DRV_CRYPTO_ALG_AEAD;
	 pAeadContext->mode = DRV_CIPHER_CCM;
	 pAeadContext->direction = (enum drv_crypto_direction)EncrDecrMode;
	 pAeadContext->key_size = keySizeInBytes;
	 CC_PalMemCopy(pAeadContext->key, CCM_Key, keySizeInBytes);
	 pAeadContext->header_size = AdataSize;
	 pAeadContext->nonce_size = SizeOfN;
	 CC_PalMemCopy(pAeadContext->nonce, N_ptr, SizeOfN);
	 pAeadContext->tag_size = SizeOfT;
	 pAeadContext->text_size = TextSize;

	 symRc = SymDriverAdaptorInit((uint32_t *)pAeadContext, pAeadContext->alg, pAeadContext->mode);
	 return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
}

CCError_t CC_AesCcmBlockAdata(
	CCAesCcmUserContext_t *ContextID_ptr,
	uint8_t *DataIn_ptr,
	size_t DataInSize)
{
	struct drv_ctx_aead *pAeadContext;
	uint32_t headerA0BorrowLen, actualHeaderLen, headerA0MetaDataLen;
	CCAesCcmPrivateContext_t *pAesCcmPrivContext;
	int symRc = CC_RET_OK;
	uint8_t pA0Block[CC_AES_BLOCK_SIZE_IN_BYTES] = {0};
	CCAesCcmPrivateContext_t tmpAesCcmPrivCtx;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* if the users context ID pointer is NULL return an error */
	if ( ContextID_ptr == NULL )  {
		return CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* if the users Data In pointer is illegal return an error */
	if ( DataIn_ptr == NULL ) {
		return CC_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
	}

	/* if the data size is illegal return an error */
	if ( DataInSize == 0 ) {
		return CC_AESCCM_DATA_IN_SIZE_ILLEGAL;
	}

	/* save private context, because RcGetUserCtxLocation may change it */
	pAeadContext = (struct drv_ctx_aead *)GetUserCtxLocation(ContextID_ptr->buff);
	pAesCcmPrivContext = (CCAesCcmPrivateContext_t *)
	       &(((uint32_t*)pAeadContext)[CC_AESCCM_USER_CTX_ACTUAL_SIZE_IN_WORDS - AESCCM_PRIVATE_CONTEXT_SIZE_WORDS]);
	tmpAesCcmPrivCtx = *pAesCcmPrivContext;

	/* Get pointer to contiguous context in the HOST buffer */
	pAeadContext = (struct drv_ctx_aead *)RcGetUserCtxLocation(ContextID_ptr->buff);
	if ( pAeadContext == NULL ) {
		return CC_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
	}
	pAesCcmPrivContext = (CCAesCcmPrivateContext_t *)
	       &(((uint32_t*)pAeadContext)[CC_AESCCM_USER_CTX_ACTUAL_SIZE_IN_WORDS - AESCCM_PRIVATE_CONTEXT_SIZE_WORDS]);

	/* restore private context */
	*pAesCcmPrivContext = tmpAesCcmPrivCtx;

	/* additional data may be processed only once */
	if (pAesCcmPrivContext->isA0BlockProcessed == 1) {
		return CC_AESCCM_ADATA_WAS_PROCESSED_ERROR;
	}



	/* formate A0 block only once */
	headerA0MetaDataLen = FormatCcmA0(pA0Block, DataInSize);
	headerA0BorrowLen = min((CC_AES_BLOCK_SIZE_IN_BYTES - headerA0MetaDataLen), DataInSize);
	actualHeaderLen = headerA0MetaDataLen + DataInSize;

	/* this is the first Adata block.
	*  Complete to AES block thus A0 = [META DATA 2B/6B | ADATA 14B/10B] */
	CC_PalMemCopy(pA0Block + headerA0MetaDataLen, DataIn_ptr, headerA0BorrowLen);

	if (actualHeaderLen <= CC_AES_BLOCK_SIZE_IN_BYTES) {
		/* given additional data plus header meta data are smaller than AES block size: A0+Adata < 16 */
		symRc = SymDriverAdaptorProcess((uint32_t *)pAeadContext, pA0Block, NULL, actualHeaderLen, pAeadContext->alg);
		if (symRc != CC_RET_OK) {
			return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
		}
	} else {
		/* given additional data plus header meta data are greater than AES block size: A0+Adata > 16 */
		/* process A0 block */
		symRc = SymDriverAdaptorProcess((uint32_t *)pAeadContext, pA0Block, NULL, CC_AES_BLOCK_SIZE_IN_BYTES, pAeadContext->alg);
		if (symRc != CC_RET_OK) {
			return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
		}

		/* prepare DMA buffer for rest of data */
		DataIn_ptr += headerA0BorrowLen;

		/* process user remaining additional data */
		symRc = SymDriverAdaptorProcess((uint32_t *)pAeadContext,
					DataIn_ptr, NULL, DataInSize - headerA0BorrowLen, pAeadContext->alg);
		if (symRc != CC_RET_OK) {
			return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
		}
	}

	pAesCcmPrivContext->isA0BlockProcessed = 1;

	return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
}


CCError_t CC_AesCcmBlockTextData(
	CCAesCcmUserContext_t *ContextID_ptr,
	uint8_t *DataIn_ptr,
	size_t DataInSize,
	uint8_t *DataOut_ptr)
{
	struct drv_ctx_aead *pAeadContext;
	int symRc = CC_RET_OK;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* if the users context ID pointer is NULL return an error */
	if ( ContextID_ptr == NULL ) {
		return CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* if the users Data In pointer is illegal return an error */
	if ( DataIn_ptr == NULL ) {
		return CC_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
	}

	/* if the Data In size is 0, return an error */
	if ( DataInSize == 0 ) {
		return CC_AESCCM_DATA_IN_SIZE_ILLEGAL;
	}

	/* if the users Data Out pointer is illegal return an error */
	if ( DataOut_ptr == NULL ) {
		return CC_AESCCM_DATA_OUT_POINTER_INVALID_ERROR;
	}

	/* Get pointer to contiguous context in the HOST buffer */
	pAeadContext = (struct drv_ctx_aead *)RcGetUserCtxLocation(ContextID_ptr->buff);
	if ( pAeadContext == NULL ) {
		return CC_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
	}

	symRc = SymDriverAdaptorProcess((uint32_t *)pAeadContext, DataIn_ptr, DataOut_ptr, DataInSize, pAeadContext->alg);
	return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
}


CEXPORT_C CCError_t CC_AesCcmFinish(
	CCAesCcmUserContext_t *ContextID_ptr,
	uint8_t *DataIn_ptr,
	size_t DataInSize,
	uint8_t *DataOut_ptr,
	CCAesCcmMacRes_t MacRes,
	uint8_t *SizeOfT)
{
        struct drv_ctx_aead *pAeadContext;
	int symRc = CC_RET_OK;

        CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

        /* if the users context ID pointer is NULL return an error */
	if ( ContextID_ptr == NULL )  {
		return CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	/* if the users Data In pointer is illegal return an error */
	if ( (DataIn_ptr == NULL) && (DataInSize != 0) ) {
		return CC_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
	}

	/* if the users Data Out pointer is illegal return an error */
	if ( (DataOut_ptr == NULL) && (DataInSize != 0) ) {
		return CC_AESCCM_DATA_OUT_POINTER_INVALID_ERROR;
	}

	/* if the users context ID pointer is NULL return an error */
	if ( ContextID_ptr == NULL ) {
		return CC_AESCCM_INVALID_USER_CONTEXT_POINTER_ERROR;
	}

	if ( SizeOfT == NULL )  {
		return CC_AESCCM_ILLEGAL_PARAMETER_SIZE_ERROR;
	}

	if ( MacRes == NULL )  {
		return CC_AESCCM_ILLEGAL_PARAMETER_ERROR;

	}
	/* Get pointer to contiguous context in the HOST buffer */
	pAeadContext = (struct drv_ctx_aead *)RcGetUserCtxLocation(ContextID_ptr->buff);
	if ( pAeadContext == NULL ) {
		return CC_AESCCM_DATA_IN_POINTER_INVALID_ERROR;
	}

	symRc = SymDriverAdaptorFinalize((uint32_t *)pAeadContext, DataIn_ptr, DataOut_ptr, DataInSize, pAeadContext->alg);
	if (symRc != CC_RET_OK) {
		return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
	}

	/* copy MAC result to context */
	*SizeOfT = pAeadContext->tag_size;

	if (pAeadContext->direction == DRV_CRYPTO_DIRECTION_DECRYPT) {
		if (CC_PalMemCmp(MacRes, pAeadContext->mac_state, *SizeOfT)) {
			return CC_AESCCM_CCM_MAC_INVALID_ERROR;
		}
	} else { /*DRV_CRYPTO_DIRECTION_ENCRYPT*/
		CC_PalMemCopy(MacRes, pAeadContext->mac_state, *SizeOfT);
	}

	return CC_CRYPTO_RETURN_ERROR(symRc, 0, SymAdaptor2CCAesCcmErr);
}

CIMPORT_C CCError_t CC_AesCcm(
	CCAesEncryptMode_t EncrDecrMode,
	CCAesCcmKey_t CCM_Key,
	CCAesCcmKeySize_t KeySizeId,
	uint8_t *N_ptr,
	uint8_t SizeOfN,
	uint8_t *ADataIn_ptr,
	size_t ADataInSize,
	uint8_t *TextDataIn_ptr,
	size_t TextDataInSize,
	uint8_t *TextDataOut_ptr,
	uint8_t SizeOfT,
	CCAesCcmMacRes_t MacRes)
{
	CCError_t rc = CC_OK;
	CCAesCcmUserContext_t ContextID;

	rc = CC_AesCcmInit(&ContextID, EncrDecrMode, CCM_Key,
				KeySizeId, ADataInSize, TextDataInSize,
				N_ptr, SizeOfN, SizeOfT);
	if (rc != CC_OK) {
		return rc;
	}

	if (ADataInSize > 0) {
		rc = CC_AesCcmBlockAdata(&ContextID, ADataIn_ptr, ADataInSize);
		if (rc != CC_OK) {
			return rc;
		}
	}

	rc = CC_AesCcmFinish(&ContextID, TextDataIn_ptr, TextDataInSize, TextDataOut_ptr, MacRes, &SizeOfT);
        if (rc != CC_OK) {
                if ((EncrDecrMode == CC_AES_DECRYPT) && (rc == CC_AESCCM_CCM_MAC_INVALID_ERROR)) {
                        CC_PalMemSetZero(TextDataOut_ptr, TextDataInSize);
                }
                return rc;
        }

        return rc;
}

