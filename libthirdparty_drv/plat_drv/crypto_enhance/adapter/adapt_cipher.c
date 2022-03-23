/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description  : adapt dx cipher interface
 * Author       : l00370476, liuchong13@huawei.com
 * Create       : 2018/12/24
 */
#include <adapt_cipher.h>
#include <api_cipher.h>
#include <api_mac.h>
#include <pal_log.h>
#include <pal_libc.h>
#include <securec.h>

/* set the module to which the file belongs, each .C file needs to be configured */
#define BSP_THIS_MODULE                BSP_MODULE_SYMM

#define ADDR_IS_ALIGNED(addr)          ((addr) % (sizeof(u32)))

CIMPORT_C CCError_t  EPS_AesInitCheckParam(
	CCAesUserContext_t  *pContext,
	CCAesEncryptMode_t   encryptDecryptFlag,
	CCAesOperationMode_t operationMode,
	CCAesPaddingType_t   paddingType)
{
	/*
	 * checking validity of the input parameters.
	 * if the users context ID pointer is NULL return an Error
	 */
	if (!pContext)
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;

	/* check if the operation mode is legal */
	if (operationMode >= CC_AES_NUM_OF_OPERATION_MODES)
		return CC_AES_ILLEGAL_OPERATION_MODE_ERROR;

	/* check the Encrypt / Decrypt flag validity */
	if (encryptDecryptFlag >= CC_AES_NUM_OF_ENCRYPT_MODES)
		return CC_AES_INVALID_ENCRYPT_MODE_ERROR;

	/* check if the padding type is legal */
	if (paddingType >= CC_AES_NUM_OF_PADDING_TYPES)
		return CC_AES_ILLEGAL_PADDING_TYPE_ERROR;

	/* we support pkcs7 padding only for ECB, CBC, MAC operation modes. */
	if ((paddingType ==  CC_AES_PADDING_PKCS7) &&
	    ((operationMode != CC_AES_MODE_ECB) &&
	     (operationMode != CC_AES_MODE_CBC) &&
	     (operationMode != CC_AES_MODE_CBC_MAC)))
		return CC_AES_ILLEGAL_PADDING_TYPE_ERROR;

	/* in MAC,XCBC,CMAC modes enable only encrypt mode  */
	if (((operationMode == CC_AES_MODE_XCBC_MAC) ||
	     (operationMode == CC_AES_MODE_CMAC) ||
	     (operationMode == CC_AES_MODE_CBC_MAC)) &&
	    (encryptDecryptFlag != CC_AES_ENCRYPT))
		return CC_AES_DECRYPTION_NOT_ALLOWED_ON_THIS_MODE;

	return CC_OK;
}

static u32 GetAesMode(CCAesOperationMode_t operationMode)
{
	switch (operationMode) {
	case CC_AES_MODE_ECB:
		return SYMM_MODE_ECB;
	case CC_AES_MODE_CBC:
		return SYMM_MODE_CBC;
	case CC_AES_MODE_CTR:
		return SYMM_MODE_CTR;
	case CC_AES_MODE_CMAC:
		return SYMM_MODE_CMAC;
	case CC_AES_MODE_CBC_MAC:
		return SYMM_MODE_CBCMAC;
	default:
		return SYMM_MODE_UNKNOWN;
	}
}

static u32 GetAesDirection(CCAesEncryptMode_t encryptDecryptFlag)
{
	switch (encryptDecryptFlag) {
	case CC_AES_ENCRYPT:
		return SYMM_DIRECTION_ENCRYPT;
	case CC_AES_DECRYPT:
		return SYMM_DIRECTION_DECRYPT;
	default:
		return SYMM_DIRECTION_UNKNOWN;
	}
}

static u32 GetAesKeyType(CCAesKeyType_t keyType)
{
	switch (keyType) {
	case CC_AES_USER_KEY:
		return API_CIPHER_KEYTYPE_USER_KEY;
	case CC_AES_CEK_AUDIO:
		return API_CIPHER_KEYTYPE_CEK_AUDIO;
	case CC_AES_CEK_VIDEO:
		return API_CIPHER_KEYTYPE_CEK_VIDEO;
	default:
		return API_CIPHER_KEYTYPE_NUMS;
	}
}

static u32 GetAesWidth(size_t keySize)
{
	switch (keySize) {
	case CC_AES_128_BIT_KEY_SIZE:
		return SYMM_WIDTH_128;
	case CC_AES_192_BIT_KEY_SIZE:
		return SYMM_WIDTH_192;
	case CC_AES_256_BIT_KEY_SIZE:
		return SYMM_WIDTH_256;
	default:
		return SYMM_WIDTH_UNKNOWN;
	}
}

CCError_t  EPS_AesSetKey(CCAesUserContext_t *pContext, CCAesKeyType_t keyType,
			 void *pKeyData, size_t keyDataSize)
{
	api_cipher_ctx_s *pctx_s   = (api_cipher_ctx_s *)pContext;
	api_mac_ctx_s    *pmac_ctx = (api_mac_ctx_s *)((api_cipher_ctx_s *)pContext + 1);
	u8 *pkey = NULL;
	u32 width   = SYMM_WIDTH_UNKNOWN;
	u32 keytype = GetAesKeyType(keyType);
	errno_t libc_ret;

	if (!pContext)
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;

	/* set keytype */
	pctx_s->keytype = keytype;
	switch (keytype) {
	/* set user key to context */
	case API_CIPHER_KEYTYPE_USER_KEY:
		if (!pKeyData)
			return CC_AES_INVALID_KEY_POINTER_ERROR;

		if (!((CCAesUserKeyData_t *)pKeyData)->pKey)
			return CC_AES_INVALID_KEY_POINTER_ERROR;

		if (keyDataSize != sizeof(CCAesUserKeyData_t))
			return CC_AES_INVALID_KEY_POINTER_ERROR;

		width = GetAesWidth(((CCAesUserKeyData_t *)pKeyData)->keySize);
		if (width > SYMM_WIDTH_256)
			return CC_AES_ILLEGAL_KEY_SIZE_ERROR;

		pkey = ((CCAesUserKeyData_t *)pKeyData)->pKey;
		pctx_s->width = width;
		pmac_ctx->width = width;
		libc_ret = memcpy_s(pctx_s->key,
				    sizeof(pctx_s->key),
				    pkey,
				    BIT2BYTE(width));
		if (libc_ret != EOK)
			return CC_AES_ILLEGAL_KEY_SIZE_ERROR;
		libc_ret = memcpy_s(pmac_ctx->key,
				    sizeof(pmac_ctx->key),
				    pkey,
				    BIT2BYTE(width));
		if (libc_ret != EOK)
			return CC_AES_ILLEGAL_KEY_SIZE_ERROR;
		break;
	case API_CIPHER_KEYTYPE_CEK_VIDEO:
	case API_CIPHER_KEYTYPE_CEK_AUDIO:
		pctx_s->width = 0;
		(void)memset_s(pctx_s->key, sizeof(pctx_s->key), 0, sizeof(pctx_s->key));
		break;
	default:
		return CC_AES_ILLEGAL_PARAMS_ERROR;
	}

	return CC_OK;
}

CIMPORT_C CCError_t EPS_AesSetIv(CCAesUserContext_t *pContext, CCAesIv_t pIV)
{
	api_cipher_ctx_s *pctx_s   = (api_cipher_ctx_s *)pContext;
	api_mac_ctx_s    *pmac_ctx = (api_mac_ctx_s *)((api_cipher_ctx_s *)pContext + 1);
	errno_t libc_ret;

	if (!pContext)
		return CC_AES_INVALID_USER_CONTEXT_POINTER_ERROR;

	if (!pIV)
		return CC_AES_INVALID_IV_OR_TWEAK_PTR_ERROR;

	/* copy iv to context */
	libc_ret = memcpy_s(pctx_s->iv, sizeof(pctx_s->iv), pIV, CC_AES_IV_SIZE_IN_BYTES);
	if (libc_ret != EOK)
		return CC_AES_DATA_IN_BUFFER_SIZE_ERROR;

	libc_ret = memcpy_s(pmac_ctx->iv,
			    sizeof(pmac_ctx->iv),
			    pIV,
			    CC_AES_IV_SIZE_IN_BYTES);
	if (libc_ret != EOK)
		return CC_AES_DATA_IN_BUFFER_SIZE_ERROR;

	return CC_OK;
}

CIMPORT_C CCError_t  EPS_AesInit(
	CCAesUserContext_t  *pContext,
	CCAesEncryptMode_t   encryptDecryptFlag,
	CCAesOperationMode_t operationMode,
	CCAesPaddingType_t   paddingType)
{
	errno_t ret;
	/* copy params into pContext, which is used as api_cipher_ctx_s */
	api_cipher_ctx_s *pctx_s = (api_cipher_ctx_s *)pContext;
	api_mac_ctx_s    *pmac_ctx = (api_mac_ctx_s *)((api_cipher_ctx_s *)pContext + 1);
	u32 direction;
	u32 mode;
	errno_t libc_ret;

	UNUSED(paddingType); /* this param is not used */

	ret = EPS_AesInitCheckParam(pContext, encryptDecryptFlag, operationMode, paddingType);
	if (ret != CC_OK)
		return ret;

	direction = GetAesDirection(encryptDecryptFlag);
	mode      = GetAesMode(operationMode);

	/* params is copy to context */
	pctx_s->algorithm   = SYMM_ALGORITHM_AES;
	pctx_s->direction   = direction;
	pctx_s->mode        = mode;
	pctx_s->blen        = 0;
	(void)memset_s(pctx_s->buf, sizeof(pctx_s->buf), 0, sizeof(pctx_s->buf));

	/* set mac ctx from cipher ctx */
	pmac_ctx->algorithm = pctx_s->algorithm;
	pmac_ctx->mode      = pctx_s->mode;
	pmac_ctx->blen      = pctx_s->blen;
	libc_ret = memcpy_s(pmac_ctx->buf, sizeof(pmac_ctx->buf), pctx_s->buf, sizeof(pctx_s->buf));
	if (libc_ret != EOK)
		return CC_AES_DATA_IN_BUFFER_SIZE_ERROR;

	return ret;
}

static CCError_t  EPS_AesBlockCheckParam(
	CCAesUserContext_t *pContext,
	u8                 *pDataIn,
	size_t              dataInSize,
	u8                 *pDataOut)
{
	api_cipher_ctx_s *pctx_s = (api_cipher_ctx_s *)pContext;

	UNUSED(pDataOut);
	/* check pointer */
	if (!pContext || !pDataIn)
		return CC_AES_DATA_IN_POINTER_INVALID_ERROR;

	if (dataInSize == 0) {
		/* Size zero is not a valid block operation */
		PAL_ERROR("dataInSize == 0\n");
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

	/* update only support ECB/CBC/CTR/CBCMAC */
	if ((pctx_s->mode != SYMM_MODE_ECB) &&
	    (pctx_s->mode != SYMM_MODE_CBC) &&
	    (pctx_s->mode != SYMM_MODE_CTR) &&
	    (pctx_s->mode != SYMM_MODE_CBCMAC))
		return CC_AES_ILLEGAL_OPERATION_MODE_ERROR;

	if ((dataInSize % SYMM_BLKLEN_AES) != 0) {
		PAL_ERROR("dataInSize = %d\n", dataInSize);
		return CC_AES_DATA_IN_SIZE_ILLEGAL;
	}

	return CC_OK;
}

/*
 * @brief      : EPS_AesMacBlock, static function, update for mac compute,
 *               only support CBCMAC multiple of blklen
 */
static CCError_t  EPS_AesMacBlock(
	CCAesUserContext_t *pContext,
	u8                 *pDataIn,
	size_t              dataInSize,
	u8                 *pDataOut)
{
	err_bsp_t ret;
	api_mac_ctx_s  *pmac_ctx = (api_mac_ctx_s *)((u8 *)pContext + sizeof(api_cipher_ctx_s));

	UNUSED(pDataOut);
	if (pmac_ctx->mode != SYMM_MODE_CBCMAC)
		return CC_AES_ILLEGAL_OPERATION_MODE_ERROR;

	ret = api_mac_update(pmac_ctx, pDataIn, dataInSize);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

static CCError_t  EPS_AesCipherBlock(
	CCAesUserContext_t *pContext,
	u8                 *pDataIn,
	size_t              dataInSize,
	u8                 *pDataOut)
{
	err_bsp_t ret;
	u32 doutlen = dataInSize;
	api_cipher_ctx_s *pctx_s = (api_cipher_ctx_s *)pContext;

	/* process blocks */
	ret = api_cipher_update(pctx_s, pDataIn, dataInSize,
				pDataOut, &doutlen);
	PAL_ERR_RETURN(ret);

	return CC_OK;
}

CIMPORT_C CCError_t  EPS_AesBlock(
	CCAesUserContext_t *pContext,
	u8                 *pDataIn,
	size_t              dataInSize,
	u8                 *pDataOut)
{
	CCError_t ret;
	api_cipher_ctx_s *pctx_s = (api_cipher_ctx_s *)pContext;

	/* check param, only multi-block is supported */
	ret = EPS_AesBlockCheckParam(pContext, pDataIn, dataInSize, pDataOut);
	if (ret != CC_OK)
		return ret;

	if ((pctx_s->mode == SYMM_MODE_ECB) ||
	    (pctx_s->mode == SYMM_MODE_CBC) ||
	    (pctx_s->mode == SYMM_MODE_CTR)) {
		if (!pDataOut)
			return CC_AES_DATA_IN_POINTER_INVALID_ERROR;
		ret = EPS_AesCipherBlock(pContext, pDataIn, dataInSize, pDataOut);
	} else {
		ret = EPS_AesMacBlock(pContext, pDataIn, dataInSize, pDataOut);
	}
	return ret;
}

CIMPORT_C CCError_t  EPS_AesFinish(
	CCAesUserContext_t *pContext,
	size_t              dataSize,
	u8                 *pDataIn,
	size_t              dataInBuffSize,
	u8                 *pDataOut,
	size_t             *dataOutBuffSize)
{
	err_bsp_t ret = ERR_DRV(ERRCODE_UNKNOWN);
	api_cipher_ctx_s *pcipher_ctx = (api_cipher_ctx_s *)pContext;
	api_mac_ctx_s  *pmac_ctx  = (api_mac_ctx_s *)((u8 *)pContext + sizeof(*pcipher_ctx));

	if (!pContext || !pDataIn || !pDataOut  || !dataOutBuffSize)
		return CC_AES_DATA_IN_POINTER_INVALID_ERROR;

	if (dataInBuffSize < dataSize)
		return CC_AES_DATA_IN_BUFFER_SIZE_ERROR;

	if (pcipher_ctx->mode == SYMM_MODE_ECB ||
	    pcipher_ctx->mode == SYMM_MODE_CBC ||
	    pcipher_ctx->mode == SYMM_MODE_CTR) {
		if (*dataOutBuffSize < dataSize) {
			PAL_ERROR("outlen = %d, dataInSize = %d\n",
				  *dataOutBuffSize, dataSize);
			return CC_AES_DATA_OUT_BUFFER_SIZE_ERROR;
		}
		if ((pcipher_ctx->mode != SYMM_MODE_CTR) &&
		    ((dataSize % SYMM_BLKLEN_AES) != 0)) {
			PAL_ERROR("dataInSize = %d\n", dataSize);
			return CC_AES_DATA_IN_SIZE_ILLEGAL;
		}
		ret = api_cipher_dofinal((api_cipher_ctx_s *)pContext,
					 pDataIn, dataSize, pDataOut,
					 dataOutBuffSize);
		PAL_ERR_RETURN(ret);
		return CC_OK;
	}

	if (*dataOutBuffSize < CC_AES_BLOCK_SIZE_IN_BYTES) {
		PAL_ERROR("outlen = %d\n", *dataOutBuffSize);
		return CC_AES_DATA_OUT_BUFFER_SIZE_ERROR;
	}
	ret = api_mac_dofinal(pmac_ctx, (pal_master_addr_t)pDataIn,
			      dataSize, pDataOut, dataOutBuffSize);
	PAL_ERR_RETURN(ret);
	return CC_OK;
}

CIMPORT_C CCError_t  EPS_AesFree(CCAesUserContext_t *pContext)
{
	(void)memset_s(pContext, CC_AES_USER_CTX_SIZE_IN_WORDS * sizeof(u32), 0,
		       CC_AES_USER_CTX_SIZE_IN_WORDS * sizeof(u32));
	return CC_OK;
}

u32 GetDesMode(CCDesOperationMode_t OperationMode)
{
	switch (OperationMode) {
	case CC_DES_ECB_mode:
		return SYMM_MODE_ECB;
	case CC_DES_CBC_mode:
		return SYMM_MODE_CBC;
	default:
		return SYMM_MODE_UNKNOWN;
	}
}

u32 GetDesDirection(CCDesEncryptMode_t EncryptDecryptFlag)
{
	switch (EncryptDecryptFlag) {
	case CC_DES_Encrypt:
		return SYMM_DIRECTION_ENCRYPT;
	case CC_DES_Decrypt:
		return SYMM_DIRECTION_DECRYPT;
	default:
		return SYMM_DIRECTION_UNKNOWN;
	}
}

u32 GetDesWidth(CCDesNumOfKeys_t NumOfKeys)
{
	switch (NumOfKeys) {
	case CC_DES_1_KeyInUse:
		return SYMM_WIDTH_64;
	case CC_DES_2_KeysInUse:
		return SYMM_WIDTH_128;
	case CC_DES_3_KeysInUse:
		return SYMM_WIDTH_192;
	default:
		return SYMM_WIDTH_UNKNOWN;
	}
}

/*
 * @brief: This function is used to initialize the DES machine.
 *	   To operate the DES machine, this should be the first function called.
 * @param[in]: ContextID_ptr, Pointer to the DES context buffer allocated by the user,
 *			      which is used for DES machine operation.
 * @param[in]: IV_ptr         The IV buffer. In ECB mode this parameter is not used.
 *			      In CBC this parameter should contain IV values.
 * @param[in]: Key_ptr        Pointer to the user's key buffer.
 * @param[in]: NumOfKeys      The number of keys used: 1, 2 or 3 (defined by the enum).
 *			      One key implies DES encryption/decryption, two or three keys imply triple-DES.
 * @param[in]: EncryptDecryptFlag, A flag that determines whether the DES should perform an Encrypt operation (0)
 *				   or a Decrypt operation (1).
 * @param[in]: OperationMode       The operation mode: ECB or CBC.
 * @return:    CC_OK on success. A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t  EPS_DesInit(
	CCDesUserContext_t  *ContextID_ptr,
	CCDesIv_t            IV_ptr,
	CCDesKey_t          *Key_ptr,
	CCDesNumOfKeys_t     NumOfKeys,
	CCDesEncryptMode_t   EncryptDecryptFlag,
	CCDesOperationMode_t OperationMode)
{
	/* copy params into pContext, which is used as api_cipher_ctx_s */
	api_cipher_ctx_s *pctx_s = (api_cipher_ctx_s *)ContextID_ptr;
	u32 direction;
	u32 mode;
	u32 width;
	errno_t libc_ret;

	/* if the users context ID pointer is NULL return an Error */
	if (!ContextID_ptr)
		return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;

	/* check if the operation mode is legal */
	if (OperationMode >= CC_DES_NumOfModes)
		return CC_DES_ILLEGAL_OPERATION_MODE_ERROR;

	/*
	 * if the operation mode selected is CBC then check the validity of
	 * the IV counter pointer
	 */
	if ((OperationMode == CC_DES_CBC_mode) && (!IV_ptr))
		return CC_DES_INVALID_IV_PTR_ON_NON_ECB_MODE_ERROR;

	/* If the number of keys is invalid return an Error */
	if ((NumOfKeys >= CC_DES_NumOfKeysOptions) || (NumOfKeys == 0))
		return CC_DES_ILLEGAL_NUM_OF_KEYS_ERROR;
	/* check the validity of the key pointer */
	if (!Key_ptr)
		return CC_DES_INVALID_KEY_POINTER_ERROR;

	/* Check the Encrypt / Decrypt flag validity */
	if (EncryptDecryptFlag >= CC_DES_EncryptNumOfOptions)
		return CC_DES_INVALID_ENCRYPT_MODE_ERROR;
	direction = GetDesDirection(EncryptDecryptFlag);
	mode      = GetDesMode(OperationMode);
	width     = GetDesWidth(NumOfKeys);

	/* params is copy to context */
	pctx_s->algorithm   = SYMM_ALGORITHM_DES;
	pctx_s->direction   = direction;
	pctx_s->mode        = mode;
	pctx_s->width       = width;
	pctx_s->blen        = 0;
	(void)memset_s(pctx_s->buf, sizeof(pctx_s->buf), 0, sizeof(pctx_s->buf));
	libc_ret = memcpy_s(pctx_s->key, sizeof(pctx_s->key), Key_ptr, BIT2BYTE(width));
	if (libc_ret != EOK)
		return CC_DES_ILLEGAL_NUM_OF_KEYS_ERROR;
	if (pctx_s->mode == SYMM_MODE_CBC) {
		libc_ret = memcpy_s(pctx_s->iv, sizeof(pctx_s->iv), IV_ptr, sizeof(CCDesIv_t));
		if (libc_ret != EOK)
			return CC_DES_ILLEGAL_PARAMS_ERROR;
	}

	return CC_OK;
}

/*
 * @brief:This function is used to process a block on the DES machine.
 *	  This function should be called after the CC_DesInit function was called.
 * @param[in]: ContextID_pt  Pointer to the DES context buffer allocated by the user,
 *			     which is used for DES machine operation.
 *			     This should be the same context used on the previous call of this session.
 * @param[in]: DataIn_ptr    The pointer to input data.
 *			     The size of the scatter/gather list representing the data buffer is limited to 128 entries,
 *			     and the size of each entry is limited to 64KB.
 *			     (fragments larger than 64KB are broken into fragments <= 64KB).
 * @param[in]: DataInSize    The size of the input data. Must be a multiple of the DES block size, 8 bytes.
 * @param[out]:DataOut_ptr   The pointer to the output data.
 *			     The size of the scatter/gather list representing the data buffer is limited to 128 entries,
 *			     and the size of each entry is limited to 64KB.
 *			     (fragments larger than 64KB are broken into fragments <= 64KB).
 * @return                   CC_OK on success. A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t  EPS_DesBlock(
	CCDesUserContext_t   *ContextID_ptr,
	u8                   *DataIn_ptr,
	size_t                DataInSize,
	u8                   *DataOut_ptr)
{
	err_bsp_t ret;
	u32 doutlen = DataInSize;
	api_cipher_ctx_s *pctx_s = (api_cipher_ctx_s *)ContextID_ptr;

	/* if the users context ID pointer is NULL return an Error */
	if (!ContextID_ptr)
		return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;

	/* if the users Data In pointer is illegal return an Error */
	if (!DataIn_ptr)
		return CC_DES_DATA_IN_POINTER_INVALID_ERROR;

	/* if the users Data Out pointer is illegal return an Error */
	if (!DataOut_ptr)
		return CC_DES_DATA_OUT_POINTER_INVALID_ERROR;

	/* data size must be a positive number and a block size mult */
	if (((DataInSize % CC_DES_BLOCK_SIZE_IN_BYTES) != 0) ||
	    (DataInSize == 0))
		return CC_DES_DATA_SIZE_ILLEGAL;

	ret = api_cipher_update(pctx_s, DataIn_ptr, DataInSize,
				DataOut_ptr, &doutlen);
	return CONVERT_RET_AGENT2ADAPT(ret);
}

/*
 * @brief: This function is used to end the DES processing session.
 *	   It is the last function called for the DES process.
 * @param[in]: ContextID_ptr    Pointer to the DES context buffer allocated by the user
 *				that is used for DES machine operation.
 *				This should be the same context that was used on the previous call of this session.
 * @return                      CC_OK on success. A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t  EPS_DesFree(CCDesUserContext_t *ContextID_ptr)
{
	/* if the users context ID pointer is NULL return an Error */
	if (!ContextID_ptr)
		return CC_DES_INVALID_USER_CONTEXT_POINTER_ERROR;

	(void)memset_s(ContextID_ptr, sizeof(*ContextID_ptr), 0, sizeof(*ContextID_ptr));

	return CC_OK;
}

/*
 * @brief: This function is used to operate the DES machine
 *	   in one integrated operation.
 * @param[in]: IV_ptr    The IV buffer in CBC mode. In ECB mode this parameter is not used.
 * @param[in]: Key_ptr   Pointer to the user's key buffer.
 * @param[in]: NumOfKeys The number of keys used: single (56bit), double (112bit) or triple (168bit).
 * @param[in]: EncryptDecryptFlag,  A flag that determines if the DES should perform an Encrypt operation (0)
 *				    or a Decrypt operation (1).
 * @param[in]: OperationMode,   The operation mode: ECB or CBC.
 * @param[in]: DataIn_ptr       The pointer to the input data.
 *				The size of the scatter/gather list representing the data buffer
 *				is limited to 128 entries, and the size of each entry is limited to 64KB.
 *				(fragments larger than 64KB are broken into fragments <= 64KB).
 * @param[in]: DataInSize       The size of the input data. Must be a multiple of the DES block size, 8 bytes.
 * @param[out]:DataOut_ptr      The pointer to the output data.
 *				The size of the scatter/gather list representing the data buffer
 *				is limited to 128 entries, and the size of each entry is limited to 64KB.
 *				(fragments larger than 64KB are broken into fragments <= 64KB).
 * @return                      CC_OK on success. A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t  EPS_Des(
	CCDesIv_t             IV_ptr,
	CCDesKey_t           *Key_ptr,
	CCDesNumOfKeys_t      NumOfKeys,
	CCDesEncryptMode_t    EncryptDecryptFlag,
	CCDesOperationMode_t  OperationMode,
	u8                   *DataIn_ptr,
	size_t                DataInSize,
	u8                   *DataOut_ptr)
{
	CCDesUserContext_t user_context;
	CCError_t error = CC_OK;
	CCError_t error_result;

	/* if no data to process -we're done */
	if (DataInSize == 0)
		goto end;

	error = EPS_DesInit(&user_context, IV_ptr, Key_ptr, NumOfKeys,
			    EncryptDecryptFlag, OperationMode);
	if (error != CC_OK)
		goto end;

	error = EPS_DesBlock(&user_context, DataIn_ptr, DataInSize, DataOut_ptr);
	if (error != CC_OK)
		goto end;

end:
	error_result = EPS_DesFree(&user_context);
	if (error != CC_OK)
		return error;
	return error_result;
}

