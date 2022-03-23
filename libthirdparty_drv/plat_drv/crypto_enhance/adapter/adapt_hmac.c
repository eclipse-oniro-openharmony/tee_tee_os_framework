/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description  : compute licence hmac
 * Author       : l00370476, liuchong13@huawei.com
 * Create       : 2018/12/26
 */
#include <adapt_hmac.h>
#include <api_hmac.h>
#include <adapt_hash.h>
#include <pal_log.h>
#include "adapt_common.h"

CCError_t EPS_ComputeLicenseHmac(u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret;

	/* call agent */
	ret = api_hmac_licence((pal_master_addr_t)pdin, dinlen, pdout, pdoutlen);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

/*
 * @param[in]: ContextID_ptr    Pointer to the HMAC context buffer allocated by the user, which is used
 *				for the HMAC machine operation.
 * @param[in]: OperationMode    One of the supported HASH modes, as defined in CCHashOperationMode_t.
 * @param[in]: key_ptr          The pointer to the user's key buffer.
 * @param[in]: keySize          The key size in bytes. if the key size is bigger than the HASH block,
 *				the key will be hashed.
 *				The limitations on the key size are the same as the limitations on MAX hash size.
 */
CIMPORT_C CCError_t EPS_HmacInit(CCHmacUserContext_t   *ContextID_ptr,
				 CCHashOperationMode_t  OperationMode,
				 u8                    *key_ptr,
				 size_t                 keySize)
{
	u32 algorithm = GetHashAlgorithm(OperationMode);
	err_bsp_t ret;

	ret = api_hmac_init((api_hmac_ctx_s *)ContextID_ptr, algorithm, key_ptr, keySize);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

/*
 * @param[in]: ContextID_ptr    Pointer to the HMAC context buffer allocated by the user
 *				that is used for the HMAC machine operation.
 * @param[in]: DataIn_ptr       Pointer to the input data to be HASHed.
 *				The size of the scatter/gather list representing the data buffer is limited to
 *				128 entries, and the size of each entry is limited to 64KB
 *				(fragments larger than 64KB are broken into fragments <= 64KB).
 * @param[in]: DataInSize       Byte size of the input data. Must be > 0. If not a multiple of the HASH block size
 *				(64 for SHA-1 and SHA-224/256,128 for SHA-384/512),
 *				no further calls to ::CC_HmacUpdate are allowed in this context,
 *				and only ::CC_HmacFinish can be called to complete the computation.
 */
CIMPORT_C CCError_t EPS_HmacUpdate(CCHmacUserContext_t  *ContextID_ptr,
				   u8                   *DataIn_ptr,
				   size_t                DataInSize)
{
	err_bsp_t ret;
	pal_master_addr_t addr = DataIn_ptr;

	ret = api_hmac_update((api_hmac_ctx_s *)ContextID_ptr, addr, DataInSize);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

/*
 * @param[in]: ContextID_ptr    Pointer to the HMAC context buffer allocated by the user, which is used
 *				for the HMAC machine operation.
 * @param[out]:HmacResultBuff  Pointer to the word-aligned 64 byte buffer. The actual size of the
 *				HASH result depends on CCHashOperationMode_t.
 */
CIMPORT_C CCError_t EPS_HmacFinish(CCHmacUserContext_t  *ContextID_ptr,
				   CCHashResultBuf_t     HmacResultBuff)
{
	err_bsp_t ret;
	pal_master_addr_t pdin = 0;
	u32 doutlen = CC_HASH_RESULT_SIZE_IN_WORDS * sizeof(u32);

	ret = api_hmac_dofinal((api_hmac_ctx_s *)ContextID_ptr, pdin, 0,
			       (u8 *)HmacResultBuff, &doutlen);

	return CONVERT_RET_AGENT2ADAPT(ret);
}

/*
 * @param[in]: OperationMode    One of the supported HASH modes, as defined in CCHashOperationMode_t.
 * @param[in]: key_ptr          The pointer to the user's key buffer.
 * @param[in]: keySize          The key size in bytes. If the key size is bigger than the HASH block,
 *				the key will be hashed.
 *				The limitations on the key size are the same as the limitations on MAX hash size.
 * @param[in]: DataIn_ptr       Pointer to the input data to be HASHed.
 *				The size of the scatter/gather list representing the data buffer is limited to 128
 *				entries, and the size of each entry is limited to 64KB (fragments larger than
 *				64KB are broken into fragments <= 64KB).
 * @param[in]: DataSize         The size of the data to be hashed (in bytes).
 * @param[out]: HmacResultBuff  Pointer to the word-aligned 64 byte buffer. The actual size of the
 *				HMAC result depends on CCHashOperationMode_t.
 */
CIMPORT_C CCError_t EPS_Hmac(CCHashOperationMode_t  OperationMode,
			     u8                    *key_ptr,
			     size_t                 keySize,
			     u8                    *DataIn_ptr,
			     size_t                 DataSize,
			     CCHashResultBuf_t      HmacResultBuff)
{
	CCError_t ret;
	CCHmacUserContext_t ctx = {0};

	ret = EPS_HmacInit(&ctx, OperationMode, key_ptr, keySize);
	if (ret != CC_OK)
		return ret;

	ret = EPS_HmacUpdate(&ctx, DataIn_ptr, DataSize);
	if (ret != CC_OK)
		return ret;

	ret = EPS_HmacFinish(&ctx, HmacResultBuff);
	if (ret != CC_OK)
		return ret;

	return CC_OK;
}
