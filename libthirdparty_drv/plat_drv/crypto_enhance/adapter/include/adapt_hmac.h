/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: declare of hmac api(same to dx api)
 * Author     : l00370476
 * Create     : 2018/12/28
 */

#ifndef __ADAPT_HMAC_H__
#define __ADAPT_HMAC_H__

#include <cc_hmac.h>

/*
 * @brief      : EPS_ComputeLicenseHmac compute license hmac
 * @param[in]  : pdin
 *               pointer to indata, it's VA of AP
 * @param[in]  : dinlen
 *               length in bytes of pointer
 * @param[in]  : pdout
 *               pointer to outbuffer, it's VA of AP
 * @return     : CC_OK if successful, others if fail
 */
CCError_t EPS_ComputeLicenseHmac(uint8_t *pdin, uint32_t dinlen, uint8_t *pdout, uint32_t *pdoutlen);

/*
 * @param[in]  : ContextID_ptr
 *               Pointer to the HMAC context buffer allocated by the user, which is used for the HMAC machine operation.
 * @param[in]  : OperationMode
 *               One of the supported HASH modes, as defined in CCHashOperationMode_t.
 * @param[in]  : key_ptr
 *               The pointer to the user's key buffer
 * @param[in]  : keySize
 *               The key size in bytes. f the key size is bigger than the HASH block, the key will be hashed.
 *               The limitations on the key size are the same as the limitations on MAX hash size.
 */
CIMPORT_C CCError_t EPS_HmacInit(CCHmacUserContext_t *ContextID_ptr, CCHashOperationMode_t OperationMode,
				 uint8_t *key_ptr, size_t keySize);

/*
 * @param[in]  : ContextID_ptr
 *               Pointer to the HMAC context buffer allocated by the user, which is used for the HMAC machine operation.
 * @param[in]  : DataIn_ptr
 *               Pointer to the input data to be HASHed. The size of the scatter/gather list representing the data
 *               buffer is limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger than
 *               64KB are broken into fragments <= 64KB).
 * @param[in]  : DataInSize
 *               Byte size of the input data. Must be > 0. If not a multiple of the HASH block size (64 for SHA-1 and
 *               SHA-224/256, 128 for SHA-384/512), no further calls to ::CC_HmacUpdate are allowed in this context
 *               and only ::CC_HmacFinish can be called to complete the computation.
 */
CIMPORT_C CCError_t EPS_HmacUpdate(CCHmacUserContext_t *ContextID_ptr, uint8_t *DataIn_ptr, size_t DataInSize);

/*
 * @param[in]  : ContextID_ptr
 *               Pointer to the HMAC context buffer allocated by the user, which is used for the HMAC machine operation.
 * @param[in]  : HmacResultBuff
 *               Pointer to the word-aligned 64 byte buffer. The actual size of the HASH result depends on
 *               CCHashOperationMode_t.
 */
CIMPORT_C CCError_t EPS_HmacFinish(CCHmacUserContext_t *ContextID_ptr, CCHashResultBuf_t HmacResultBuff);

/*
 * @param[in]  : OperationMode
 *               One of the supported HASH modes, as defined in CCHashOperationMode_t.
 * @param[in]  : key_ptr
 *               The pointer to the user's key buffer.
 * @param[in]  : keySize
 *               The key size in bytes. If the key size is bigger than the HASH block, the key will be hashed.
 *               The limitations on the key size are the same as the limitations on MAX hash size
 * @param[in]  : DataIn_ptr
 *               Pointer to the input data to be HASHed. The size of the scatter/gather list representing the data
 *               buffer is limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger
 *               than 64KB are broken into fragments <= 64KB).
 * @param[in]  : DataSize
 *               The size of the data to be hashed (in bytes)
 * @param[in]  : HmacResultBuff
 *               Pointer to the word-aligned 64 byte buffer. The actual size of the HMAC result depends on
 *               CCHashOperationMode_t.
 */
CIMPORT_C CCError_t EPS_Hmac(CCHashOperationMode_t OperationMode, uint8_t *key_ptr,
			     size_t keySize, uint8_t *DataIn_ptr, size_t DataSize,
			     CCHashResultBuf_t HmacResultBuff);

#endif

