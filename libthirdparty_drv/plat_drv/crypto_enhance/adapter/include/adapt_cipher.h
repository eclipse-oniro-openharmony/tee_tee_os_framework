/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: declare of api
 * Author     : l00370476
 * Create     : 2018/12/28
 */

#ifndef __ADAPT_CIPHER_H__
#define __ADAPT_CIPHER_H__

#include <cc_crypto_ctx.h>
#include <cc_aes.h>
#include <cc_aes_defs.h>
#include <cc_aes_error.h>
#include <cc_des.h>
#include <cc_des_error.h>
#include "adapt_common.h"

CCError_t EPS_AesSetKey(
	CCAesUserContext_t  *pContext,
	CCAesKeyType_t       keyType,
	void                *pKeyData,
	size_t               keyDataSize);

CIMPORT_C CCError_t EPS_AesSetIv(
	CCAesUserContext_t  *pContext,
	CCAesIv_t            pIV);

CIMPORT_C CCError_t EPS_AesInit(
	CCAesUserContext_t  *pContext,
	CCAesEncryptMode_t   encryptDecryptFlag,
	CCAesOperationMode_t operationMode,
	CCAesPaddingType_t   paddingType);

CIMPORT_C CCError_t EPS_AesBlock(
	CCAesUserContext_t  *pContext,
	uint8_t             *pDataIn,
	size_t               dataInSize,
	uint8_t             *pDataOut);

CIMPORT_C CCError_t EPS_AesFinish(
	CCAesUserContext_t  *pContext,
	size_t               dataSize,
	uint8_t             *pDataIn,
	size_t               dataInBuffSize,
	uint8_t             *pDataOut,
	size_t              *dataOutBuffSize);

/*
 * @brief     : This function is used to initialize the DES machine.
 *              To operate the DES machine, this should be the first function called.
 * @param[in] : ContextID_ptr
 *              Pointer to the DES context buffer allocated by the user, which is used for
 *              the DES machine operation.
 * @param[in] : IV_ptr
 *              The IV buffer. In ECB mode this parameter is not used. In CBC this parameter should
 *              contain the IV values.
 * @param[in] : Key_ptr
 *              Pointer to the user's key buffer.
 * @param[in] : NumOfKeys
 *              The number of keys used: 1, 2 or 3 (defined by the enum).One key implies DES
 *              encryption/decryption, two or three keys imply triple-DES.
 * @param[in] : EncryptDecryptFlag
 *              A flag that determines whether the DES should perform an Encrypt operation (0)
 *              or a Decrypt operation (1).
 * @param[in] : OperationMode The operation mode: ECB or CBC.

 * @return    : CC_OK on success.
 * @return    : A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t EPS_DesInit(
	CCDesUserContext_t  *ContextID_ptr,
	CCDesIv_t            IV_ptr,
	CCDesKey_t          *Key_ptr,
	CCDesNumOfKeys_t     NumOfKeys,
	CCDesEncryptMode_t   EncryptDecryptFlag,
	CCDesOperationMode_t OperationMode);

/*
 * @brief     : This function is used to process a block on the DES machine.
 *              This function should be called after the CC_DesInit function was called.
 * @param[in] : ContextID_ptr
 *              Pointer to the DES context buffer allocated by the user, which is used for the DES machine operation.
 *              This should be the same context used on the previous call of this session.
 * @param[in] : DataIn_ptr
 *              The pointer to input data. The size of the scatter/gather list representing the data buffer is limited
 *              to 128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are broken
 *              into fragments <= 64KB).
 * @param[in] : DataInSize
 *              The size of the input data. Must be a multiple of the DES block size, 8 bytes.
 * @param[in] : DataOut_ptr
 *              The pointer to the output data. The size of the scatter/gather list representing the data buffer is
 *              limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are
 *              broken into fragments <= 64KB).
 * @return    : CC_OK on success.
 * @return    : A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t EPS_DesBlock(
	CCDesUserContext_t  *ContextID_ptr,
	uint8_t             *DataIn_ptr,
	size_t               DataInSize,
	uint8_t             *DataOut_ptr);

/*
 * @brief     : This function is used to end the DES processing session.
 *              It is the last function called for the DES process.
 * @param[in] : ContextID_ptr
 *              Pointer to the DES context buffer allocated by the user that is used for the DES machine operation.
 *              This should be the same context that was used on the previous call of this session.
 * @return    : CC_OK on success.
 * @return    : A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t EPS_DesFree(CCDesUserContext_t *ContextID_ptr);

/*
 * @brief     : This function is used to operate the DES machine in one integrated operation.
 * @param[in] : IV_ptr
 *              The IV buffer in CBC mode. In ECB mode this parameter is not used.
 * @param[in] : Key_ptr
 *              Pointer to the user's key buffer.
 * @param[in] : NumOfKeys
 *              The number of keys used: single (56bit), double (112bit) or triple (168bit).
 * @param[in] : EncryptDecryptFlag
 *              A flag that determines if the DES should perform an Encrypt operation (0) or a Decrypt operation (1).
 * @param[in] : OperationMode
 *              The operation mode: ECB or CBC.
 * @param[in] : DataIn_ptr
 *              The pointer to the input data. The size of the scatter/gather list representing the data buffer is
 *              limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are
 *              broken into fragments <= 64KB).
 * @param[in] : DataInSize
 *              The size of the input data. Must be a multiple of the DES block size, 8 bytes.
 * @param[in] : DataOut_ptr
 *              The pointer to the output data. The size of the scatter/gather list representing the data buffer is
 *              limited to 128 entries, and the size of each entry is limited to 64KB (fragments larger than 64KB are
 *              broken into fragments <= 64KB).
 * @return    : CC_OK on success.
 * @return    : A non-zero value from cc_des_error.h on failure.
 */
CIMPORT_C CCError_t  EPS_Des(
	CCDesIv_t            IV_ptr,
	CCDesKey_t          *Key_ptr,
	CCDesNumOfKeys_t     NumOfKeys,
	CCDesEncryptMode_t   EncryptDecryptFlag,
	CCDesOperationMode_t OperationMode,
	uint8_t             *DataIn_ptr,
	size_t               DataInSize,
	uint8_t             *DataOut_ptr);

#endif

