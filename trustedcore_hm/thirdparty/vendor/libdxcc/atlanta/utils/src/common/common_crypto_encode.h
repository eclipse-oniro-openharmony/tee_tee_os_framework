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

#ifndef _COMMON_CRYPTO_ENCODE_H
#define _COMMON_CRYPTO_ENCODE_H

#include <stdint.h>

#define CC_COMMON_CALC_BASE64_ENCODE_SIZE(origSize) ((((origSize+2)/3)*4)+1)
#define CC_COMMON_CALC_BASE64_MAX_DECODE_SIZE(encodedSize) ((encodedSize*3)/4)  /* max size in case no padding to encoded buffer */

/**
* @brief performs base64-encode
*
* @param[in] pBuff             - the buffer to encode
* @param[in] buffLen           - input buffer length
* @param[in/out] pEncBuffLen   - encoded buffer length
* @param[out] pEncBuff         - encoded buffer
*/
/*********************************************************/
int32_t CC_CommonBase64Encode(uint8_t *pBuff,
			    uint32_t  buffLen,
			    uint8_t *pEncBuff,
			    uint32_t *pEecBuffLen);


/**
* @brief performs base64-decode
*
* @param[in] pEncBuff          - base64-encoded buffer
* @param[in] encBuffLen        - input buffer length
* @param[in/out] pDecBuffLen   - decoded buffer length
* @param[out] pDecBuff         - decoded buffer
*/
/*********************************************************/
int32_t CC_CommonBase64Decode(uint8_t *pEncBuff,
			    uint32_t  encBuffLen,
			    uint8_t *pDecBuff,
			    uint32_t *pDecBuffLen);



/**
* @brief Encodes data into PEM format
*
* @param[in] pBuff             - the buffer to encode
* @param[in] buffLen           - input buffer length
* @param[out] pEncBuff         - encoded buffer
* @param[in/out] pEncBuffLen   - encoded buffer length
*/
/*********************************************************/
int32_t CC_CommonPemEncode(uint8_t *pBuff,
			    uint32_t  buffLen,
			    uint8_t *pEncBuff,
			    uint32_t *pEecBuffLen);


/**
* @brief Decode PEM-encoded data
*
* @param[in] pEncBuff          - base64-encoded buffer
* @param[in] encBuffLen        - input buffer length
* @param[out] pDecBuff         - decoded buffer
* @param[in/out] pDecBuffLen   - decoded buffer length
*/
/*********************************************************/
int32_t CC_CommonPemDecode(uint8_t *pEncBuff,
			    uint32_t  encBuffLen,
			    uint8_t *pDecBuff,
			    uint32_t *pDecBuffLen);

#endif
