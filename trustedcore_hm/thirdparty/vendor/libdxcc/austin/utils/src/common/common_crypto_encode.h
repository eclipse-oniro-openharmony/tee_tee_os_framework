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

#ifndef _COMMON_CRYPTO_ENCODE_H
#define _COMMON_CRYPTO_ENCODE_H

#define DX_COMMON_CALC_BASE64_ENCODE_SIZE(origSize) ((((origSize + 2) / 3) * 4) + 1)
#define DX_COMMON_CALC_BASE64_MAX_DECODE_SIZE(encodedSize) \
    ((encodedSize * 3) / 4) /* max size in case no padding to encoded buffer */

/*
 * @brief performs base64-encode
 *
 * @param[in] pBuff             - the buffer to encode
 * @param[in] buffLen           - input buffer length
 * @param[in/out] pEncBuffLen   - encoded buffer length
 * @param[out] pEncBuff         - encoded buffer
 */
/* ****************************************************** */
int DX_Common_Base64_Encode(unsigned char *pBuff, unsigned int buffLen, unsigned char *pEncBuff,
                            unsigned int *pEecBuffLen);

/*
 * @brief performs base64-decode
 *
 * @param[in] pEncBuff          - base64-encoded buffer
 * @param[in] encBuffLen        - input buffer length
 * @param[in/out] pDecBuffLen   - decoded buffer length
 * @param[out] pDecBuff         - decoded buffer
 */
/* ****************************************************** */
int DX_Common_Base64_Decode(unsigned char *pEncBuff, unsigned int encBuffLen, unsigned char *pDecBuff,
                            unsigned int *pDecBuffLen);

/*
 * @brief Encodes data into PEM format
 *
 * @param[in] pBuff             - the buffer to encode
 * @param[in] buffLen           - input buffer length
 * @param[out] pEncBuff         - encoded buffer
 * @param[in/out] pEncBuffLen   - encoded buffer length
 */
/* ****************************************************** */
int DX_Common_PEM_Encode(unsigned char *pBuff, unsigned int buffLen, unsigned char *pEncBuff,
                         unsigned int *pEecBuffLen);

/*
 * @brief Decode PEM-encoded data
 *
 * @param[in] pEncBuff          - base64-encoded buffer
 * @param[in] encBuffLen        - input buffer length
 * @param[out] pDecBuff         - decoded buffer
 * @param[in/out] pDecBuffLen   - decoded buffer length
 */
/* ****************************************************** */
int DX_Common_PEM_Decode(unsigned char *pEncBuff, unsigned int encBuffLen, unsigned char *pDecBuff,
                         unsigned int *pDecBuffLen);

#endif
