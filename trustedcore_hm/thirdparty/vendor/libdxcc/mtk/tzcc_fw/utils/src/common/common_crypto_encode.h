/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _COMMON_CRYPTO_ENCODE_H
#define _COMMON_CRYPTO_ENCODE_H

#include <stdint.h>

#define SASI_COMMON_CALC_BASE64_ENCODE_SIZE(origSize) ((((origSize + 2) / 3) * 4) + 1)
#define SASI_COMMON_CALC_BASE64_MAX_DECODE_SIZE(encodedSize) \
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
int32_t SaSi_CommonBase64Encode(uint8_t *pBuff, uint32_t buffLen, uint8_t *pEncBuff, uint32_t *pEecBuffLen);

/*
 * @brief performs base64-decode
 *
 * @param[in] pEncBuff          - base64-encoded buffer
 * @param[in] encBuffLen        - input buffer length
 * @param[in/out] pDecBuffLen   - decoded buffer length
 * @param[out] pDecBuff         - decoded buffer
 */
/* ****************************************************** */
int32_t SaSi_CommonBase64Decode(uint8_t *pEncBuff, uint32_t encBuffLen, uint8_t *pDecBuff, uint32_t *pDecBuffLen);

/*
 * @brief Encodes data into PEM format
 *
 * @param[in] pBuff             - the buffer to encode
 * @param[in] buffLen           - input buffer length
 * @param[out] pEncBuff         - encoded buffer
 * @param[in/out] pEncBuffLen   - encoded buffer length
 */
/* ****************************************************** */
int32_t SaSi_CommonPemEncode(uint8_t *pBuff, uint32_t buffLen, uint8_t *pEncBuff, uint32_t *pEecBuffLen);

/*
 * @brief Decode PEM-encoded data
 *
 * @param[in] pEncBuff          - base64-encoded buffer
 * @param[in] encBuffLen        - input buffer length
 * @param[out] pDecBuff         - decoded buffer
 * @param[in/out] pDecBuffLen   - decoded buffer length
 */
/* ****************************************************** */
int32_t SaSi_CommonPemDecode(uint8_t *pEncBuff, uint32_t encBuffLen, uint8_t *pDecBuff, uint32_t *pDecBuffLen);

#endif
