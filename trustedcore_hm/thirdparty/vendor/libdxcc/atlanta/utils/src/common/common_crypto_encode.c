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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/bio.h>
#include "common_crypto_encode.h"
#include "common_util_log.h"


/* header and footer of the PEM */
#define CC_UTIL_COMMON_PEM_HEADER		"-----BEGIN CERTIFICATE-----"
#define CC_UTIL_COMMON_PEM_FOOTER  		"-----END CERTIFICATE-----"


#define IS_BASE64_ENCODE_VAL(val) \
        ((((val >= '0') && (val <= '9')) || \
         ((val >= 'A') && (val <= 'Z')) || \
         ((val >= 'a') && (val <= 'z')) || \
         (val == '+') || (val == '/'))?1:0)

/**
* @brief Encodes data into base64 format
*
* @param[in] pBuff             - the buffer to encode
* @param[in] buffLen           - input buffer length
* @param[out] pEncBuff         - encoded buffer
* @param[in/out] pEncBuffLen   - encoded buffer length
*/
/*********************************************************/
int32_t CC_CommonBase64Encode(uint8_t *pBuff,
			    uint32_t  buffLen,
			    uint8_t *pEncBuff,
			    uint32_t *pEecBuffLen)
{
	BIO *bio = NULL;
	BIO *b64 = NULL;;
	size_t size;
	FILE *stream = NULL;
	int32_t actualWritten = 0;
	int32_t rc = 0;

	if ((NULL == pBuff) ||
	    (NULL == pEncBuff) ||
	    (NULL == pEecBuffLen) ||
	    (0 == buffLen)) {
		UTIL_LOG_ERR("ilegal inputs\n");
		return 1;
	}
	if (*pEecBuffLen < ((((buffLen*4)+2)/3)+1)) {
		UTIL_LOG_ERR("ilegal outBuffLen %d \n", *pEecBuffLen);
		return 1;
	}

	memset(pEncBuff, 0, *pEecBuffLen);

	stream = fmemopen(pEncBuff, *pEecBuffLen, "w");
	if (NULL == stream) {
		UTIL_LOG_ERR("failed to open mem\n");
		return 1;
	}
	b64 = BIO_new(BIO_f_base64());
	if (NULL == b64) {
		UTIL_LOG_ERR("failed to BIO_new\n");
		rc = 1;
		goto End_Base64Encode;
	}
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	if (NULL == bio) {
		UTIL_LOG_ERR("failed to BIO_new_fp\n");
		rc = 1;
		goto End_Base64Encode;
	}
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	actualWritten = BIO_write(bio, pBuff, buffLen);
	BIO_flush(bio);
	if (actualWritten != buffLen) {
		UTIL_LOG_ERR("failed to BIO_write buffLen %d = actualWritten %d\n", buffLen, actualWritten);
		rc = 1;
		goto End_Base64Encode;
	}
	rc = 0;

	End_Base64Encode:
	if (bio != NULL) { /* clears bio and b64, b64 mustn't clear explicitly*/
		BIO_free_all(bio);
	}
	if (stream != NULL) {
		fclose(stream);
	}
	return rc;
}


/**
* @brief Decode base64-encoded data
*
* @param[in] pEncBuff          - base64-encoded buffer
* @param[in] encBuffLen        - input buffer length
* @param[out] pDecBuff         - decoded buffer
* @param[in/out] pDecBuffLen   - decoded buffer length
*/
/*********************************************************/
int32_t CC_CommonBase64Decode(uint8_t *pEncBuff,
			    uint32_t  encBuffLen,
			    uint8_t *pDecBuff,
			    uint32_t *pDecBuffLen)
{
	BIO *bio = NULL;
	BIO *b64 = NULL;
	int32_t actualRead = 0;
	int32_t expDecBuffLen = 0;
	FILE* stream = NULL;
	int32_t padding = 0;
	int32_t rc = 0;
	int32_t i = 0;

	if ((NULL == pEncBuff) ||
	    (NULL == pDecBuff) ||
	    (NULL == pDecBuffLen) ||
	    (0 == encBuffLen)) {
		UTIL_LOG_ERR("ilegal inputs\n");
		return 1;
	}

	UTIL_LOG_INFO("started. encBuffLen %d\n", encBuffLen);
	/* check validity of decoded buffer length */
	i = encBuffLen-1;
	while (!IS_BASE64_ENCODE_VAL(pEncBuff[i])) {
		UTIL_LOG_INFO("pEncBuff[%d] 0x%x\n", i, pEncBuff[i]);
		padding++;
		i--;
	}
	expDecBuffLen = (((encBuffLen-padding)*3)/4);
	if (*pDecBuffLen < expDecBuffLen) {
		UTIL_LOG_ERR("ilegal inputs outBuffLen %d expDecBuffLen %d\n", *pDecBuffLen, expDecBuffLen);
		rc = 1;
		goto End_Base64Decode;
	}

	memset(pDecBuff, 0, *pDecBuffLen);

	stream = fmemopen(pEncBuff, encBuffLen, "r");
	if (NULL == stream) {
		UTIL_LOG_ERR("failed to open mem\n");
		rc = 1;
		goto End_Base64Decode;
	}

	b64 = BIO_new(BIO_f_base64());
	if (NULL == b64) {
		UTIL_LOG_ERR("failed to BIO_new\n");
		rc = 1;
		goto End_Base64Decode;
	}
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	if (NULL == bio) {
		UTIL_LOG_ERR("failed to BIO_new_fp\n");
		rc = 1;
		goto End_Base64Decode;
	}
	bio = BIO_push(b64, bio);
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	actualRead = BIO_read(bio, pDecBuff, encBuffLen);
	if (actualRead != expDecBuffLen) {
		UTIL_LOG_ERR("failed to BIO_read expDecBuffLen %d = actualRead %d\n", expDecBuffLen, actualRead);
		rc = 1;
		goto End_Base64Decode;
	}
	*pDecBuffLen = actualRead;
	rc = 0;

	End_Base64Decode:
	if (bio != NULL) { /* clears bio and b64, b64 mustn't clear explicitly*/
		BIO_free_all(bio);
	}
	if (stream != NULL) {
		fclose(stream);
	}
	UTIL_LOG_INFO("rc %d\n", rc);
	return rc;
}



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
			    uint32_t *pEecBuffLen)
{
	#define NL_MAX_BYTES_SIZE  64
	BIO *bio = NULL;
	BIO *b64 = NULL;;
	size_t size;
	FILE *stream = NULL;
	int32_t actualWritten = 0;
	int32_t rc = 0;
	int32_t base64Size = ((((buffLen*4)+2)/3)+1);
	int32_t base64NlSize = ((base64Size+NL_MAX_BYTES_SIZE-1)/NL_MAX_BYTES_SIZE);
	int32_t pemSize = 0;
	uint8_t *pNextEncOffset = NULL;

	if ((NULL == pBuff) ||
	    (NULL == pEncBuff) ||
	    (NULL == pEecBuffLen) ||
	    (0 == buffLen)) {
		UTIL_LOG_ERR("ilegal inputs\n");
		return 1;
	}

	/* use buffer size, NL might be added */
	pemSize = *pEecBuffLen;

	UTIL_LOG_INFO("pemSize %d, base64Size %d, buffLen %d\n", pemSize, base64Size, buffLen);
	memset(pEncBuff, 0, pemSize);
	memcpy(pEncBuff, CC_UTIL_COMMON_PEM_HEADER, sizeof(CC_UTIL_COMMON_PEM_HEADER));

	pNextEncOffset = pEncBuff+sizeof(CC_UTIL_COMMON_PEM_HEADER);

	stream = fmemopen(pNextEncOffset, pemSize, "w");
	if (NULL == stream) {
		UTIL_LOG_ERR("failed to open mem\n");
		return 1;
	}
	b64 = BIO_new(BIO_f_base64());
	if (NULL == b64) {
		UTIL_LOG_ERR("failed to BIO_new\n");
		rc = 1;
		goto End_Base64Encode;
	}
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	if (NULL == bio) {
		UTIL_LOG_ERR("failed to BIO_new_fp\n");
		rc = 1;
		goto End_Base64Encode;
	}
	bio = BIO_push(b64, bio);
	actualWritten = BIO_write(bio, pBuff, buffLen);
	BIO_flush(bio);
	if (actualWritten != buffLen) {
		UTIL_LOG_ERR("failed to BIO_write buffLen %d = actualWritten %d\n", buffLen, actualWritten);
		rc = 1;
		goto End_Base64Encode;
	}
	UTIL_LOG_INFO("base64Size %d\n", base64Size);
	memcpy(pEncBuff+pemSize-sizeof(CC_UTIL_COMMON_PEM_FOOTER), CC_UTIL_COMMON_PEM_FOOTER, sizeof(CC_UTIL_COMMON_PEM_FOOTER));
	//UTIL_LOG_BYTE_BUFF("pEncBuff", pEncBuff, pemSize);
	rc = 0;

	End_Base64Encode:
	if (bio != NULL) { /* clears bio and b64, b64 mustn't clear explicitly*/
		BIO_free_all(bio);
	}
	if (stream != NULL) {
		fclose(stream);
	}
	return rc;
}


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
			    uint32_t *pDecBuffLen)
{
	BIO *bio = NULL;
	BIO *b64 = NULL;
	int32_t actualRead = 0;
	int32_t expDecBuffLen = 0;
	FILE* stream = NULL;
	int32_t padding = 0;
	int32_t rc = 0;
	int32_t i = 0;
	uint8_t *pBase64Buff = NULL;

	if ((NULL == pEncBuff) ||
	    (NULL == pDecBuff) ||
	    (NULL == pDecBuffLen) ||
	    (0 == encBuffLen)) {
		UTIL_LOG_ERR("ilegal inputs\n");
		return 1;
	}

	UTIL_LOG_INFO("started. encBuffLen %d\n", encBuffLen);
	//UTIL_LOG_BYTE_BUFF("pEncBuff", pEncBuff, encBuffLen);
	pBase64Buff = pEncBuff+sizeof(CC_UTIL_COMMON_PEM_HEADER);
	encBuffLen -= (sizeof(CC_UTIL_COMMON_PEM_HEADER) + sizeof(CC_UTIL_COMMON_PEM_FOOTER));
	UTIL_LOG_INFO("encBuffLen 0x%x, CC_UTIL_COMMON_PEM_HEADER 0x%lx, CC_UTIL_COMMON_PEM_FOOTER 0x%lx\n", encBuffLen, sizeof(CC_UTIL_COMMON_PEM_HEADER), sizeof(CC_UTIL_COMMON_PEM_FOOTER));
	/* check validity of decoded buffer length */
	i = encBuffLen-1;
	while ((!IS_BASE64_ENCODE_VAL(pBase64Buff[i])) && (i > 0)) {
		UTIL_LOG_INFO("pBase64Buff[%d] 0x%x\n", i, pBase64Buff[i]);
		padding++;
		i--;
	}
	expDecBuffLen = (((encBuffLen-padding)*3)/4);
	if (*pDecBuffLen < expDecBuffLen) {
		UTIL_LOG_ERR("ilegal inputs outBuffLen %d expDecBuffLen %d\n", *pDecBuffLen, expDecBuffLen);
		rc = 1;
		goto End_PemDecode;
	}
	UTIL_LOG_INFO("expDecBuffLen 0x%x\n", expDecBuffLen);

	memset(pDecBuff, 0, *pDecBuffLen);

	stream = fmemopen(pBase64Buff, encBuffLen, "r");
	if (NULL == stream) {
		UTIL_LOG_ERR("failed to open mem\n");
		rc = 1;
		goto End_PemDecode;
	}

	b64 = BIO_new(BIO_f_base64());
	if (NULL == b64) {
		UTIL_LOG_ERR("failed to BIO_new\n");
		rc = 1;
		goto End_PemDecode;
	}
	bio = BIO_new_fp(stream, BIO_NOCLOSE);
	if (NULL == bio) {
		UTIL_LOG_ERR("failed to BIO_new_fp\n");
		rc = 1;
		goto End_PemDecode;
	}
	bio = BIO_push(b64, bio);
	actualRead = BIO_read(bio, pDecBuff, encBuffLen);
	if (0 == actualRead) {
		UTIL_LOG_ERR("failed to BIO_read actualRead %d\n", actualRead);
		rc = 1;
		goto End_PemDecode;
	}
	*pDecBuffLen = actualRead;
	rc = 0;

	End_PemDecode:
	if (bio != NULL) { /* clears bio and b64, b64 mustn't clear explicitly*/
		BIO_free_all(bio);
	}
	if (stream != NULL) {
		fclose(stream);
	}
	UTIL_LOG_INFO("rc %d\n", rc);
	return rc;
}
