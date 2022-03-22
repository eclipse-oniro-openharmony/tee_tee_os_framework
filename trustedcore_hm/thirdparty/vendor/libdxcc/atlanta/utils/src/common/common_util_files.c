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
#include <limits.h>
#include "common_util_log.h"

/**
 * @brief This function reads bytes from text file into provided buffer
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int32_t CC_CommonUtilCopyDataFromRawTextFile (uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen)
{
	int32_t status = 0;
	FILE *fd;
	int32_t actualFileLen=0;
	int32_t actualRead=0;
	int32_t maxBytesToRead = 0;


	if ((NULL == fileName) ||
	    (NULL == outBuff) ||
	    (NULL == outBuffLen)) {
		UTIL_LOG_ERR( "ilegal parameters for %s\n", __func__);
		return 1;
	}
	if (0 == *outBuffLen) {
		UTIL_LOG_ERR( "ilegal outBuffLen \n");
		return 1;
	}
	fd = fopen(fileName, "rt");
	if (NULL == fd) {
		UTIL_LOG_ERR( "failed to open file %s for reading\n", fileName);
		return 1;
	}
	memset(outBuff, 0, *outBuffLen);

	/* Get file length */
	fseek(fd, 0, SEEK_END);
	actualFileLen = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	/* calculate max bytes to read. should be the min of bytes in file and buffer size*/
	maxBytesToRead = (actualFileLen > (*outBuffLen))?(*outBuffLen):actualFileLen;
	if (0 == maxBytesToRead) {
		UTIL_LOG_ERR( "ilegal maxBytesToRead == 0\n");
		status = 1;
		goto EXIT;
	}

	/* read file content */
	actualRead = fread(outBuff, 1, maxBytesToRead, fd);

	while ((outBuff[actualRead-1] == ' ') ||
	       (outBuff[actualRead-1] == '\n') ||
	       (outBuff[actualRead-1] == '\0') ||
	       (outBuff[actualRead-1] == 0x0A) ||
	       (outBuff[actualRead-1] == 0x0D)) {
		actualRead--;
	}
	*outBuffLen = actualRead;

	EXIT:
	if (fd != NULL) {
		fclose(fd);
	}
	return status;
}


/**
 * @brief This function reads bytes from text file into provided buffer
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int32_t CC_CommonUtilCopyDataFromTextFile (uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen)
{
    #define NUM_OF_CHARS_FOR_BYTE 4
	int32_t status = 0;
	FILE *fd;
	int32_t i = 0, j=0, k=0;
	int32_t actualFileLen=0;
	int32_t tempNum=0;
	int32_t actualRead=0;
	int32_t maxBytesToRead = 0;
	int8_t *filebufptr = NULL;
	int8_t str[NUM_OF_CHARS_FOR_BYTE+1];


	if ((NULL == fileName) ||
	    (NULL == outBuff) ||
	    (NULL == outBuffLen)) {
		UTIL_LOG_ERR( "ilegal parameters for %s\n", __func__);
		return 1;
	}
	if (0 == *outBuffLen) {
		UTIL_LOG_ERR( "ilegal outBuffLen \n");
		return 1;
	}
	fd = fopen(fileName, "rt");
	if (NULL == fd) {
		UTIL_LOG_ERR( "failed to open file %s for reading\n", fileName);
		return 1;
	}
	memset(outBuff, 0, *outBuffLen);

	/* Get file length */
	fseek(fd, 0, SEEK_END);
	actualFileLen = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	/* calculate max bytes to read. should be the min of bytes in file and buffer size*/
	maxBytesToRead = (actualFileLen > (*outBuffLen*5))?(*outBuffLen*5):actualFileLen;
	if (0 == maxBytesToRead) {
		UTIL_LOG_ERR( "ilegal maxBytesToRead == 0\n");
		status = 1;
		goto EXIT;
	}


	/* allocate buffer for data from file */
	filebufptr = (int8_t*)malloc(maxBytesToRead+1);
	if (filebufptr == NULL) {
		UTIL_LOG_ERR( "failed to allocate memory\n");
		status = 1;
		goto EXIT;
	}

	/* NULL terminated string to avoid buffer overflow of the sscanf that is used later */
	filebufptr[maxBytesToRead] = '\0';

	/* read file content */
	actualRead = fread(filebufptr, 1, maxBytesToRead, fd);
	j=0;
	k=0;
	for (i=0; i<maxBytesToRead; i++) {
		if (((filebufptr[i] >= '0') && (filebufptr[i] <= '9')) ||
		    ((filebufptr[i] >= 'a') && (filebufptr[i] <= 'f')) ||
		    ((filebufptr[i] >= 'A') && (filebufptr[i] <= 'F')) ||
		    (filebufptr[i] == 'x') || (filebufptr[i] == 'X') &&
		    (k<NUM_OF_CHARS_FOR_BYTE)) {
			str[k++] = filebufptr[i];
		} else {
			if ((filebufptr[i] == ' ') ||
			    (filebufptr[i] == '\n') ||
			    (filebufptr[i] == '\0') ||
			    (filebufptr[i] == ',')) {
				if (k>0) {
					str[k] = '\0';
					tempNum = strtol(str, NULL, 16);
					if ((LONG_MIN == tempNum) ||
					    (LONG_MAX == tempNum)) {
						UTIL_LOG_ERR( "strtol failed. check file name %s\n", fileName);
						status = 1;
						goto EXIT_AND_FREE;
					}
					outBuff[j++] = tempNum;
					k = 0;
				}
				continue;
			} else {
				UTIL_LOG_ERR( "ilegal uint8_t in file %c offset %d within file name %s\n", filebufptr[i], i, fileName);
				status = 1;
				goto EXIT_AND_FREE;
			}
		}
	}
	*outBuffLen = j;

	EXIT_AND_FREE:
	if (filebufptr != NULL) {
		free(filebufptr);
	}
	EXIT:
	if (fd != NULL) {
		fclose(fd);
	}
	return status;
}


/**
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int32_t CC_CommonUtilCopyDataFromBinFile(uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen)
{
	int32_t rc = 0;
	FILE *fd;
	int32_t actualRead = 0;
	int32_t actualFileLen = 0;


	if ((NULL == fileName) ||
	    (NULL == outBuff) ||
	    (0 == *outBuffLen)) {
		UTIL_LOG_ERR( "ilegal parameters for %s\n", __func__);
		return 1;
	}
	UTIL_LOG_INFO( "opening %s\n", fileName);
	fd = fopen(fileName, "rb");
	if (NULL == fd) {
		UTIL_LOG_ERR( "failed to open file %s for reading\n", fileName);
		return 1;
	}
	/* Get file length */
	fseek(fd, 0, SEEK_END);
	actualFileLen=ftell(fd);
	fseek(fd, 0, SEEK_SET);
	if (0 == actualFileLen) {
		UTIL_LOG_ERR( "ilegal actualFileLen == 0\n");
		rc = 3;
		goto EXIT_AND_FREE;
	}

	/* calculate max bytes to read. should be the min of bytes in file and buffer size*/
	if (actualFileLen > *outBuffLen) {
		UTIL_LOG_ERR( "ilegal actualFileLen %d > *outBuffLen %d\n", actualFileLen, *outBuffLen);
		rc = 2;
		goto EXIT_AND_FREE;
	}

	/* read file content */
	actualRead = fread(outBuff, 1, actualFileLen, fd);
	if (EOF == outBuff[actualRead-1]) {
		actualRead--;
	}
	*outBuffLen = actualRead;

	EXIT_AND_FREE:
	if (fd != NULL) {
		fclose(fd);
	}
	return rc;
}


/**
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
int32_t CC_CommonUtilCopyBuffToBinFile(uint8_t *fileName, uint8_t *inBuff, uint32_t inBuffLen)
{
	int32_t rc = 0;
	int32_t actualWriten = 0;
	FILE *fd;


	if ((NULL == fileName) ||
	    (NULL == inBuff) ||
	    (0 == inBuffLen)) {
		UTIL_LOG_ERR( "ilegal parameters for %s\n", __func__);
		return 1;
	}
	fd = fopen(fileName, "wb");
	if (NULL == fd) {
		UTIL_LOG_ERR( "failed to open file %s for writing\n", fileName);
		return 1;
	}

	actualWriten = fwrite(inBuff, 1, inBuffLen, fd);
	if (actualWriten != inBuffLen) {
		UTIL_LOG_ERR( "failed to write data to file actual written %d, expected %d\n", actualWriten, inBuffLen);
		rc = 1;
	}

	if (fd != NULL) {
		fclose(fd);
	}
	UTIL_LOG_ERR( "%d bytes were written %s\n", actualWriten, fileName);


	return rc;
}
