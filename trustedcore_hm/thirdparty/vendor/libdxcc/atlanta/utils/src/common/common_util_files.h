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

#ifndef _COMMON_UTIL_FILES_H
#define _COMMON_UTIL_FILES_H


#include <stdint.h>

#ifdef WIN32
#define UTILEXPORT_C __declspec(dllexport)
#else
#define UTILEXPORT_C
#endif

#define UTIL_MAX_FILE_NAME  256

/**
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t CC_CommonUtilCopyDataFromRawTextFile (uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen);

/**
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t CC_CommonUtilCopyDataFromTextFile (uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen);

/**
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t CC_CommonUtilCopyDataFromBinFile (uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen);

/**
 * @brief This function copies a buffer to a file
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t CC_CommonUtilCopyBuffToBinFile (uint8_t *fileName, uint8_t *inBuff, uint32_t inBuffLen);
#endif
