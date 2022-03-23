/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _COMMON_UTIL_FILES_H
#define _COMMON_UTIL_FILES_H

#include <stdint.h>

#ifdef WIN32
#define UTILEXPORT_C __declspec(dllexport)
#else
#define UTILEXPORT_C
#endif

#define UTIL_MAX_FILE_NAME 256

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t SaSi_CommonUtilCopyDataFromRawTextFile(uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen);

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t SaSi_CommonUtilCopyDataFromTextFile(uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen);

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t SaSi_CommonUtilCopyDataFromBinFile(uint8_t *fileName, uint8_t *outBuff, uint32_t *outBuffLen);

/*
 * @brief This function copies a buffer to a file
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int32_t SaSi_CommonUtilCopyBuffToBinFile(uint8_t *fileName, uint8_t *inBuff, uint32_t inBuffLen);
#endif
