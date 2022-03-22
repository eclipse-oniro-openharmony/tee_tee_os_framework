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

#ifndef _COMMON_UTIL_FILES_H
#define _COMMON_UTIL_FILES_H

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
UTILEXPORT_C int DX_Common_Util_copyDataFromRawTextFile(unsigned char *fileName, unsigned char *outBuff,
                                                        unsigned int *outBuffLen);

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int DX_Common_Util_copyDataFromTextFile(unsigned char *fileName, unsigned char *outBuff,
                                                     unsigned int *outBuffLen);

/*
 * @brief This function
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int DX_Common_Util_copyDataFromBinFile(unsigned char *fileName, unsigned char *outBuff,
                                                    unsigned int *outBuffLen);

/*
 * @brief This function copies a buffer to a file
 *
 * @param[in]
 *
 * @param[out]
 *
 * @return uint8_t -

 */
UTILEXPORT_C int DX_Common_Util_copyBuffToBinFile(unsigned char *fileName, unsigned char *inBuff,
                                                  unsigned int inBuffLen);
#endif
