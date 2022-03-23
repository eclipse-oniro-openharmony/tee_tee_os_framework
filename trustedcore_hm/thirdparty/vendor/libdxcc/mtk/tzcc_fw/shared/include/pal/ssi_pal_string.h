/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_STRING_H
#define _SSI_PAL_STRING_H

#ifdef __cplusplus
extern "C" {
#endif

#include "ssi_pal_types.h"
#include "ssi_pal_string_plat.h"
/*
 * @brief File Description:
 *        This file contains functions for string manipulation. The functions implementations
 *        are generally just wrappers to different operating system calls.
 *        None of the described functions will check the input parameters so the behavior
 *        of the APIs in illegal parameters case is dependent on the operating system behavior.
 *
 */

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/*
 * @brief This function purpose is to return the string length (Null terminated buffer)
 *
 *
 * @param[in] aStr - Pointer to string
 *
 * @return The string length
 */
uint32_t SaSi_PalStrLen(char *aStr);

/* Definition for StrLen */
#define SaSi_PalStrLen _SaSi_PalStrLen

/*
 * @brief This function purpose is to find the string specified in aStrSearchFor in the
 *        string specified in aStrSearchIn
 *
 *
 * @param[in] aStrSearchIn - Pointer to string to search in
 * @param[in] aStrSearchFor - Pointer to string to search for in aStrSearchIn
 *
 * @return Pointer to the first occurrence of searchFor in searchIn or NULL if string
 *           was not found.
 */
char *SaSi_PalFindStr(const char *aStrSearchIn, const char *aStrSearchFor);

/* Definition for */
#define SaSi_PalFindStr _SaSi_PalFindStr

/*
 * @brief This function purpose is to find the first appearance of aChr in aStr.
 *
 *
 * @param[in] aStr - Pointer to string
 * @param[in] aChr - Char to look for in string
 *
 * @return A pointer to the first appearance of aChr in aStr, if not found NULL is returned
 */
char *SaSi_PalStrChr(char *aStr, char aChr);

/* Definition for StrChr */
#define SaSi_PalStrChr _SaSi_PalStrChr

/*
 * @brief This function purpose is to find the last appearance of aChr in aStr
 *
 *
 * @param[in] aStr - Pointer to string
 * @param[in] aChr - Char to look for in string
 *
 * @return A pointer to the last appearance of aChr in aStr, if not found NULL is returned
 */
char *SaSi_PalStrRChr(char *aStr, char aChr);

/* Definition for StrRChr */
#define SaSi_PalStrRChr _SaSi_PalStrRChr

/*
 * @brief This function purpose is to copy aSize bytes from aSrcStr to aDestStr.
 *
 *
 * @param[in] aDestStr - Pointer to destination string
 * @param[in] aSrcStr - Pointer to source string (to copy from)
 * @param[in] aSize - Number of bytes to copy
 *
 * @return A pointer to destination string
 */
char *SaSi_PalStrNCopy(char *aDestStr, char *aSrcStr, uint32_t aSize);

/* Definition for StrNCopy */
#define SaSi_PalStrNCopy _SaSi_PalStrNCopy

#ifdef __cplusplus
}
#endif

#endif
