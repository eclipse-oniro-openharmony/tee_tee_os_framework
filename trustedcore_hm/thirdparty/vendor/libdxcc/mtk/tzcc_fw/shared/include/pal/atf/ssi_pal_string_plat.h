/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_PAL_STRING_INT_H
#define _SSI_PAL_STRING_INT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
/*
 * @brief File Description:
 *        This file contains wrapper functions for string manipulation.
 */

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/*
 * @brief A wrapper function for strlen functionality. The function returns the size of a given string
 *
 */
#define _SaSi_PalStrLen strlen

/*
 * @brief A wrapper function for strstr functionality. The functions find a string in a string and
 *        return a pointer to it.
 *
 */
#define _SaSi_PalFindStr strstr

/*
 * @brief A wrapper function for strchr functionality. The function finds a char in a given string.
 *
 */
#define _SaSi_PalStrChr strchr

/*
 * @brief A wrapper function for strrchr functionality. The function finds a char inside a string
 *        (from the end) and returns a pointer to it
 *
 */
#define _SaSi_PalStrRChr strrchr

/*
 * @brief A wrapper for strncpy functionality. The function copies a string.
 *
 */
#define _SaSi_PalStrNCopy strncpy

#ifdef __cplusplus
}
#endif

#endif
