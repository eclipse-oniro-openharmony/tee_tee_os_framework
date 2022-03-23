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

#ifndef _CC_PAL_MEMALLOC_INT_H
#define _CC_PAL_MEMALLOC_INT_H


#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>
/**
* @brief File Description:
*        This file contains wrappers for memory operations APIs.
*/


/*----------------------------
      PUBLIC FUNCTIONS
-----------------------------------*/

/**
 * @brief A wrapper over malloc functionality. The function allocates a buffer according to given size
 *
 */
 #define _CC_PalMemMalloc    malloc


/**
 * @brief A wrapper over realloc functionality. The function allocates and copy a buffer
 *        according to size
 *
 */
#define _CC_PalMemRealloc    realloc


/**
 * @brief A wrapper over free functionality/ The function will free allocated memory.
 *
 */
#define _CC_PalMemFree       free



#ifdef __cplusplus
}
#endif

#endif


