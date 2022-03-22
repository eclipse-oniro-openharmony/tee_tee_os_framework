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

#ifndef  TEE_COMPLETION_PLAT_H
#define  TEE_COMPLETION_PLAT_H

#include "cc_pal_types.h"

/******************************************************************************
*				DEFINES
******************************************************************************/


/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/


/*!
 * This function initializes the completion counter event, clears the
 * state structure and sets completion counter "0" as the first available
 * counter to be used when calling "AllocCounter".
 *
 * \return int one of the error codes defined in err.h
 */
void InitCompletionPlat(void);

/*!
 * This function waits for current descriptor sequence completion.
 */
void WaitForSequenceCompletionPlat(void);

/*!
 * This function allocates a reserved word for dummy completion descriptor.
 *
 * \return a non-zero value in case of failure
 */
int AllocCompletionPlatBuffer(void);


/*!
 * This function free resources previuosly allocated by AllocCompletionPlatBuffer.
 */
void FreeCompletionPlatBuffer(void);

#endif /*TEE_COMPLETION_PLAT_H*/

