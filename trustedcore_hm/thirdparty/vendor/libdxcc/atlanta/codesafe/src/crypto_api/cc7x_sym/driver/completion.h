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

#ifndef  _COMPLETION_H
#define  _COMPLETION_H


#include "completion_plat.h"

/******************************************************************************
*			   	    MACROS
******************************************************************************/

/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/

/*!
 * This function calls the platform specific Completion Initializer function.
 *
 * \return int one of the error codes defined in err.h
 */
#define InitCompletion InitCompletionPlat

/*!
 * This function waits for current descriptor sequence completion.
 * The "WaitForSequenceCompletionPlat" function must implement by
 * the platform port layer.
 */
#define WaitForSequenceCompletion WaitForSequenceCompletionPlat

#endif /*_COMPLETION_H*/

