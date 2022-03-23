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

#ifndef _CC_SECURE_CLK_DEFS_H
#define _CC_SECURE_CLK_DEFS_H


/*!
@file
@brief This file contains definitions for secure clock. The file contains configurable parameters that should be adjusted to the target
       platform.
*/

#ifdef __cplusplus
extern "C"
{
#endif

/* Secure Clock definitions */
/*-------------------------*/

/*! Defines the frequency of the low-resolution clock in Hz units. Modify the value to the external slow clock frequency on
  the target platform. 1MHz (1000000) is recommended. */
#define EXTERNAL_SLOW_OSCILLATOR_HZ 1000000

#ifdef __cplusplus
}
#endif

#endif



