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

#ifndef _CC_PAL_ABORT_H
#define _CC_PAL_ABORT_H


#include "cc_pal_abort_plat.h"

/*!
@file
@brief This file contains definitions for PAL Abort API.
*/

/*!
This function performs the "Abort" operation, should be implemented according to platform and TEE_OS.
*/

#define CC_PalAbort(msg) //_CC_PalAbort(msg)

#endif


