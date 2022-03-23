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

#ifndef _CC_PKA_HW_PLAT_DEFS_H
#define _CC_PKA_HW_PLAT_DEFS_H

#ifdef __cplusplus
extern "C"
{
#endif

/*!
@file
@brief Contains the enums and definitions that are used in the PKA code (definitions that are platform dependent).
*/

#define CC_PKA_WORD_SIZE_IN_BITS		     128

#define CC_RSA_MAX_VALID_KEY_SIZE_VALUE_IN_BITS      3072

#define CC_RSA_MAX_KEY_GENERATION_HW_SIZE_BITS       4096


/* PKA operations maximal count of extra bits: */
#define PKA_EXTRA_BITS  8
#define PKA_MAX_COUNT_OF_PHYS_MEM_REGS  32

#ifdef __cplusplus
}
#endif

#endif //_CC_PKA_HW_PLAT_DEFS_H


