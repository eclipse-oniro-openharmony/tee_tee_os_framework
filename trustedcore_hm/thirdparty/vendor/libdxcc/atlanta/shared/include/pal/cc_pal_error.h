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

#ifndef _CC_PAL_ERROR_H
#define _CC_PAL_ERROR_H

/*!
@file
@brief This file contains the platform dependent error definitions.
*/

#ifdef __cplusplus
extern "C"
{
#endif

#define CC_PAL_BASE_ERROR                0x0F000000

/* Memory error returns */
#define CC_PAL_MEM_BUF1_GREATER          CC_PAL_BASE_ERROR + 0x01UL
#define CC_PAL_MEM_BUF2_GREATER          CC_PAL_BASE_ERROR + 0x02UL

/* Semaphore error returns */
#define CC_PAL_SEM_CREATE_FAILED         CC_PAL_BASE_ERROR + 0x03UL
#define CC_PAL_SEM_DELETE_FAILED         CC_PAL_BASE_ERROR + 0x04UL
#define CC_PAL_SEM_WAIT_TIMEOUT          CC_PAL_BASE_ERROR + 0x05UL
#define CC_PAL_SEM_WAIT_FAILED           CC_PAL_BASE_ERROR + 0x06UL
#define CC_PAL_SEM_RELEASE_FAILED        CC_PAL_BASE_ERROR + 0x07UL

#define CC_PAL_ILLEGAL_ADDRESS	   	 CC_PAL_BASE_ERROR + 0x08UL

#ifdef __cplusplus
}
#endif

#endif


