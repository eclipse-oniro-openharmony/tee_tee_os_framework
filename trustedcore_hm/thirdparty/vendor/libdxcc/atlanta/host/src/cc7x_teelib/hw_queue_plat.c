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
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_HW_QUEUE

#include "cc_pal_types.h"
#include "cc_pal_log.h"
#include "cc_hw_queue_defs.h"
#include "hw_queue_plat.h"
#include "cc_sym_error.h"
#include "cc_hal.h"

/******************************************************************************
*				FUNCTIONS
******************************************************************************/


/*!
 * Waits until the HW queue Water Mark is signaled.
 */
void WaitForHwQueueWaterMark(void)
{
	uint32_t data = 0;

	/* wait for watermark signal */
	CC_HalWaitInterrupt(CC_REG_FLD_GET(HOST, HOST_IRR, DSCRPTR_WATERMARK_INT, data));
}

