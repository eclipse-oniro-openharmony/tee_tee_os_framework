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

#include "completion.h"
#include "cc_hw_queue_defs.h"
#include "hw_queue.h"
#include "cc_sym_error.h"
#include "cc_pal_log.h"
#include "cc_pal_abort.h"


/******************************************************************************
*				GLOBALS
******************************************************************************/

/******************************************************************************
*				FUNCTIONS
******************************************************************************/

int InitHWQueue(void)
{
	return CC_RET_OK;
}

/*!
 * This function adds a HW descriptor sequence to a HW queue. If not
 * enough free slot are available in the HW queue, the function will set
 * up the "Water Mark" register and wait on an event until free slots are
 * available. This function will always mark the last descriptor in the
 * sequence as "last", even if the "last" bit was left clear. The caller
 * can leave the "Ack needed" field un-initialized. This function will
 * set the "Ack needed" field in each descriptor to either zero or to the
 * CounterId for the last descriptor.
 * The caller can indirectly control whether the function will block until
 * the descriptor is complete or return without blocking for asynchronous
 * mode. This is done by referring to a completion counter ID that is
 * defined as "external completion" or "internal completion".
 *
 * \param descSeq A pointer to a HW descriptor sequence. All descriptor
 *		      structures are 5 words long according to [CC54-DESC].
 *		      The sequence buffer is a group of word aligned sequential
 *		      descriptor buffers.
 */
void AddHWDescSequence(HwDesc_s* descSeq)
{

	HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(1);

	/* Push to HW queue */
	HW_DESC_PUSH_TO_QUEUE(descSeq);
}


