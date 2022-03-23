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

#ifndef  _HW_QUEUE_H
#define  _HW_QUEUE_H

#include "hw_queue_plat.h"
#include "completion_plat.h"
#include "cc_hw_queue_defs.h"
#include "hw_queue_defs_plat.h"
#include "hw_queue_plat.h"
#include "completion.h"

/* Wrapper for HW_QUEUE_POLL_QUEUE_UNTIL_EMPTY() to allow fallback to blocking
   with WaitForSequenceCompletion after polling for some time.
   This helps avoiding hw queue getting stuck in case of a context switch when
   lock bit is on. This is relevant only for multi-task environments (i.e.,
   when openrtos is running) */
#define HW_QUEUE_POLL_TIMEOUT (30)
#define HW_QUEUE_WAIT_UNTIL_EMPTY() \
	while (!HW_QUEUE_POLL_QUEUE_UNTIL_EMPTY(HW_QUEUE_POLL_TIMEOUT)) {      \
		/* Not empty after polling for a while -                       \
		   go for blocking to allow context switch */                  \
		WaitForSequenceCompletion();                                   \
	}

/*
 Locks HW queue sequencer.
 This API must use in platforms that should avoid
 descriptors sequence interleaving.
*/
#define HW_QUEUE_LOCK() _HW_QUEUE_LOCK()

/*
 Unlocks HW queue sequencer.
 This API must use in platforms that should avoid
 descriptors sequence interleaving.
*/
#define HW_QUEUE_UNLOCK() _HW_QUEUE_UNLOCK()

/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/

/*!
 * This function initializes a HW queue, sets up the watermark event and
 * the mutex related to that queue.
 *
 * \return int one of the error codes defined in err.h
 */
int InitHWQueue(void);

/*!
 * This function adds a HW descriptor sequence to a HW queue. If not
 * enough free slot are available in the HW queue, the function will set
 * up the "Water Mark" register and wait on an event until free slots are
 * available.
 *
 * \param descSeq A pointer to a HW descriptor sequence. All descriptor
 *		      structures are 6 words.
 *		      The sequence buffer is a group of word aligned sequential
 *		      descriptor buffers.
 */
void AddHWDescSequence(HwDesc_s* descSeq);


#endif /*FW_HW_QUEUE_H*/

