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

#ifndef  HW_QUEUE_PLAT_H
#define  HW_QUEUE_PLAT_H

#include "cc_hal.h"


/******************************************************************************
*				MACROS
******************************************************************************/
#define DEFAULT_AXI_ID 0 				/* Virtual Host */
#define DEFALUT_AXI_SECURITY_MODE AXI_SECURE		/* NS bit */
#define HW_DESC_STATE_LOCATION DMA_BUF_DLLI



/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/


/*!
 * Waits until the HW queue Water Mark is signaled.
 */
void WaitForHwQueueWaterMark(void);


/*!
 * This function sets the DIN field of a HW descriptors to DLLI mode.
 * The AXI and NS bits are set, hard coded to zero. this asiengment is
 * for TEE only. for PEE TBD to set the AXI and NS bits to 1.
 *
 *
 * \param pDesc pointer HW descriptor struct
 * \param dinAdr DIN address
 * \param dinSize Data size in bytes
 */
#define HW_DESC_SET_STATE_DIN_PARAM(pDesc, dinAdr, dinSize)				\
	do {		                                                       	\
		HW_DESC_SET_DIN_SRAM(pDesc, dinAdr, dinSize);			\
	} while (0)
#define HW_DESC_SET_STATE_DOUT_PARAM(pDesc, doutAdr, doutSize)				\
	do {		                                                               	\
		HW_DESC_SET_DOUT_SRAM(pDesc, doutAdr, doutSize);			\
	} while (0)

/* No HW queue sequencer is needed */
#define _HW_QUEUE_LOCK()
#define _HW_QUEUE_UNLOCK()


#endif /*HW_QUEUE_PLAT_H*/
