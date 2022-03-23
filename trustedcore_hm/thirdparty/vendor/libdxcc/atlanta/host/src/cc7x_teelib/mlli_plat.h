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

#ifndef  MLLI_PLAT_H
#define  MLLI_PLAT_H

#include "cc_lli_defs.h"
#include "cc_hw_queue_defs.h"

/******************************************************************************
*				DEFINITIONS
******************************************************************************/


/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/

#define DX_GetIsMlliExternalAlloc() 0
/******************************************************************************
*				FUNCTION PROTOTYPES
******************************************************************************/


/*!
 * Rerturns the head of the MLLI buffer.
 *
 * \return dx_sram_addr_t.
 */
CCSramAddr_t DX_GetMLLIWorkspace(void);



#endif /*MLLI_PLAT_H*/


