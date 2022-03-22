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

#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_MLLI

#include "cc_pal_types.h"
#include "cc_pal_mem.h"
#include "cc_pal_abort.h"
#include "cc_plat.h"
#include "completion.h"
#include "hw_queue.h"
#include "mlli.h"
#include "cc_sram_map.h"


/******************************************************************************
*				GLOBALS
******************************************************************************/

/* SRAM workspace buffer for input and output MLLI tables per queue */
static CCSramAddr_t gMlliWorkspace = CC_SRAM_MLLI_BASE_ADDR;

static void SetMlliStopEntry(void);

/******************************************************************************
*			FUNCTIONS DECLARATIONS
******************************************************************************/


/******************************************************************************
*				FUNCTIONS
******************************************************************************/

/*!
 * This function allocates IN/OUT MLLI tables in SRAM and appends the
 * "Last LLI" marker to the end of the IN/OUT tables. Each MLLI table size
 * is 1K + 8 bytes of the "last LLI" entry.
 *
 * \param none
 *
 * \return one of the error codes defined in err.h
 */
void InitMlli()
{
	CC_PAL_LOG_INFO("Clear MLLI workspace at adr=0x%08X size=0x%08X\n",
		(unsigned int)gMlliWorkspace, (unsigned int)(MLLI_IN_OUT_BUF_SIZE));

	/* clear MLLI tables memory */
	_ClearSram(gMlliWorkspace, (MLLI_IN_OUT_BUF_SIZE));
	SetMlliStopEntry();

}


static void SetMlliStopEntry(void)
{
	CCSramAddr_t buffOfs = gMlliWorkspace;
	uint8_t	i;

	/* Buffer offset to first entry in input table */
	buffOfs += MLLI_IN_OUT_BUF_SIZE;

	/* Buffer offset to last entry in input table */
	buffOfs += (MLLI_IN_OUT_BUF_SIZE - LLI_ENTRY_BYTE_SIZE);

	/* Set stop entry in last position of every MLLI table. */
	/* We have two tables (IN/OUT) per queue */
	for ( i=0; i<2; i++ ) {
		CC_PAL_LOG_INFO("Set stop entry at adr=0x%08X\n", (unsigned int)buffOfs);

		_WriteWordsToSram(buffOfs, 0x80000000, sizeof(uint32_t));
		/* Set offset to next table */
		buffOfs += MLLI_BUF_SIZE;
	}
}

CCSramAddr_t DX_GetMLLIWorkspace(void)
{
	return gMlliWorkspace;
}

