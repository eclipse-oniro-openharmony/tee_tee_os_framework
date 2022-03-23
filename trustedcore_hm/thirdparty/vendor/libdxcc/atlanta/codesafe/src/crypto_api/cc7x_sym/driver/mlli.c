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
#include "mlli_plat.h"


/******************************************************************************
*				GLOBALS
******************************************************************************/


/******************************************************************************
*			FUNCTIONS DECLARATIONS
******************************************************************************/


/******************************************************************************
*				FUNCTIONS
******************************************************************************/


/*!
 * This function retrieves the pointer to the first LLI entry in the MLLI
 * table which resides in SRAM. The first LLI will always be located after
 * the link entry to the next MLLI table.
 *
 * \param dir [in] -indicates MLLI_INPUT_TABLE or MLLI_OUTPUT_TABLE
 *
 * \return A pointer to the first LLI entry in the MLLI table
 */
CCSramAddr_t GetFirstLliPtr(MLLIDirection_t direction)
{
	CCSramAddr_t buffOfs;

	buffOfs = DX_GetMLLIWorkspace();

	/* Set offset to input or output table */
	buffOfs += ((direction == MLLI_INPUT_TABLE) ? 0 : MLLI_BUF_SIZE);

	return buffOfs;
}

/*!
 * This function initiates reading of MLLI table in given host memory to
 * the MLLI buffer in SRAM. It pushes DLLI-to-SRAM BYPASS descriptor.
 *
 * \param mlliHostAddr [in] - Host DMA address of a structure which represents the
 *			MLLI table as follow:
 *		     1. A pointer to the first input MLLI table in system RAM
 *		     	and it's size.
 *		     2. The total number of MLLI tables.
 *		     3. The table direction (can be either MLLI_INPUT_TABLE or
 *		     	MLLI_OUTPUT_TABLE).
 * \param tableSize The size in bytes of the pointed MLLI table.
 * \param axiNs The AXI NS bit
 * \param direction Denotes whether this is MLLI for input or for output
*/
void PrepareMLLITable(CCDmaAddr_t pMlliData, uint32_t size, uint8_t axiNs, MLLIDirection_t direction)
{
	CCSramAddr_t mlliAdr;
	HwDesc_s desc;

	/* Check if already allocated by external module */
	if ( DX_GetIsMlliExternalAlloc() == 1 ) {
		CC_PalAbort("MLLI workspace is already allocated by external module");
	}

	if (size > (MLLI_BUF_SIZE - LLI_ENTRY_BYTE_SIZE)) {
		CC_PAL_LOG_ERR("Given MLLI size=%u B is too large!\n", (unsigned int)size);
		CC_PalAbort("Given MLLI size is too large!");
	}

	mlliAdr = DX_GetMLLIWorkspace();
	mlliAdr += ( (direction == MLLI_INPUT_TABLE) ? 0 : MLLI_BUF_SIZE );

	/* prepare the first MLLI mlliTable from host */
	HW_DESC_INIT(&desc);
	HW_DESC_SET_DIN_TYPE(&desc, DMA_DLLI, pMlliData, size, axiNs);
	HW_DESC_SET_DOUT_SRAM(&desc, mlliAdr, size);
	HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
	AddHWDescSequence(&desc);
}

