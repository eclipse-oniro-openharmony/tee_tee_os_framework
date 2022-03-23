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

#ifndef  _MLLI_H
#define  _MLLI_H

#include "cc_plat.h"
#include "cc_lli_defs.h"
#include "cc_hw_queue_defs.h"

/******************************************************************************
*				DEFINITIONS
******************************************************************************/

#define MLLI_BUF_SIZE			(FW_MLLI_TABLE_LEN * LLI_ENTRY_BYTE_SIZE)
#define MLLI_BUF_SIZE_IN_WORDS		(FW_MLLI_TABLE_LEN * LLI_ENTRY_WORD_SIZE)
#define MLLI_IN_OUT_BUF_SIZE 		(2 * MLLI_BUF_SIZE)
#define MLLI_IN_OUT_BUF_SIZE_IN_WORDS 	(2 * MLLI_BUF_SIZE_IN_WORDS)

/******************************************************************************
*				TYPE DEFINITIONS
******************************************************************************/

typedef enum MLLIDirection {
	MLLI_INPUT_TABLE,
	MLLI_OUTPUT_TABLE,
	MLLI_OPTIONS,
	MLLI_END = INT32_MAX,
}MLLIDirection_t;

/******************************************************************************
*				FUNCTION PROTOTYPES
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
void InitMlli(void);

/*!
 * Rerturns the max. size of single MLLI buffer.
 *
 * \return uint32_t The size of MLLI buffer in bytes.
 */
uint32_t GetMlliBufferSize(void);


/*!
 * This function retrieves the pointer to the first LLI entry in the MLLI
 * table which resides in SRAM. The first LLI will always be located after
 * the link entry to the next MLLI table.
 *
 * \param dir [in] -indicates MLLI_INPUT_TABLE or MLLI_OUTPUT_TABLE
 *
 * \return A pointer to the first LLI entry in the MLLI table
 */
CCSramAddr_t GetFirstLliPtr(MLLIDirection_t dir);

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
void PrepareMLLITable(CCDmaAddr_t pMlliData, uint32_t size, uint8_t axiNs, MLLIDirection_t direction);


#endif /*_MLLI_H*/


