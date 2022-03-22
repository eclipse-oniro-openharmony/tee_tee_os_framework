/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef SEP_MLLI_H
#define SEP_MLLI_H

#include "cc_plat.h"
#include "dx_lli_defs.h"
#include "compiler.h"
#include "hw_queue_defs.h"

/* *****************************************************************************
 *                DEFINITIONS
 * *************************************************************************** */

#define MLLI_BUF_SIZE                 (FW_MLLI_TABLE_LEN * LLI_ENTRY_BYTE_SIZE)
#define MLLI_BUF_SIZE_IN_WORDS        (FW_MLLI_TABLE_LEN * LLI_ENTRY_WORD_SIZE)
#define MLLI_IN_OUT_BUF_SIZE          (2 * MLLI_BUF_SIZE)
#define MLLI_IN_OUT_BUF_SIZE_IN_WORDS (2 * MLLI_BUF_SIZE_IN_WORDS)

/* *****************************************************************************
 *                TYPE DEFINITIONS
 * *************************************************************************** */

typedef enum MLLIDirection {
    MLLI_INPUT_TABLE,
    MLLI_OUTPUT_TABLE,
    MLLI_OPTIONS,
    MLLI_END = INT32_MAX,
} MLLIDirection_t;

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * This function allocates IN/OUT MLLI tables in SRAM and appends the
 * "Last LLI" marker to the end of the IN/OUT tables. Each MLLI table size
 * is 1K + 8 bytes of the "last LLI" entry.
 *
 * \param none
 *
 * \return one of the error codes defined in err.h
 */
void InitMlli(void) DX_ICACHE_FUNCTION;

/* !
 * Rerturns the max. size of single MLLI buffer.
 *
 * \return uint32_t The size of MLLI buffer in bytes.
 */
uint32_t GetMlliBufferSize(void);

/* !
 * This function allocates the MLLI workspace for use by an external module.
 * Once the workspace is allocated, it can not be used by the MLLI module.
 * Once freed, the MLLI module can use it once more after setting the stop
 * entries in each table.
 *
 * \param qid [IN] - Queue ID
 *        pBuf [OUT] - Pointer to the returned allocated buffer pointer
 *       bufSize [OUT] - Pointer to the returned buffer size
 *
 * \return none
 */
void AllocateMlliBuffers(int qid, uint32_t **pBuf, uint32_t *bufSize);

/* !
 * This function frees the MLLI workspace used by the external module.
 * Once the buffers are allocated, they can not be used by the MLLI module.
 * Once freed, MLLI modules can use them once more after setting the stop
 * entries in each table.
 *
 * \param qid [IN] - Queue ID
 *
 * \return none
 */
void FreeMlliBuffers(int qid);

/* !
 * This function retrieves the pointer to the first LLI entry in the MLLI
 * table which resides in SRAM. The first LLI will always be located after
 * the link entry to the next MLLI table.
 *
 * \param qid [in] -The queue Id.
 * \param dir [in] -indicates MLLI_INPUT_TABLE or MLLI_OUTPUT_TABLE
 *
 * \return A pointer to the first LLI entry in the MLLI table
 */
DxSramAddr_t GetFirstLliPtr(int qid, MLLIDirection_t dir);

/* !
 * This function initiates reading of MLLI table in given host memory to
 * the MLLI buffer in SRAM. It pushes DLLI-to-SRAM BYPASS descriptor.
 *
 * \param qid [in] -The queue Id.
 * \param mlliHostAddr [in] - Host DMA address of a structure which represents the
 *            MLLI table as follow:
 *             1. A pointer to the first input MLLI table in system RAM
 *                 and it's size.
 *             2. The total number of MLLI tables.
 *             3. The table direction (can be either MLLI_INPUT_TABLE or
 *                 MLLI_OUTPUT_TABLE).
 * \param tableSize The size in bytes of the pointed MLLI table.
 * \param axiNs The AXI NS bit
 * \param direction Denotes whether this is MLLI for input or for output
 */
void PrepareMLLITable(int qid, DxDmaAddr_t pMlliData, uint32_t size, uint8_t axiNs, MLLIDirection_t direction);

/* !
 * This function checks if MLLI buffer was allocated for external use.
 *
 * \param qid [IN] - Queue ID
 *
 * \return none
 */
uint8_t IsMlliAllocatedExternally(int qid);

#endif /* SEP_MLLI_H */
