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

#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_MLLI

#include "dx_pal_types.h"
#include "dx_pal_mem.h"
#include "dx_pal_abort.h"
#include "cc_plat.h"
#include "completion.h"
#include "hw_queue.h"
#include "mlli.h"
#include "mlli_plat.h"

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */

/* *****************************************************************************
 *            FUNCTIONS DECLARATIONS
 * *************************************************************************** */

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

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
DxSramAddr_t GetFirstLliPtr(int qid, MLLIDirection_t direction)
{
    DxSramAddr_t buffOfs;

    DX_PAL_LOG_INFO("qid=%d\n", (int)qid);

    buffOfs = (DX_GetMLLIWorkspace() + qid * MLLI_IN_OUT_BUF_SIZE);

    /* Set offset to input or output table */
    buffOfs += ((direction == MLLI_INPUT_TABLE) ? 0 : MLLI_BUF_SIZE);

    return buffOfs;
}

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
void PrepareMLLITable(int qid, DxDmaAddr_t pMlliData, uint32_t size, uint8_t axiNs, MLLIDirection_t direction)
{
    DxSramAddr_t mlliAdr;
    HwDesc_s desc;

    /* Check if already allocated by external module */
    if (DX_GetIsMlliExternalAlloc(qid) == 1) {
        DX_PAL_Abort("MLLI workspace is already allocated by external module");
    }

    /* Advised by ARM CC supporter, change limit to 1024B to compatible with unaligned 500KB buffer */
    if (size > (MLLI_BUF_SIZE - LLI_ENTRY_BYTE_SIZE)) {
        DX_PAL_LOG_ERR("Given MLLI size=%u B is too large!\n", (unsigned int)size);
        if (size > MLLI_BUF_SIZE) {
            DX_PAL_Abort("Given MLLI size is too large!");
        }
    }

    mlliAdr = DX_GetMLLIWorkspace() + qid * MLLI_IN_OUT_BUF_SIZE;
    mlliAdr += ((direction == MLLI_INPUT_TABLE) ? 0 : MLLI_BUF_SIZE);

    /* prepare the first MLLI mlliTable from host */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_TYPE(&desc, DMA_DLLI, pMlliData, size, QID_TO_AXI_ID(qid), axiNs);
    HW_DESC_SET_DOUT_SRAM(&desc, mlliAdr, size);
    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
    AddHWDescSequence(qid, &desc);
}
