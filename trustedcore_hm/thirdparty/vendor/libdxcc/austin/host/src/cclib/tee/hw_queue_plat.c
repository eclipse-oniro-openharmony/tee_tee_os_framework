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
#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_HW_QUEUE

#include "dx_pal_types.h"
#include "dx_pal_log.h"
#include "hw_queue_defs.h"
#include "hw_queue_plat.h"
#include "dx_error.h"
#include "dx_hal.h"

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* Counts all AXI write descriptor (with LAST bit set) since last completion request */
uint32_t gAxiWriteCount[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;

/* !
 * HW queue init.
 *
 * \param qid Should always be "0".
 *
 * \return int
 */
int InitHwQueuePlat(int qid)
{
    if (qid != NO_OS_QUEUE_ID) {
        return DX_RET_INVARG_QID;
    }
    return DX_RET_OK;
}

/* !
 * Waits until the HW queue Water Mark is signaled.
 */
void WaitForHwQueueWaterMark(void)
{
    uint32_t data = 0;

    /* wait for watermark signal */
    DX_HAL_WaitInterrupt(DX_CC_REG_FLD_GET(HOST, HOST_IRR, DSCRPTR_WATERMARK_INT, data));
}
