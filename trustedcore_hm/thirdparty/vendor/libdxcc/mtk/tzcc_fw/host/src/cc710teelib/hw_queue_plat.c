/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */
#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_HW_QUEUE

#include "ssi_pal_types.h"
#include "ssi_pal_log.h"
#include "hw_queue_defs.h"
#include "hw_queue_plat.h"
#include "ssi_error.h"
#include "ssi_hal.h"

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* Counts all AXI write descriptor (with LAST bit set) since last completion request */
uint32_t gAxiWriteCount[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;

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
        return SASI_RET_INVARG_QID;
    }
    return SASI_RET_OK;
}

/* !
 * Waits until the HW queue Water Mark is signaled.
 */
void WaitForHwQueueWaterMark(void)
{
    uint32_t data = 0;

    /* wait for watermark signal */
    SaSi_HalWaitInterrupt(SASI_REG_FLD_GET(HOST, HOST_IRR, DSCRPTR_WATERMARK_INT, data));
}
