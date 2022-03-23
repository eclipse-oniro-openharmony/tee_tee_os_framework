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

#ifndef HW_QUEUE_PLAT_H
#define HW_QUEUE_PLAT_H

#include "compiler.h"
#include "dx_hal.h"

/* *****************************************************************************
 *                MACROS
 * *************************************************************************** */
/* PLAT CC44 */
#define DEFAULT_AXI_ID            0          /* Virtual Host */
#define DEFALUT_AXI_SECURITY_MODE AXI_SECURE /* NS bit */
#define HW_DESC_STATE_LOCATION    DMA_BUF_DLLI

/* *****************************************************************************
 *                FUNCTION PROTOTYPES
 * *************************************************************************** */

/* !
 * This function initializes the HW queue water mark semaphore event.
 *
 * \param qid The hw queue ID.
 *
 * \return int one of the error codes defined in err.h
 */
int InitHwQueuePlat(int qid) DX_ICACHE_FUNCTION;

/* !
 * Waits until the HW queue Water Mark is signaled.
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 */
void WaitForHwQueueWaterMark(void);

/* !
 * This function sets the DIN field of a HW descriptors to DLLI mode.
 * The AXI and NS bits are set, hard coded to zero. this asiengment is
 * for TEE only. for PEE TBD to set the AXI and NS bits to 1.
 *
 *
 * \param pDesc pointer HW descriptor struct
 * \param dinAdr DIN address
 * \param dinSize Data size in bytes
 */
#define HW_DESC_SET_STATE_DIN_PARAM(pDesc, dinAdr, dinSize) \
    do {                                                    \
        HW_DESC_SET_DIN_SRAM(pDesc, dinAdr, dinSize);       \
    } while (0)
#define HW_DESC_SET_STATE_DOUT_PARAM(pDesc, doutAdr, doutSize) \
    do {                                                       \
        HW_DESC_SET_DOUT_SRAM(pDesc, doutAdr, doutSize);       \
    } while (0)

/* No HW queue sequencer is needed */
#define _HW_QUEUE_LOCK()
#define _HW_QUEUE_UNLOCK()

/* !
 * This function sets the DIN field of a HW descriptors to DLLI mode.
 * The AXI and NS bits are set, hard coded to zero. this asiengment is
 * for TEE only. for PEE TBD to set the AXI and NS bits to 1.
 *
 *
 * \param pDesc pointer HW descriptor struct
 * \param dinAdr DIN address
 * \param dinSize Data size in bytes
 */
#define HW_DESC_SET_SPECIAL_DIN_PARAM(pDesc, dinAdr, dinSize)                                                       \
    do {                                                                                                            \
        /* use QUEUE0 since the offsets in each QUEUE does not depend on the QID */                                 \
        DX_CC_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD0, VALUE, (pDesc)->word[0], ((uint32_t)(dinAdr)));         \
        DX_CC_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_DMA_MODE, (pDesc)->word[1], NO_DMA);                \
        DX_CC_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_SIZE, (pDesc)->word[1], (dinSize));                 \
        DX_CC_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_VIRTUAL_HOST, (pDesc)->word[1], (DEFAULT_AXI_ID));  \
        DX_CC_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, NS_BIT, (pDesc)->word[1], (DEFALUT_AXI_SECURITY_MODE)); \
    } while (0)

#endif /* HW_QUEUE_PLAT_H */
