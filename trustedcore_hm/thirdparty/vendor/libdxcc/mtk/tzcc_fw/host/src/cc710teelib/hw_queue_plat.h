/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef HW_QUEUE_PLAT_H
#define HW_QUEUE_PLAT_H

#include "ssi_compiler.h"
#include "ssi_hal.h"

/* *****************************************************************************
 *                MACROS
 * *************************************************************************** */
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
int InitHwQueuePlat(int qid) SASI_ICACHE_FUNCTION;

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
#define HW_DESC_SET_SPECIAL_DIN_PARAM(pDesc, dinAdr, dinSize)                                                      \
    do {                                                                                                           \
        /* use QUEUE0 since the offsets in each QUEUE does not depend on the QID */                                \
        SASI_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD0, VALUE, (pDesc)->word[0], ((uint32_t)(dinAdr)));         \
        SASI_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_DMA_MODE, (pDesc)->word[1], NO_DMA);                \
        SASI_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_SIZE, (pDesc)->word[1], (dinSize));                 \
        SASI_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, DIN_VIRTUAL_HOST, (pDesc)->word[1], (DEFAULT_AXI_ID));  \
        SASI_REG_FLD_SET(CRY_KERNEL, DSCRPTR_QUEUE0_WORD1, NS_BIT, (pDesc)->word[1], (DEFALUT_AXI_SECURITY_MODE)); \
    } while (0)

#endif /* HW_QUEUE_PLAT_H */
