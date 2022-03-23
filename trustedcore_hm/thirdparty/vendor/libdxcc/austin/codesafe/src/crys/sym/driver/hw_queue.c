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

#include "compiler.h"
#include "completion.h"
#include "hw_queue_defs.h"
#include "hw_queue.h"
#include "dx_error.h"
#include "dx_pal_log.h"
#include "dx_pal_abort.h"

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */
extern uint32_t gAxiWriteCount[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

/* !
 * This function initializes a HW queue, sets up the watermark event and
 * the mutex related to that queue.
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 *
 * \return int one of the error codes defined in err.h
 */
int InitHWQueue(void)
{
    int rc = DX_RET_OK;
    int qid;

    for (qid = 0; qid < MAX_NUM_HW_QUEUES; qid++) {
        /* initializes resources of the specific platform */
        rc = InitHwQueuePlat(qid);
        if (rc != DX_RET_OK) {
            goto EndWithErr;
        }
    }

EndWithErr:
    return rc;
}

/* !
 * This function adds a HW descriptor sequence to a HW queue. If not
 * enough free slot are available in the HW queue, the function will set
 * up the "Water Mark" register and wait on an event until free slots are
 * available. This function will always mark the last descriptor in the
 * sequence as "last", even if the "last" bit was left clear. The caller
 * can leave the "Ack needed" field un-initialized. This function will
 * set the "Ack needed" field in each descriptor to either zero or to the
 * CounterId for the last descriptor.
 * The caller can indirectly control whether the function will block until
 * the descriptor is complete or return without blocking for asynchronous
 * mode. This is done by referring to a completion counter ID that is
 * defined as "external completion" or "internal completion".
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 * \param descSeq A pointer to a HW descriptor sequence. All descriptor
 *              structures are 5 words long according to [CC54-DESC].
 *              The sequence buffer is a group of word aligned sequential
 *              descriptor buffers.
 */
void AddHWDescSequence(int qid, HwDesc_s *descSeq)
{
    HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(qid, 1);

    /* Push to HW queue */
    /* Check if dout is of AXI type */
    if (IS_HW_DESC_DOUT_TYPE_AXI(descSeq)) {
        gAxiWriteCount[qid]++;

        if (gAxiWriteCount[qid] == (1 << FIFO_AXI_COUNTER_BIT_SIZE)) {
            DX_PAL_Abort("Too many AXI dout in sequence!");
        }
    }

    HW_DESC_PUSH_TO_QUEUE(qid, descSeq);
}

/* !
 * This function adds a dummy completion HW descriptor to a HW queue in
 * order to later on signal an internal completion event.
 * The dummy HW completion descriptor is created by using the DMA bypass
 * mode with zero size DIN and DOUT data. A counter ID related to the qid is always
 * used to setup the "Ack required" field in the HW descriptor.
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 * \param taskId Task ID as set by vTaskSetCurrentTaskTag().
 * \param completionCtx Completion context contains the required information for completion (platform specific).
 */
void AddCompletionDesc(int qid, uint32_t taskId, void *completionCtx)
{
    HwDesc_s desc;

    DX_PAL_LOG_DEBUG("qid=%d taskId=%d\n", (int)qid, (int)taskId);

    HW_DESC_INIT(&desc);

    /* create NOP descriptor */
    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);

    /* set the ACK bits with the completion counter if corresponding the queue id */
    HW_DESC_SET_ACK_NEEDED(&desc, QID_TO_COMPLETION_COUNTER_ID(qid));

    /* Lock the HW queue */
    HW_QUEUE_LOCK();

    HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(qid, 1);

    /* Add sequence to completion fifo */
    /* Mark according to completion type: internal or external */
    CompletionFifoInsert(qid, taskId, completionCtx, gAxiWriteCount[qid]);

    HW_DESC_PUSH_TO_QUEUE(qid, &desc);

    /* Clear the AXI counter */
    gAxiWriteCount[qid] = 0;

    /* Unlock HW queue */
    HW_QUEUE_UNLOCK();
}

/* !
 * This function adds a set register HW descriptor to a HW queue.
 * Note: the caller must make sure that the new register value does not affect
 * the other HW queue (if exists).
 *
 * \param qid An ID of a HW queue according to the queue priority. "1" is the lowest priority.
 * \param address The register address.
 * \param value The register value.
 */
void AddSetRegisterValueDesc(int qid, uint32_t address, uint32_t value)
{
    HwDesc_s desc;

    DX_PAL_LOG_DEBUG("qid=%d, register=0x%08X, value=%d\n", (int)qid, (unsigned int)address, (int)value);

    /* create register set descriptor */
    HW_DESC_INIT(&desc);
    HW_DESC_SET_DIN_NO_DMA(&desc, address, SET_REGISTER_DESC_MARK);
    HW_DESC_SET_DOUT_NO_DMA(&desc, value, 0, 1);
    HW_DESC_SET_FLOW_MODE(&desc, BYPASS);
    AddHWDescSequence(qid, &desc);
}
