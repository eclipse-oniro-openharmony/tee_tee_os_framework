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
#define DX_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_COMPLETION
#include "dx_pal_types.h"
#include "cc_plat.h"
#include "dx_pal_mem.h"
#include "dx_pal_dma.h"
#include "dx_pal_abort.h"
#include "dx_error.h"
#include "dx_pal_log.h"
#include "compiler.h"
#include "completion.h"
#include "hw_queue.h"
#include "dx_hal.h"
#include "dx_pal_perf.h"
#include "dx_host.h"

/* For Zynq7000 - AXI IDs are offseted by 8 */
#define AXIM_MON_BASE_OFFSET DX_CC_REG_OFFSET(CRY_KERNEL, AXIM_MON_COMP8)

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */
static uint8_t gCompletionFifo[MAX_NUM_HW_QUEUES][COMPLETION_FIFO_LEN] DX_SRAM_SBSS_VARIABLE;

/* Items are inserted to head and removed from tail */
static uint32_t gCompletionFifoHead[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;
static uint32_t gCompletionFifoTail[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;
static uint32_t gAxiWriteCompleted[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;

static uint32_t gCompletionCount[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;
static CompletionType_t gCompletionCtx[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;
static uint32_t gTaskId[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;
static uint32_t gExpectedAxiWrites[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;

/* dummy completion buffer for last DLLI descriptor */
typedef struct {
    DxVirtAddr_t *pBuffVirtAddr;
    DxDmaAddr_t buffPhysAddr;
} DmaBuffAddress_t;

static DmaBuffAddress_t gCompletionDummyBuffer;

extern uint32_t gAxiWriteCount[MAX_NUM_HW_QUEUES] DX_SRAM_SBSS_VARIABLE;

/* *****************************************************************************
 *            FUNCTIONS PROTOTYPES
 * *************************************************************************** */

/* The interrupt handlers are naked functions that call C handlers. The C
   handlers are marked as noinline to ensure they work correctly when the
   optimiser is on. */
static void CompletionDescHandler(void) __attribute__((noinline));

static void AddLastCompletionDesc(int qid, uint32_t taskId, void *completionCtx);

/* *****************************************************************************
 *                FUNCTIONS
 * *************************************************************************** */

static void CompletionDescHandler()
{
    uint32_t complCntr;
    int qid;
    uint32_t status, axi_err;
    status = 0;

    /* Init to lowest prioirty */
    qid = 0;

    /* Mask only one counter per queue */
    while ((status |= (DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, DSCRPTR_COMPLETION_STATUS /* 0xe3c */)) &
                       BITMASK(MAX_COMPLETION_COUNTERS)))) {
        /* Loop will start at highest prioirty */
        qid = (qid + 1) & (MAX_COMPLETION_COUNTERS - 1);

        if (status & BITMASK_AT(1, qid)) {
            /* Read completion counter register. Counter is cleared once we read it ! */
            gCompletionCount[qid] += DX_HAL_ReadCcRegister(
                DX_CC_REG_OFFSET(CRY_KERNEL, DSCRPTR_COMPLETION_COUNTER0 /* e00 */) + qid * sizeof(uint32_t));

            /* status still set, but engine completion counter was already handled */
            if (gCompletionCount[qid] == 0) {
                status = status & ~(BITMASK_AT(1, qid));
                continue;
            }

            /* Get completion info from fifo, if not already done so */
            if (gCompletionCtx[qid] == COMPLETION_INVALID) {
                CompletionFifoRemove(qid, &gTaskId[qid], &gCompletionCtx[qid], &gExpectedAxiWrites[qid]);
            }

            /* Wait for AXI completion - verify number of completed write transactions is 1 */
            do {
                complCntr = DX_CC_REG_FLD_GET(
                    CRY_KERNEL, AXIM_MON_COMP8, VALUE,
                    DX_HAL_ReadCcRegister(AXIM_MON_BASE_OFFSET /* b80 */ + QID_TO_AXI_ID(qid) * sizeof(uint32_t)));
            } while (complCntr < 1);
            if (complCntr != 1) {
                DX_PAL_Abort("AXI completion counter incorrect.");
            }

            axi_err = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, AXIM_MON_ERR));
            if (axi_err) {
                DX_PAL_Abort("AXI monitor error.");
            }

            gAxiWriteCompleted[qid] += complCntr;

            if (gAxiWriteCompleted[qid] >= gExpectedAxiWrites[qid]) {
                gAxiWriteCompleted[qid] -= gExpectedAxiWrites[qid];
                gCompletionCtx[qid] = COMPLETION_INVALID;
                gCompletionCount[qid]--;
            }

        } /* if (status & BITMASK_AT(1, qid)) */

    } /* while ( (status = ( READ_REGISTER... */
}

/* !
 * This function waits for current descriptor sequence completion.
 */
void WaitForSequenceCompletionPlat(void)
{
    int qid                   = CURR_QUEUE_ID();
    uint32_t taskId           = CURR_TASK_ID();
    uint32_t data             = 0;
    DX_PAL_PerfData_t perfIdx = 0;

    /* Acknowledge completion to host */
    AddLastCompletionDesc(qid, taskId, (void *)COMPLETION_EXTERNAL);

    // set the data to wait only for decriptor completion mask interrupt
    DX_CC_REG_FLD_SET(HOST_RGF, HOST_IRR, DSCRPTR_COMPLETION_MASK, data, 1);

    DX_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);
    DX_HAL_WaitInterrupt(data);

    DX_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);

    CompletionDescHandler();

    DX_PAL_LOG_INFO("Sequence completed\n");
}

/* !
 * This function initializes the completion counter event, clears the
 * state structure and sets completion counter "0" as the first available
 * counter to be used when calling "AllocCounter".
 *
 * \return int one of the error codes defined in err.h
 */
int InitCompletionPlat(void)
{
    uint8_t dummy;
    int qid;

    /* Clear completion fifo */
    for (qid = 0; qid < MAX_NUM_HW_QUEUES; qid++) {
        /* Clear FIFO head/tail */
        gCompletionFifoHead[qid] = 0;
        gCompletionFifoTail[qid] = 0;

        /* The global AXI write counter is reset only once */
        gAxiWriteCompleted[qid] = 0;

        gCompletionCount[qid]   = 0;
        gExpectedAxiWrites[qid] = 0;
        gCompletionCtx[qid]     = COMPLETION_INVALID;

        DX_PAL_MemSetZero(gCompletionFifo, MAX_NUM_HW_QUEUES * COMPLETION_FIFO_LEN);

        /* Clear all past AXI completion counters */
        /* Actual bus values of AXI IDs for queues (0-3) DMA are 8, 9, A, B */
        dummy = DX_HAL_ReadCcRegister(AXIM_MON_BASE_OFFSET + QID_TO_AXI_ID(qid) * sizeof(uint32_t));
        DX_PAL_LOG_DEBUG("Initial AXI_MON_COMP%d value=0x%08X\n", (int)qid, (unsigned int)dummy);
        dummy = dummy; /* avoid compiler warning */
    }

    return DX_RET_OK;
}

/* !
 * This function adds a completion report to the completion fifo.
 *
 * \param qid The queue id.
 * \param taskId Completion task ID as set by vTaskSetCurrentTaskTag().
 * \param completionType COMPLETION_INTERNAL or COMPLETION_EXTERNAL.
 * \param axiWriteCount AXI transactions counter from previous completion report.
 */
void CompletionFifoInsert(int qid, uint32_t taskId, CompletionType_t *completionType, uint32_t axiWriteCount)
{
    uint8_t fifoItem = 0;
    uint32_t fifoIdx;

    if (((CompletionType_t)completionType != COMPLETION_INTERNAL) &&
        ((CompletionType_t)completionType != COMPLETION_EXTERNAL)) {
        DX_PAL_Abort("Bad completionType");
    }
    if (taskId >= BITMASK(FIFO_TASK_ID_BIT_SIZE)) {
        DX_PAL_Abort("Bad completionTaskId");
    }
    if (axiWriteCount >= BITMASK(FIFO_AXI_COUNTER_BIT_SIZE)) {
        DX_PAL_Abort("Bad axiWriteCount");
    }
    if ((gCompletionFifoHead[qid] - gCompletionFifoTail[qid]) >= COMPLETION_FIFO_LEN) {
        DX_PAL_Abort("Completion FIFO overflow");
    }

    SET_FIFO_COMPLETION_TYPE(fifoItem, (CompletionType_t)completionType);
    SET_FIFO_AXI_COUNTER(fifoItem, axiWriteCount);
    SET_FIFO_COMPLETION_TASK_ID(fifoItem, taskId);
    fifoIdx                       = gCompletionFifoHead[qid] & (COMPLETION_FIFO_LEN - 1);
    gCompletionFifo[qid][fifoIdx] = fifoItem;

    gCompletionFifoHead[qid]++;

    DX_PAL_LOG_DEBUG("qid=%d taskId=%d fifoIdx=%d gCompletionFifoHead[qid]=%d completionType=%s axiWriteCount=%d\n",
                     (int)qid, (int)taskId, (int)fifoIdx, (int)gCompletionFifoHead[qid],
                     ((CompletionType_t)completionType == COMPLETION_INTERNAL) ? "INTERNAL" : "EXTERNAL",
                     (int)axiWriteCount);
#ifdef ARM_DSM
    DX_PAL_dsmWorkarround();
#endif
}

/* !
 * This function remove a completion report to the completion fifo.
 *
 * \param qid The queue id.
 * \param taskId Task ID to be signaled upon completion.
 * \param completionType COMPLETION_INTERNAL or COMPLETION_EXTERNAL.
 * \param axiWriteCount AXI transactions counter from previous completion report.
 */
void CompletionFifoRemove(int qid, uint32_t *taskId, CompletionType_t *completionType, uint32_t *axiWriteCount)
{
    uint8_t fifoItem = 0;
    uint32_t fifoIdx;

    /* Check for fifo empty */
    if (gCompletionFifoHead[qid] == gCompletionFifoTail[qid]) {
        DX_PAL_Abort("Completion FIFO empty");
    }

    fifoIdx  = gCompletionFifoTail[qid] & (COMPLETION_FIFO_LEN - 1);
    fifoItem = gCompletionFifo[qid][fifoIdx];

    *completionType = GET_FIFO_COMPLETION_TYPE(fifoItem);
    *axiWriteCount  = GET_FIFO_AXI_COUNTER(fifoItem);
    *taskId         = GET_FIFO_COMPLETION_TASK_ID(fifoItem);

    /* Note: we focibly comment out these lines since in CC54 project the FIFO mechanism runs from interrupt service
     * routine while in other projects it runs from a task. Enabling this print will cause the CC54 SeP to stack in
     * debug mode. */
    // DX_PAL_LOG_DEBUG("qid=%d taskId=%d fifoIdx=%d gCompletionFifoTail[qid]=%d completionType=%s axiWriteCount=%d\n",
    //    (int)qid, (int)*taskId, (int)fifoIdx, (int)gCompletionFifoTail[qid],
    //    (*completionType==COMPLETION_INTERNAL)?"INTERNAL":"EXTERNAL", (int)*axiWriteCount);

    gCompletionFifoTail[qid]++;

    if ((*completionType != COMPLETION_INTERNAL) && (*completionType != COMPLETION_EXTERNAL)) {
        DX_PAL_Abort("Bad completionType");
    }
    if (*taskId >= BITMASK(FIFO_TASK_ID_BIT_SIZE)) {
        DX_PAL_Abort("Bad completionTaskId");
    }
    if (*axiWriteCount >= BITMASK(FIFO_AXI_COUNTER_BIT_SIZE)) {
        DX_PAL_Abort("Bad axiWriteCount");
    }
}

/* !
 * This function allocates a reserved word for dummy completion descriptor.
 *
 * \return a non-zero value in case of failure
 */
int AllocCompletionPlatBuffer(void)
{
    uint32_t error;

    /* Allocates a DMA-contiguous buffer, and gets its virtual address */
    error = DX_PAL_DmaContigBufferAllocate(sizeof(uint32_t), (uint8_t **)&(gCompletionDummyBuffer.pBuffVirtAddr));
    if (!error) {
        /* gets the buffer physical address for HW transactions */
        gCompletionDummyBuffer.buffPhysAddr =
            DX_PAL_MapVirtualToPhysical((uint8_t *)gCompletionDummyBuffer.pBuffVirtAddr);
    }
    return error;
}

/* !
 * This function free resources previuosly allocated by AllocCompletionPlatBuffer.
 */
void FreeCompletionPlatBuffer(void)
{
    DX_PAL_DmaContigBufferFree(sizeof(uint32_t), (uint8_t *)gCompletionDummyBuffer.pBuffVirtAddr);
    return;
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
static void AddLastCompletionDesc(int qid, uint32_t taskId, void *completionCtx)
{
    HwDesc_s desc;

    DX_PAL_LOG_DEBUG("qid=%d taskId=%d\n", (int)qid, (int)taskId);

    HW_DESC_INIT(&desc);

    HW_DESC_SET_DIN_CONST(&desc, 0, sizeof(uint32_t));

    /* set last indication for dummy AXI completion */
    HW_DESC_SET_DOUT_DLLI(&desc, gCompletionDummyBuffer.buffPhysAddr, sizeof(uint32_t), QID_TO_AXI_ID(qid), 0, 1);

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
