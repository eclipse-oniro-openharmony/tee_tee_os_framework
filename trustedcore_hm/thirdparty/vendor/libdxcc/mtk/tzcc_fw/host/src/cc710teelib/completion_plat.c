/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */
#define SASI_PAL_LOG_CUR_COMPONENT DX_LOG_MASK_COMPLETION
#include "ssi_pal_types.h"
#include "cc_plat.h"
#include "ssi_pal_mem.h"
#include "ssi_pal_dma.h"
#include "ssi_pal_abort.h"
#include "ssi_error.h"
#include "ssi_pal_log.h"
#include "ssi_compiler.h"
#include "completion.h"
#include "hw_queue.h"
#include "ssi_hal.h"
#include "ssi_pal_perf.h"
#include "dx_host.h"
/* For Zynq7000 - AXI IDs are offseted by 8 */
#define AXIM_MON_BASE_OFFSET SASI_REG_OFFSET(CRY_KERNEL, AXIM_MON_COMP8)

/* *****************************************************************************
 *                GLOBALS
 * *************************************************************************** */
static uint8_t gCompletionFifo[MAX_NUM_HW_QUEUES][COMPLETION_FIFO_LEN] SASI_SRAM_SBSS_VARIABLE;

/* Items are inserted to head and removed from tail */
static uint32_t gCompletionFifoHead[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;
static uint32_t gCompletionFifoTail[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;
static uint32_t gAxiWriteCompleted[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;

static uint32_t gCompletionCount[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;
static CompletionType_t gCompletionCtx[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;
static uint32_t gTaskId[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;
static uint32_t gExpectedAxiWrites[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;

/* dummy completion buffer for last DLLI descriptor */
typedef struct {
    SaSiVirtAddr_t *pBuffVirtAddr;
    SaSiDmaAddr_t buffPhysAddr;
} DmaBuffAddress_t;

static DmaBuffAddress_t gCompletionDummyBuffer;

extern uint32_t gAxiWriteCount[MAX_NUM_HW_QUEUES] SASI_SRAM_SBSS_VARIABLE;

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
    while ((status |= (SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, DSCRPTR_COMPLETION_STATUS /* 0xe3c */)) &
                       BITMASK(MAX_COMPLETION_COUNTERS)))) {
        /* Loop will start at highest prioirty */
        qid = (qid + 1) & (MAX_COMPLETION_COUNTERS - 1);

        if (status & BITMASK_AT(1, qid)) {
            /* Read completion counter register. Counter is cleared once we read it ! */
            gCompletionCount[qid] += SASI_HAL_READ_REGISTER(
                SASI_REG_OFFSET(CRY_KERNEL, DSCRPTR_COMPLETION_COUNTER0 /* e00 */) + qid * sizeof(uint32_t));

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
                complCntr = SASI_REG_FLD_GET(
                    CRY_KERNEL, AXIM_MON_COMP8, VALUE,
                    SASI_HAL_READ_REGISTER(AXIM_MON_BASE_OFFSET /* b80 */ + QID_TO_AXI_ID(qid) * sizeof(uint32_t)));
            } while (complCntr < 1);
            if (complCntr != 1) {
                SaSi_PalAbort("AXI completion counter incorrect.");
            }

            axi_err = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(CRY_KERNEL, AXIM_MON_ERR));
            if (axi_err) {
                SaSi_PalAbort("AXI monitor error.");
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
    int qid                    = CURR_QUEUE_ID();
    uint32_t taskId            = CURR_TASK_ID();
    uint32_t data              = 0;
    SaSi_PalPerfData_t perfIdx = 0;

    /* Acknowledge completion to host */
    AddLastCompletionDesc(qid, taskId, (void *)COMPLETION_EXTERNAL);

    // set the data to wait only for decriptor completion mask interrupt
    SASI_REG_FLD_SET(HOST_RGF, HOST_IRR, DSCRPTR_COMPLETION_LOW_INT, data, 1);

    SASI_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);
    SaSi_HalWaitInterrupt(data);

    SASI_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);

    CompletionDescHandler();

    SASI_PAL_LOG_INFO("Sequence completed\n");
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

        SaSi_PalMemSetZero(gCompletionFifo, MAX_NUM_HW_QUEUES * COMPLETION_FIFO_LEN);

        /* Clear all past AXI completion counters */
        /* Actual bus values of AXI IDs for queues (0-3) DMA are 8, 9, A, B */
        dummy = SASI_HAL_READ_REGISTER(AXIM_MON_BASE_OFFSET + QID_TO_AXI_ID(qid) * sizeof(uint32_t));
        SASI_PAL_LOG_DEBUG("Initial AXI_MON_COMP%d value=0x%08X\n", (int)qid, (unsigned int)dummy);
        dummy = dummy; /* avoid compiler warning */
    }

    return SASI_RET_OK;
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
        SaSi_PalAbort("Bad completionType");
    }
    if (taskId >= BITMASK(FIFO_TASK_ID_BIT_SIZE)) {
        SaSi_PalAbort("Bad completionTaskId");
    }
    if (axiWriteCount >= BITMASK(FIFO_AXI_COUNTER_BIT_SIZE)) {
        SaSi_PalAbort("Bad axiWriteCount");
    }
    if ((gCompletionFifoHead[qid] - gCompletionFifoTail[qid]) >= COMPLETION_FIFO_LEN) {
        SaSi_PalAbort("Completion FIFO overflow");
    }

    SET_FIFO_COMPLETION_TYPE(fifoItem, (CompletionType_t)completionType);
    SET_FIFO_AXI_COUNTER(fifoItem, axiWriteCount);
    SET_FIFO_COMPLETION_TASK_ID(fifoItem, taskId);
    fifoIdx                       = gCompletionFifoHead[qid] & (COMPLETION_FIFO_LEN - 1);
    gCompletionFifo[qid][fifoIdx] = fifoItem;

    gCompletionFifoHead[qid]++;

    SASI_PAL_LOG_DEBUG("qid=%d taskId=%d fifoIdx=%d gCompletionFifoHead[qid]=%d completionType=%s axiWriteCount=%d\n",
                       (int)qid, (int)taskId, (int)fifoIdx, (int)gCompletionFifoHead[qid],
                       ((CompletionType_t)completionType == COMPLETION_INTERNAL) ? "INTERNAL" : "EXTERNAL",
                       (int)axiWriteCount);
#ifdef ARM_DSM
    SaSi_PalDsmWorkarround();
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
        SaSi_PalAbort("Completion FIFO empty");
    }

    fifoIdx  = gCompletionFifoTail[qid] & (COMPLETION_FIFO_LEN - 1);
    fifoItem = gCompletionFifo[qid][fifoIdx];

    *completionType = GET_FIFO_COMPLETION_TYPE(fifoItem);
    *axiWriteCount  = GET_FIFO_AXI_COUNTER(fifoItem);
    *taskId         = GET_FIFO_COMPLETION_TASK_ID(fifoItem);

    /* Note: we focibly comment out these lines since in CC54 project the FIFO mechanism runs from interrupt service
     * routine while in other projects it runs from a task. Enabling this print will cause the CC54 SeP to stack in
     * debug mode. */
    // SASI_PAL_LOG_DEBUG("qid=%d taskId=%d fifoIdx=%d gCompletionFifoTail[qid]=%d completionType=%s
    // axiWriteCount=%d\n",
    //    (int)qid, (int)*taskId, (int)fifoIdx, (int)gCompletionFifoTail[qid],
    //    (*completionType==COMPLETION_INTERNAL)?"INTERNAL":"EXTERNAL", (int)*axiWriteCount);

    gCompletionFifoTail[qid]++;

    if ((*completionType != COMPLETION_INTERNAL) && (*completionType != COMPLETION_EXTERNAL)) {
        SaSi_PalAbort("Bad completionType");
    }
    if (*taskId >= BITMASK(FIFO_TASK_ID_BIT_SIZE)) {
        SaSi_PalAbort("Bad completionTaskId");
    }
    if (*axiWriteCount >= BITMASK(FIFO_AXI_COUNTER_BIT_SIZE)) {
        SaSi_PalAbort("Bad axiWriteCount");
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
    error = SaSi_PalDmaContigBufferAllocate(sizeof(uint32_t), (uint8_t **)&(gCompletionDummyBuffer.pBuffVirtAddr));
    if (!error) {
        /* gets the buffer physical address for HW transactions */
        gCompletionDummyBuffer.buffPhysAddr =
            SaSi_PalMapVirtualToPhysical((uint8_t *)gCompletionDummyBuffer.pBuffVirtAddr);
    }
    return error;
}

/* !
 * This function free resources previuosly allocated by AllocCompletionPlatBuffer.
 */
void FreeCompletionPlatBuffer(void)
{
    SaSi_PalDmaContigBufferFree(sizeof(uint32_t), (uint8_t *)gCompletionDummyBuffer.pBuffVirtAddr);
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

    SASI_PAL_LOG_DEBUG("qid=%d taskId=%d\n", (int)qid, (int)taskId);

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
