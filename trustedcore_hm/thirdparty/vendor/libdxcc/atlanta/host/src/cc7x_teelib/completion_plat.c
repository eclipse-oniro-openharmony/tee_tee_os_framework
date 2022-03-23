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
#define CC_PAL_LOG_CUR_COMPONENT CC_LOG_MASK_COMPLETION
#include "cc_pal_types.h"
#include "cc_plat.h"
#include "cc_pal_mem.h"
#include "cc_pal_dma.h"
#include "cc_pal_abort.h"
#include "cc_sym_error.h"
#include "cc_pal_log.h"
#include "completion.h"
#include "hw_queue.h"
#include "cc_hal.h"
#include "cc_pal_perf.h"
#include "dx_host.h"


/******************************************************************************
*				GLOBALS
******************************************************************************/

/* dummy completion buffer for last DLLI descriptor */
typedef struct {
	CCVirtAddr_t 		*pBuffVirtAddr;
	CCPalDmaBlockInfo_t    	dmaBlockList; //CCDmaAddr_t buffPhysAddr;
	CC_PalDmaBufferHandle   dmaBuffHandle;
}DmaBuffAddress_t;

static DmaBuffAddress_t gCompletionDummyBuffer;


/******************************************************************************
*			FUNCTIONS PROTOTYPES
******************************************************************************/

/* The interrupt handlers are naked functions that call C handlers. The C
   handlers are marked as noinline to ensure they work correctly when the
   optimiser is on. */
static void CompletionDescHandler(void)		__attribute__((noinline));

static void AddLastCompletionDesc(void);


/******************************************************************************
*				FUNCTIONS
******************************************************************************/

static void CompletionDescHandler(void)
{
	uint32_t regVal;

	/* 1. Read completion counter register (counts ack_needed). Counter is cleared once we read it ! */
	regVal =  CC_HAL_READ_REGISTER(CC_REG_OFFSET(CRY_KERNEL, DSCRPTR_COMPLETION_COUNTER) );
	if ( regVal != 1 ) {
		CC_PalAbort("CC completion counter incorrect.");
	}

	/* 2. Wait for AXI completion - verify number of completed write transactions is 1 */
	do {
		regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(CRY_KERNEL,AXIM_MON_COMP));
	} while (regVal < 1);
	if (regVal!=1) {
		CC_PalAbort("AXI completion counter incorrect.");
	}

	/* 3. Check for AXIM errors */
	regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(CRY_KERNEL,AXIM_MON_ERR));
	if (regVal) {
		CC_PalAbort("AXI monitor error.");
	}

}

/*!
 * This function waits for current descriptor sequence completion.
 */
void WaitForSequenceCompletionPlat(void)
{
	uint32_t data = 0;
	CCPalPerfData_t perfIdx = 0;

	/* Acknowledge completion to host */
	AddLastCompletionDesc();

	/* Set the data to wait only for decriptor completion mask interrupt */
	CC_REG_FLD_SET(HOST_RGF, HOST_IRR, DSCRPTR_COMPLETION_INT, data, 1);

	CC_PAL_PERF_OPEN_NEW_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);
	CC_HalWaitInterrupt(data);
	CC_PAL_PERF_CLOSE_ENTRY(perfIdx, PERF_TEST_TYPE_HW_CMPLT);

	/* Call interrupt handler */
	CompletionDescHandler();

	CC_PAL_LOG_INFO("Sequence completed\n");
}

/*!
 * This function initializes the completion counter event and the AXI MON completion .
 *
 */
void InitCompletionPlat(void)
{
	uint32_t regVal=0;

	/* Clear on read AXIM_MON_COMP (counts last_ind) */
	regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(CRY_KERNEL,AXIM_MON_COMP));

	/* Clear on read COMPLETION_COUNTER (counts ack_needed) */
	regVal =  CC_HAL_READ_REGISTER(CC_REG_OFFSET(CRY_KERNEL, DSCRPTR_COMPLETION_COUNTER) );

	/* Set the data to wait only for decriptor completion mask interrupt */
	regVal=0;
	CC_REG_FLD_SET(HOST_RGF, HOST_ICR, DSCRPTR_COMPLETION, regVal, 1);
	CC_HalClearInterrupt(regVal);

	return;
}


/*!
 * This function allocates a reserved word for dummy completion descriptor.
 *
 * \return a non-zero value in case of failure
 */
int AllocCompletionPlatBuffer(void)
{
	uint32_t error;
	uint32_t   numOfBlocks = 1;

	/* Allocates a DMA-contiguous buffer, and gets its virtual address */
	error = CC_PalDmaContigBufferAllocate(sizeof(uint32_t), (uint8_t **)&(gCompletionDummyBuffer.pBuffVirtAddr));
	if (error != 0) {
		return error;
	}
	/* Map the dummy buffer - no need to sync data between transactions */
	error = CC_PalDmaBufferMap((uint8_t *)gCompletionDummyBuffer.pBuffVirtAddr,
			     sizeof(uint32_t),
			     CC_PAL_DMA_DIR_BI_DIRECTION,
			     &numOfBlocks,
			     &gCompletionDummyBuffer.dmaBlockList,
			     &gCompletionDummyBuffer.dmaBuffHandle);
	return error;
}


/*!
 * This function free resources previuosly allocated by AllocCompletionPlatBuffer.
 */
void FreeCompletionPlatBuffer(void)
{
	uint32_t   numOfBlocks = 1;
	/* Unap the dummy buffer - no need to sync data between transactions */
	CC_PalDmaBufferUnmap((uint8_t *)gCompletionDummyBuffer.pBuffVirtAddr,
			     sizeof(uint32_t),
			     CC_PAL_DMA_DIR_BI_DIRECTION,
			     numOfBlocks,
			     &gCompletionDummyBuffer.dmaBlockList,
			     gCompletionDummyBuffer.dmaBuffHandle);
	CC_PalDmaContigBufferFree(sizeof(uint32_t), (uint8_t *)gCompletionDummyBuffer.pBuffVirtAddr);
	return;
}


/*!
 * This function adds a dummy completion HW descriptor to a HW queue in
 * order to later on signal an internal completion event.
 * The dummy HW completion descriptor is created by using the DMA bypass
 * mode with zero size DIN and DOUT data. A counter ID is always
 * used to setup the "Ack required" field in the HW descriptor.
 *
 */
static void AddLastCompletionDesc(void)
{
	HwDesc_s desc;

	HW_DESC_INIT(&desc);

	HW_DESC_SET_DIN_CONST(&desc, 0, sizeof(uint32_t));

	/* set last indication for dummy AXI completion */
	HW_DESC_SET_DOUT_DLLI(&desc, gCompletionDummyBuffer.dmaBlockList.blockPhysAddr, gCompletionDummyBuffer.dmaBlockList.blockSize, 0, 1);

	HW_DESC_SET_FLOW_MODE(&desc, BYPASS);

	/* set the ACK bits with the completion counter */
	HW_DESC_SET_ACK_LAST(&desc);

	/* Lock the HW queue */
	HW_QUEUE_LOCK();

	HW_QUEUE_POLL_QUEUE_UNTIL_FREE_SLOTS(1);

	HW_DESC_PUSH_TO_QUEUE(&desc);

	/* Unlock HW queue */
	HW_QUEUE_UNLOCK();
}




