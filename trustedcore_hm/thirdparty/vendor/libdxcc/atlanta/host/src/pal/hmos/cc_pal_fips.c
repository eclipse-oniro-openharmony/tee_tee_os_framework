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

//#include <unistd.h>
//#include <pthread.h>
#include "cc_pal_types.h"
#include "cc_pal_fips.h"
#include "cc_pal_mem.h"
#include "cc_hal.h"
#include "dx_host.h"
#include "cc_regs.h"
#include "cc_fips_defs.h"

CCFipsStateData_t 	gStateData = { CC_FIPS_STATE_CRYPTO_APPROVED, CC_TEE_FIPS_ERROR_OK, CC_FIPS_TRACE_NONE };
//pthread_t threadId;
bool thread_exit = false;
uint32_t threadRc;

#define GPR0_IRR_MASK (1<<DX_HOST_IRR_GPR0_BIT_SHIFT)

void *fipsIrqThread(void *params)
{

	CC_UNUSED_PARAM(params);
#if 0
	uint32_t regVal = 0;
	uint32_t fipsMask = GPR0_IRR_MASK;
	while(!thread_exit) {
		regVal = CC_HAL_READ_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_IRR));
		if (regVal & fipsMask) {
			CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_ICR), fipsMask);
			CC_FipsIrqHandle();
		}
		usleep(100); // wait 100 milisecond
	}
	threadRc = 0;
#endif
 //       pthread_exit(&threadRc);
	return NULL;
}


CCError_t CC_PalFipsWaitForReeStatus(void)
{
#if 0
	uint32_t rc;

	thread_exit = false;
	rc = pthread_create(&threadId, NULL, fipsIrqThread, NULL);
	if (rc != 0) {
		return rc;
	}
	// join will be in the termination function
#endif
	return CC_OK;
}

CCError_t CC_PalFipsStopWaitingRee(void)
{
#if 0
	void *threadRet;

	thread_exit = true; // The fips thread checks this flag and act accordingly
	pthread_join(threadId, &threadRet);
	return CC_OK;
#endif
	return CC_OK;
}

CCError_t CC_PalFipsGetState(CCFipsState_t *pFipsState)
{
	*pFipsState = gStateData.state;

	return CC_OK;
}


CCError_t CC_PalFipsGetError(CCFipsError_t *pFipsError)
{
	*pFipsError = gStateData.error;

	return CC_OK;
}


CCError_t CC_PalFipsGetTrace(CCFipsTrace_t *pFipsTrace)
{
	*pFipsTrace = gStateData.trace;

	return CC_OK;
}

CCError_t CC_PalFipsSetState(CCFipsState_t fipsState)
{
	gStateData.state = fipsState;

	return CC_OK;
}

CCError_t CC_PalFipsSetError(CCFipsError_t fipsError)
{
	gStateData.error = fipsError;

	return CC_OK;
}

CCError_t CC_PalFipsSetTrace(CCFipsTrace_t fipsTrace)
{
	gStateData.trace = (gStateData.trace | fipsTrace);

	return CC_OK;
}

