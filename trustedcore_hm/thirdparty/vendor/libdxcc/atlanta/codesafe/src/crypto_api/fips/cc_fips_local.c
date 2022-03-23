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

#include "cc_pal_types.h"
#include "cc_hal_plat.h"
#include "cc_regs.h"
#include "cc_pal_mutex.h"
#include "cc_pal_abort.h"
#include "cc_pal_fips.h"
#include "cc_des.h"
#include "cc_fips.h"
#include "cc_fips_defs.h"
#include "cc_fips_rsa_defs.h"
#include "cc_fips_dh_defs.h"
#include "cc_fips_prng_defs.h"

#ifndef CC_NOT_SUPPORT_ECC_FIPS
#include "cc_fips_ecc_defs.h"
#endif

extern CC_PalMutex CCFipsMutex;


CCError_t FipsNotifyUponTeeStatus(CCFipsError_t  fipsError)
{

	if (fipsError == CC_TEE_FIPS_ERROR_OK) {
		CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_GPR), (CC_FIPS_SYNC_TEE_STATUS|CC_FIPS_SYNC_MODULE_OK));
	} else {
		CC_HAL_WRITE_REGISTER(CC_REG_OFFSET(HOST_RGF, HOST_GPR), (CC_FIPS_SYNC_TEE_STATUS|CC_FIPS_SYNC_MODULE_ERROR));
	}
	return CC_OK;
}



CCError_t FipsSetState(CCFipsState_t fipsState)
{
        CCError_t error = CC_OK;
        CCFipsState_t prevFipsState = 0;

	error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
	if (error != CC_OK) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

        error = CC_PalFipsGetState(&prevFipsState);
        if (error != CC_OK) {
                goto End;
        }

        fipsState |= prevFipsState;

        error = CC_PalFipsSetState(fipsState);
        if (error != CC_OK) {
                goto End;
        }

End:
	if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
		CC_PalAbort("Fail to release mutex\n");
	}

        return error;
}

CCError_t FipsGetRawState(CCFipsState_t *pFipsState)
{
        CCError_t 	error = CC_OK;

        if (pFipsState == NULL) {
                return CC_FAIL;
        }

        error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
        if (error != CC_OK) {
                CC_PalAbort("Fail to acquire mutex\n");
        }

        error = CC_PalFipsGetState(pFipsState);

        if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return error;
}

CCError_t FipsRevertState(CCFipsState_t fipsState)
{
        CCError_t error = CC_OK;
        CCFipsState_t prevFipsState = 0;

        if ((fipsState != CC_FIPS_STATE_SUSPENDED) && (fipsState != CC_FIPS_STATE_CRYPTO_APPROVED)) {
                return CC_FIPS_ERROR;
        }

        error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
        if (error != CC_OK) {
                CC_PalAbort("Fail to acquire mutex\n");
        }

        error = CC_PalFipsGetState(&prevFipsState);
        if (error != CC_OK) {
                goto End;
        }

        prevFipsState &= ~fipsState;

        error = CC_PalFipsSetState(prevFipsState);
        if (error != CC_OK) {
                goto End;
        }

End:
        if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
                CC_PalAbort("Fail to release mutex\n");
        }

        return error;
}


CCError_t FipsSetReeStatus(CCFipsReeStatus_t status)
{
        CCError_t error = CC_OK;

        if (status == CC_TEE_FIPS_REE_STATUS_ERROR) {
                error = FipsSetError(CC_TEE_FIPS_ERROR_FROM_REE);
        }
        else {
                error = FipsRevertState(CC_FIPS_STATE_SUSPENDED);
                if (error == CC_OK) {
                        error = FipsSetState(CC_FIPS_STATE_CRYPTO_APPROVED);
                }
        }

        return error;
}


CCError_t FipsSetError(CCFipsError_t  fipsError)
{
        CCError_t error = CC_OK;
	CCFipsError_t  currentFipsError;

	if (fipsError == CC_TEE_FIPS_ERROR_OK) {
		return CC_FIPS_ERROR;
	}

	error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
	if (error != CC_OK) {
		CC_PalAbort("Fail to acquire mutex\n");
	}
	error = CC_PalFipsGetError(&currentFipsError);
        if (error != CC_OK) {
                goto End;
        }
        if (currentFipsError != CC_TEE_FIPS_ERROR_OK) {
                goto End;
	}
        error = CC_PalFipsSetError(fipsError);
	if (error != CC_OK) {
		goto End;
	}
        error = CC_PalFipsSetState(CC_FIPS_STATE_ERROR);
	if (error != CC_OK) {
		goto End;
	}
        if (fipsError != CC_TEE_FIPS_ERROR_FROM_REE) {
                error = FipsNotifyUponTeeStatus(fipsError);
        }
End:
	if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
		CC_PalAbort("Fail to release mutex\n");
	}

        return error;
}

CCError_t FipsSetTrace(CCFipsTrace_t fipsTrace)
{
        CCError_t error = CC_OK;

	error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
	if (error != CC_OK) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

	error = CC_PalFipsSetTrace(fipsTrace);

	if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
		CC_PalAbort("Fail to release mutex\n");
	}

        return error;
}


CCError_t FipsGetTrace(CCFipsTrace_t *pFipsTrace)
{
        CCError_t error = CC_OK;

	if (pFipsTrace == NULL) {
		return CC_FAIL;
	}

	error = CC_PalMutexLock(&CCFipsMutex, CC_INFINITE);
	if (error != CC_OK) {
		CC_PalAbort("Fail to acquire mutex\n");
	}

	error = CC_PalFipsGetTrace(pFipsTrace);

	if (CC_PalMutexUnlock(&CCFipsMutex) != CC_OK) {
		CC_PalAbort("Fail to release mutex\n");
	}

	return error;
}


CCError_t FipsRunPowerUpTest(CCRndContext_t *pRndContext, CCFipsKatContext_t  *pFipsCtx)
{
	CCFipsError_t fipsErr = CC_TEE_FIPS_ERROR_OK;

	fipsErr = CC_FipsAesRunTests();
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
	fipsErr = CC_FipsAesCcmRunTests();
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
	fipsErr = CC_FipsDesRunTests();
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
	fipsErr = CC_FipsHashRunTests();
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
        fipsErr = CC_FipsHmacRunTests();
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
                goto End;
        }
        fipsErr = CC_FipsRsaKat(pRndContext, &pFipsCtx->fipsRsaCtx);
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
	fipsErr = CC_FipsEcdsaKat(pRndContext, &pFipsCtx->fipsEcdsaCtx);
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
	fipsErr = CC_FipsEcdhKat(&pFipsCtx->fipsEcdhCtx);
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
	fipsErr = CC_FipsDhKat(&pFipsCtx->fipsDhCtx);
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
	fipsErr = CC_FipsPrngKat(pRndContext, &pFipsCtx->fipsPrngCtx);
        if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		goto End;
        }
End:
	if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
		FipsSetError(fipsErr);
		return CC_FIPS_MODULE_ERROR_BASE;
	}

	FipsNotifyUponTeeStatus(CC_TEE_FIPS_ERROR_OK);
	return CC_OK;
}

