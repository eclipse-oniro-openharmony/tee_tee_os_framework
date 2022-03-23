/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_types.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "ssi_pal_fips.h"
#include "sasi_des.h"
#include "sasi_fips.h"
#include "sasi_fips_defs.h"
#include "sasi_fips_rsa_defs.h"
#include "sasi_fips_dh_defs.h"
#include "sasi_fips_prng_defs.h"

#ifndef SSI_NOT_SUPPORT_ECC_FIPS
#include "sasi_fips_ecc_defs.h"
#endif

extern SaSi_PalMutex sasiFipsMutex;

CC_FipsError_t FipsSetState(CC_FipsState_t fipsState)
{
    SaSiError_t error            = SASI_OK;
    CC_FipsState_t prevFipsState = 0;

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    error = SaSi_PalFipsGetState(&prevFipsState);
    if (error != SASI_OK) {
        goto End;
    }

    fipsState |= prevFipsState;

    error = SaSi_PalFipsSetState(fipsState);
    if (error != SASI_OK) {
        goto End;
    }

End:
    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}

SaSiError_t FipsGetRawState(CC_FipsState_t *pFipsState)
{
    SaSiError_t error = SASI_OK;

    if (pFipsState == NULL) {
        return SASI_FAIL;
    }

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    error = SaSi_PalFipsGetState(pFipsState);

    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}

SaSiError_t FipsRevertState(CC_FipsState_t fipsState)
{
    SaSiError_t error            = SASI_OK;
    CC_FipsState_t prevFipsState = 0;

    if ((fipsState != CC_FIPS_STATE_SUSPENDED) && (fipsState != CC_FIPS_STATE_CRYPTO_APPROVED)) {
        return SaSi_FIPS_ERROR;
    }

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    error = SaSi_PalFipsGetState(&prevFipsState);
    if (error != SASI_OK) {
        goto End;
    }

    prevFipsState &= ~fipsState;

    error = SaSi_PalFipsSetState(prevFipsState);
    if (error != SASI_OK) {
        goto End;
    }

End:
    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CC_FipsError_t FipsSetError(CC_FipsError_t fipsError)
{
    SaSiError_t error = SASI_OK;
    CC_FipsError_t currentFipsError;

    if (fipsError == CC_TEE_FIPS_ERROR_OK) {
        return SaSi_FIPS_ERROR;
    }

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }
    error = SaSi_PalFipsGetError(&currentFipsError);
    if (error != SASI_OK) {
        goto End;
    }
    if (currentFipsError != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    error = SaSi_PalFipsSetError(fipsError);
    if (error != SASI_OK) {
        goto End;
    }
    error = SaSi_PalFipsSetState(CC_FIPS_STATE_ERROR);
    if (error != SASI_OK) {
        goto End;
    }
    if (fipsError != CC_TEE_FIPS_ERROR_FROM_REE) {
        error = SaSi_PalFipsNotifyUponTeeError();
    }
End:
    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CC_FipsError_t FipsSetTrace(CC_FipsTrace_t fipsTrace)
{
    SaSiError_t error = SASI_OK;

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    error = SaSi_PalFipsSetTrace(fipsTrace);

    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CC_FipsError_t FipsGetTrace(CC_FipsTrace_t *pFipsTrace)
{
    SaSiError_t error = SASI_OK;

    if (pFipsTrace == NULL) {
        return SASI_FAIL;
    }

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    error = SaSi_PalFipsGetTrace(pFipsTrace);

    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}

CC_FipsError_t FipsRunPowerUpTest(SaSi_RND_Context_t *pRndContext, SaSi_FipsKatContext_t *pFipsCtx)
{
    CC_FipsError_t fipsErr = CC_TEE_FIPS_ERROR_OK;

    fipsErr = SaSi_FipsAesRunTests();
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsAesCcmRunTests();
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsDesRunTests();
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsHashRunTests();
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsHmacRunTests();
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsRsaKat(pRndContext, &pFipsCtx->fipsRsaCtx);
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsEcdsaKat(pRndContext, &pFipsCtx->fipsEcdsaCtx);
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsEcdhKat(&pFipsCtx->fipsEcdhCtx);
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsDhKat(&pFipsCtx->fipsDhCtx);
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
    fipsErr = SaSi_FipsPrngKat(pRndContext, &pFipsCtx->fipsPrngCtx);
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        goto End;
    }
End:
    if (fipsErr != CC_TEE_FIPS_ERROR_OK) {
        FipsSetError(fipsErr);
        return SaSi_FIPS_MODULE_ERROR_BASE;
    }

    return SaSi_OK;
}
