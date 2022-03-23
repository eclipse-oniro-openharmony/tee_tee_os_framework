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
#include "ssi_regs.h"
#include "ssi_hal_plat.h"
#include "ssi_general_defs.h"

extern SaSi_PalMutex sasiFipsMutex;

SaSiError_t SaSi_FIPS_SetReeStatus(CC_FipsReeStatus_t status)
{
    SaSiError_t error = SaSi_OK;

    if (status == CC_TEE_FIPS_REE_STATUS_ERROR) {
        error = FipsSetError(CC_TEE_FIPS_ERROR_FROM_REE);
    } else {
        error = FipsRevertState(CC_FIPS_STATE_SUSPENDED);
        if (error == SaSi_OK) {
            error = FipsSetState(CC_FIPS_STATE_CRYPTO_APPROVED);
        }
    }

    return error;
}

SaSiError_t SaSi_FIPS_SetCryptoUsageState(CC_FipsCryptoUsageState_t state)
{
    SaSiError_t error        = SaSi_OK;
    CC_FipsState_t fipsState = 0;

    error = SaSi_FIPS_GetState(&fipsState, NULL);
    if (error != SaSi_OK) {
        return error;
    }

    if (fipsState != CC_FIPS_STATE_SUSPENDED) {
        return SaSi_FIPS_ERROR;
    }

    if (state == CC_TEE_FIPS_CRYPTO_USAGE_STATE_NON_APPROVED) {
        error = FipsRevertState(CC_FIPS_STATE_CRYPTO_APPROVED);
    } else {
        error = FipsSetState(CC_FIPS_STATE_CRYPTO_APPROVED);
    }

    return error;
}

SaSiError_t SaSi_FIPS_GetError(CC_FipsError_t *pFipsError)
{
    SaSiError_t error = SASI_OK;

    if (pFipsError == NULL) {
        return SASI_FAIL;
    }

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    error = SaSi_PalFipsGetError(pFipsError);

    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    return error;
}

SaSiError_t SaSi_FIPS_GetState(CC_FipsState_t *pFipsState, bool *pIsDeviceZeroized)
{
    SaSiError_t error           = SASI_OK;
    uint32_t regVal             = 0;
    uint32_t lcsVal             = 0;
    CC_FipsState_t palFipsState = 0;

    if (pFipsState == NULL) {
        return SASI_FAIL;
    }

    error = SaSi_PalMutexLock(&sasiFipsMutex, SASI_INFINITE);
    if (error != SASI_OK) {
        SaSi_PalAbort("Fail to acquire mutex\n");
    }

    error = SaSi_PalFipsGetState(&palFipsState);
    if (pIsDeviceZeroized != NULL) {
        /* Read LCS */
        regVal             = SASI_HAL_READ_REGISTER(SASI_REG_OFFSET(HOST_RGF, LCS_REG));
        lcsVal             = SASI_REG_FLD_GET(0, LCS_REG, LCS_REG, regVal);
        *pIsDeviceZeroized = ((lcsVal == SASI_LCS_RMA_LCS) ? true : false);
    }

    if (SaSi_PalMutexUnlock(&sasiFipsMutex) != SASI_OK) {
        SaSi_PalAbort("Fail to release mutex\n");
    }

    if (error != SASI_OK) {
        return error;
    }

    if (palFipsState & CC_FIPS_STATE_ERROR) {
        *pFipsState = CC_FIPS_STATE_ERROR;
    } else if (palFipsState & CC_FIPS_STATE_SUSPENDED) {
        *pFipsState = CC_FIPS_STATE_SUSPENDED;
    } else if (palFipsState & CC_FIPS_STATE_SUPPORTED) {
        *pFipsState = CC_FIPS_STATE_SUPPORTED;
    } else {
        *pFipsState = CC_FIPS_STATE_NOT_SUPPORTED;
    }

    return error;
}
