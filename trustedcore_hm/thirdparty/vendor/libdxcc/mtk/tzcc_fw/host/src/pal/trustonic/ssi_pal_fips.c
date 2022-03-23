/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_types.h"
#include "ssi_pal_fips.h"
#include "ssi_pal_mem.h"

CC_FipsStateData_t gStateData = { CC_FIPS_STATE_CRYPTO_APPROVED, CC_TEE_FIPS_ERROR_OK, CC_FIPS_TRACE_NONE };

bool gReeError = false;

SaSiError_t SaSi_PalFipsGetState(CC_FipsState_t *pFipsState)
{
    *pFipsState = gStateData.state;

    return SASI_OK;
}

SaSiError_t SaSi_PalFipsGetError(CC_FipsError_t *pFipsError)
{
    *pFipsError = gStateData.error;

    return SASI_OK;
}

SaSiError_t SaSi_PalFipsGetTrace(CC_FipsTrace_t *pFipsTrace)
{
    *pFipsTrace = gStateData.trace;

    return SASI_OK;
}

SaSiError_t SaSi_PalFipsSetState(CC_FipsState_t fipsState)
{
    gStateData.state = fipsState;

    return SASI_OK;
}

SaSiError_t SaSi_PalFipsSetError(CC_FipsError_t fipsError)
{
    gStateData.error = fipsError;

    return SASI_OK;
}

SaSiError_t SaSi_PalFipsSetTrace(CC_FipsTrace_t fipsTrace)
{
    gStateData.trace = (CC_FipsTrace_t)(gStateData.trace | fipsTrace);

    return SASI_OK;
}

SaSiError_t SaSi_PalFipsNotifyUponTeeError(void)
{
    gReeError = true;

    return SASI_OK;
}
