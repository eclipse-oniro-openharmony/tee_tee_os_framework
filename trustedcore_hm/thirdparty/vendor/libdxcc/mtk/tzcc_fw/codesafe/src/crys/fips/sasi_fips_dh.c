/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#include "ssi_pal_log.h"
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "sasi_dh.h"
#include "sasi_fips.h"
#include "sasi_fips_error.h"
#include "sasi_fips_defs.h"
#include "sasi_fips_dh_kat_data.h"

/* KAT test for DH.  */
CC_FipsError_t SaSi_FipsDhKat(SaSi_DH_FipsKat_t *pFipsCtx)
{
    SaSiError_t rc;
    CC_FipsError_t fipsRc = CC_TEE_FIPS_ERROR_OK;
    SaSi_DHUserPubKey_t *pUsrPubKey;
    SaSi_DHPrimeData_t *pPrimeData;
    uint8_t *pSecretBuff;
    uint16_t secretBuffSize;

    if (pFipsCtx == NULL) {
        return CC_TEE_FIPS_ERROR_DH_PUT;
    }

    pUsrPubKey     = &pFipsCtx->pubKey;
    pPrimeData     = &pFipsCtx->primeData;
    pSecretBuff    = pFipsCtx->secretBuff;
    secretBuffSize = sizeof(pFipsCtx->secretBuff);

    // Generate secrete key
    rc = SaSi_DH_GetSecretKey_MTK((uint8_t *)fipsDhKat2048InitiatorPrivKey, sizeof(fipsDhKat2048InitiatorPrivKey),
                                  (uint8_t *)fipsDhKat2048ResponderPubKey, sizeof(fipsDhKat2048ResponderPubKey),
                                  (uint8_t *)fipsDhKat2048PrimeP, sizeof(fipsDhKat2048PrimeP), pUsrPubKey, pPrimeData,
                                  pSecretBuff, &secretBuffSize);
    if ((rc != SaSi_OK) || (secretBuffSize != sizeof(pFipsCtx->secretBuff))) {
        fipsRc = CC_TEE_FIPS_ERROR_DH_PUT;
        goto End;
    }

    // Verify secret is the same as expected
    rc = SaSi_PalMemCmp((uint8_t *)fipsDhKat2048Secret, pSecretBuff, secretBuffSize);
    if (rc != SaSi_OK) {
        fipsRc = CC_TEE_FIPS_ERROR_DH_PUT;
        goto End;
    }

    FipsSetTrace(CC_FIPS_TRACE_DH_PUT);

End:
    SaSi_PalMemSetZero(pFipsCtx, sizeof(SaSi_DH_FipsKat_t));
    return fipsRc;
}
