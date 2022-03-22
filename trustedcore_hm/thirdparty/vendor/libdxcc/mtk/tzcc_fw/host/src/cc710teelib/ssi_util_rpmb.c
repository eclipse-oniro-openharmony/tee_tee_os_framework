/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_util_cmac.h"
#include "cc_plat.h"
#include "ssi_pal_dma.h"
#include "ssi_util_rpmb_adaptor.h"
#include "ssi_util_key_derivation_defs.h"
#include "sasi_fips_defs.h"
#include "ssi_pal_mem.h"

/* ******************************************************************************* */
/* ***************         RPMB shared secret key functions    ******************* */
/* ******************************************************************************* */

/* Computes and outputs the device RPMB Key based on fixed data & KDR */
SaSiUtilError_t SaSi_UtilDeriveRPMBKey(SaSiUtilRpmbKey_t pRpmbKey)
{
    SaSiError_t rc = SASI_UTIL_OK;

    uint8_t label[]   = { RPMB_KEY_DERIVATION_LABAL };
    uint8_t context[] = { RPMB_KEY_DERIVATION_CONTEXT };

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check parameters validity */
    if (pRpmbKey == NULL)
        return SASI_UTIL_DATA_OUT_POINTER_INVALID_ERROR;

    /* invoke KDF with KDR to calculate the first 16 bytes of the key */
    rc = SaSi_UtilKeyDerivation(SASI_UTIL_ROOT_KEY, NULL, (const uint8_t *)&label, sizeof(label),
                                (const uint8_t *)&context, sizeof(context), pRpmbKey,
                                2 * SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES);
    if (rc != SASI_UTIL_OK)
        return rc;

    return rc;
}

/* Receives a list of data frames, each 284 bytes long, as described in [JESD84], and
   calculates an HMAC-SHA256 authentication code of the callers' data buffers using RPMB key. */
SaSiUtilError_t SaSi_UtilSignRPMBFrames(unsigned long *pListOfDataFrames, uint32_t listSize,
                                        SaSiUtilHmacResult_t pHmacResult)
{
    SaSiError_t rc = SASI_UTIL_OK;
    SaSiUtilRpmbKey_t rpmbKey;
    SaSi_HMACUserContext_t UserContext;
    int i = 0, size;
    SaSi_HASH_Result_t tempHashRes;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* check parameters validity */
    if ((pListOfDataFrames == NULL) || (pHmacResult == NULL))
        return SASI_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    if ((listSize < SASI_UTIL_MIN_RPMB_DATA_BUFFERS) || (listSize > SASI_UTIL_MAX_RPMB_DATA_BUFFERS))
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;

    /* compute the device RPMB key */
    rc = SaSi_UtilDeriveRPMBKey(rpmbKey);

    /* in case of a single frame, perform an integrated HMAC flow */
    if (listSize == 1) {
        rc = SaSi_HMAC_MTK(SaSi_HASH_SHA256_mode, rpmbKey, sizeof(SaSiUtilRpmbKey_t), (uint8_t *)(pListOfDataFrames[0]),
                           SASI_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, tempHashRes);
        if (rc == SaSi_OK) {
            SaSi_PalMemCopy(pHmacResult, tempHashRes, sizeof(SaSiUtilHmacResult_t));
        }
        return rc;
    }

    /* else,
       join 64 data frames together to one chunk (284*64) to perform hash update,
       only last chunk (<= 64 frames) should do finalize */

    /* initializes the HMAC machine on the SaSi level */
    rc = SaSi_HMAC_Init_MTK(&UserContext, SaSi_HASH_SHA256_mode, rpmbKey, sizeof(SaSiUtilRpmbKey_t));
    if (rc != SaSi_OK)
        return rc;

    while (listSize) {
        size = min(listSize, RPMB_MAX_BLOCKS_PER_UPDATE);

        /* performs a HASH update on each chunk (create up to 128 MLLI entries) */
        rc = RpmbHmacUpdate(&UserContext, &pListOfDataFrames[i], size);
        if (rc != SaSi_OK)
            return rc;

        i += size;
        listSize -= size;
    }

    /* finalizes the HMAC processing of a all data blocks */
    rc = RpmbHmacFinish(&UserContext, tempHashRes);
    if (rc == SaSi_OK) {
        SaSi_PalMemCopy(pHmacResult, tempHashRes, sizeof(SaSiUtilHmacResult_t));
    }

    return rc;
}
