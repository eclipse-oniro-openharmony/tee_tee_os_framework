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

/* ************ Include Files ************** */
#include "dx_util.h"
#include "cc_plat.h"
#include "dx_pal_dma.h"
#include "dx_util_rpmb_adaptor.h"

/* ******************************************************************************* */
/* ***************         RPMB shared secret key functions    ******************* */
/* ******************************************************************************* */

/* Computes and outputs the device RPMB Key based on fixed data & KDR */
DxUTILError_t DX_UTIL_DeriveRPMBKey(DxUtilRpmbKey_t pRpmbKey)
{
    DxError_t rc     = DX_UTIL_OK;
    uint8_t dataIn[] = { KEY_DERIVATION_4_RPMB };

    /* check parameters validity */
    if (pRpmbKey == NULL)
        return DX_UTIL_DATA_OUT_POINTER_INVALID_ERROR;

    /* call DX_UTIL_CmacDeriveKey with KDR to calculate the first 16 bytes of the key */
    rc = DX_UTIL_CmacDeriveKey(DX_UTIL_KDR_KEY, dataIn, sizeof(dataIn), pRpmbKey);
    if (rc != DX_UTIL_OK)
        return rc;

    /* call DX_UTIL_CmacDeriveKey with KDR to calculate the second 16 bytes of the key */
    dataIn[0] = 0x02;
    rc = DX_UTIL_CmacDeriveKey(DX_UTIL_KDR_KEY, dataIn, sizeof(dataIn), (pRpmbKey + sizeof(DxUtilRpmbKey_t) / 2));
    if (rc != DX_UTIL_OK)
        return rc;

    return rc;
}

/* Receives a list of data frames, each 284 bytes long, as described in [JESD84], and
   calculates an HMAC-SHA256 authentication code of the callers' data buffers using RPMB key. */
DxUTILError_t DX_UTIL_SignRPMBFrames(unsigned long *pListOfDataFrames, uint32_t listSize,
                                     DxUtilHmacResult_t pHmacResult)
{
    DxError_t rc = DX_UTIL_OK;
    DxUtilRpmbKey_t rpmbKey;
    CRYS_HMACUserContext_t UserContext;
    int i = 0, size;

    /* check parameters validity */
    if ((pListOfDataFrames == NULL) || (pHmacResult == NULL))
        return DX_UTIL_DATA_OUT_POINTER_INVALID_ERROR;
    if ((listSize < DX_UTIL_MIN_RPMB_DATA_BUFFERS) || (listSize > DX_UTIL_MAX_RPMB_DATA_BUFFERS))
        return DX_UTIL_ILLEGAL_PARAMS_ERROR;

    /* compute the device RPMB key */
    rc = DX_UTIL_DeriveRPMBKey(rpmbKey);

    /* in case of a single frame, perform an integrated HMAC flow */
    if (listSize == 1) {
        rc = CRYS_HMAC(CRYS_HASH_SHA256_mode, rpmbKey, sizeof(DxUtilRpmbKey_t), (uint8_t *)(pListOfDataFrames[0]),
                       DX_UTIL_RPMB_DATA_FRAME_SIZE_IN_BYTES, pHmacResult);
        return rc;
    }

    /* else,
       join 64 data frames together to one chunk (284*64) to perform hash update,
       only last chunk (<= 64 frames) should do finalize */

    /* initializes the HMAC machine on the CRYS level */
    rc = CRYS_HMAC_Init(&UserContext, CRYS_HASH_SHA256_mode, rpmbKey, sizeof(DxUtilRpmbKey_t));
    if (rc != CRYS_OK)
        return rc;

    while (listSize) {
        size = min(listSize, RPMB_MAX_BLOCKS_PER_UPDATE);

        /* performs a HASH update on each chunk (create up to 128 MLLI entries) */
        rc = RpmbHmacUpdate(&UserContext, &pListOfDataFrames[i], size);
        if (rc != CRYS_OK)
            return rc;

        i += size;
        listSize -= size;
    }

    /* finalizes the HMAC processing of a all data blocks */
    rc = RpmbHmacFinish(&UserContext, pHmacResult);

    return rc;
}
