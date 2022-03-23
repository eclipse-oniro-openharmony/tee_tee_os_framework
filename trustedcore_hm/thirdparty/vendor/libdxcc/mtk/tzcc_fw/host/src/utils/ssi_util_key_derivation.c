/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ************ Include Files ************** */
#include "ssi_pal_types.h"
#include "ssi_pal_mem.h"
#include "ssi_util_int_defs.h"
#include "ssi_error.h"
#include "ssi_aes.h"
#include "ssi_util_defs.h"
#include "ssi_util_error.h"
#include "ssi_util_key_derivation.h"
#include "ssi_hal_plat.h"
#include "ssi_regs.h"
#include "ssi_pal_mutex.h"
#include "ssi_pal_abort.h"
#include "ssi_util_cmac.h"
#include "sasi_fips_defs.h"

SaSiUtilError_t SaSi_UtilKeyDerivation(SaSiUtilKeyType_t keyType, SaSiAesUserKeyData_t *pUserKey, const uint8_t *pLabel,
                                       size_t labelSize, const uint8_t *pContextData, size_t contextSize,
                                       uint8_t *pDerivedKey, size_t derivedKeySize)
{
    uint32_t rc = 0;
    uint32_t dataSize, i, iterationNum, numIteration, bytesToCopy;
    uint8_t dataIn[SASI_UTIL_MAX_KDF_SIZE_IN_BYTES] = { 0 };
    uint8_t tmp[SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES];
    size_t length, lengthReverse;

    CHECK_AND_RETURN_ERR_UPON_FIPS_ERROR();

    /* Check key type */
    switch (keyType) {
    case SASI_UTIL_ROOT_KEY:
        break;
    case SASI_UTIL_USER_KEY:
        if (pUserKey->pKey == NULL) {
            return SASI_UTIL_INVALID_KEY_TYPE;
        }
        break;
    default:
        return SASI_UTIL_INVALID_KEY_TYPE;
    }

    /* Check Label, Context, DerivedKey sizes */
    if (derivedKeySize > SASI_UTIL_MAX_DERIVED_KEY_SIZE_IN_BYTES)
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;

    if (((labelSize != 0) && (pLabel == NULL)) || (labelSize == 0) ||
        (labelSize > SASI_UTIL_MAX_LABEL_LENGTH_IN_BYTES)) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    if (((contextSize != 0) && (pContextData == NULL)) || (contextSize == 0) ||
        (contextSize > SASI_UTIL_MAX_CONTEXT_LENGTH_IN_BYTES)) {
        return SASI_UTIL_ILLEGAL_PARAMS_ERROR;
    }

    /* Generate dataIn buffer for CMAC: iteration || Label || 0x00 || context || length */

    i = 1;
    numIteration =
        (derivedKeySize + SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES - 1) / SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
    length = derivedKeySize * 8;
    if (length > 0xFF)
        dataSize = SASI_UTIL_FIX_DATA_MAX_SIZE_IN_BYTES;
    else
        dataSize = SASI_UTIL_FIX_DATA_MIN_SIZE_IN_BYTES;

    dataSize += labelSize + contextSize;

    if (labelSize != 0) {
        SaSi_PalMemCopy((uint8_t *)&dataIn[i], pLabel, labelSize);
        i += labelSize;
    }

    dataIn[i++] = 0x00;

    if (contextSize != 0) {
        SaSi_PalMemCopy((uint8_t *)&dataIn[i], pContextData, contextSize);
        i += contextSize;
    }

    if (length > 0xFF) {
        /* Reverse words order and bytes in each word */
        lengthReverse = ((length & 0xFF00) >> 8) | ((length & 0xFF) << 8);
        SaSi_PalMemCopy((uint8_t *)&dataIn[i], (uint8_t *)&lengthReverse, 2);
    } else
        SaSi_PalMemCopy((uint8_t *)&dataIn[i], (uint8_t *)&length, 1);

    for (iterationNum = 0; iterationNum < numIteration; iterationNum++) {
        dataIn[0] = iterationNum + 1;
        rc        = SaSi_UtilCmacDeriveKey(keyType, pUserKey, dataIn, dataSize, tmp);
        if (rc != SASI_SUCCESS) {
            return rc;
        }

        /* concatenate the latest PRF result */
        /* copy only number of bits that required... */
        if (derivedKeySize > SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES) {
            bytesToCopy = SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
            derivedKeySize -= SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES;
        } else
            bytesToCopy = derivedKeySize;
        SaSi_PalMemCopy((uint8_t *)&pDerivedKey[iterationNum * SASI_UTIL_AES_CMAC_RESULT_SIZE_IN_BYTES], tmp,
                        bytesToCopy);
    }

    return rc;
}
