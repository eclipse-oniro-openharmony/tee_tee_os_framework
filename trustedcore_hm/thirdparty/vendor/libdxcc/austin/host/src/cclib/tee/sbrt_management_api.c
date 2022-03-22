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
// #include <stdio.h>
#include "dx_pal_types.h"
#include "util.h"
#include "crypto_driver_defs.h"
#include "dx_otp_defs.h"
#include "secureboot_defs.h"
#include "sbrt_management_defs.h"
#include "sbrt_management_api.h"
#include "sbrt_management_hw_defs.h"
#include "sbrt_management_error.h"
#include "hw_queue_defs.h"
#include "secureboot_defs.h"
#include "dx_hal_plat.h"
#include "dx_cclib.h"
#include "dx_util_defs.h"
#include "dx_pal_mem.h"
#include "dx_hal_plat.h"
#include "dx_hal.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Internal Functions **************************** */

DxError_t DX_SBRT_GetLcs(uint32_t *pLcs)
{
    DxError_t error = DX_SUCCESS;
    uint32_t sdFlag, manufacturerFlag = 0;
    uint32_t lcsVal = 0;

    /* Check input variables */
    if (pLcs == DX_NULL) {
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* Wait on LCS valid before reading the LCS register */
    DX_CCLIB_WAIT_ON_LCS_VALID_BIT();

    /* Read LCS */
    lcsVal = DX_HAL_ReadCcRegister(DX_CC_REG_OFFSET(CRY_KERNEL, LCS_REG));
    lcsVal = DX_CC_REG_FLD_GET(0, LCS_REG, LCS_REG, lcsVal);

    /* Return the LCS value */
    *pLcs = lcsVal;

    switch (lcsVal) {
    /* If lifecycle is "secure", verify the following */
    case DX_SBRT_SECURE_LCS:
        /* Check RKEK error bit */
        DX_UTIL_IS_OTP_KDR_ERROR(error);
        if (error) {
            return DX_SBRT_ILLEGAL_RKEK_VALUE_ERR;
        }
        /* Verify security disable flag is off */
        error = DX_HAL_ReadOTPWord(DX_OTP_MANUFACTRER_FLAG_OFFSET, &manufacturerFlag);
        if (error != DX_SUCCESS)
            return error;
        sdFlag = DX_CC_REG_FLD_GET(0, OTP_MANUFACTRER_FLAG, SD, manufacturerFlag);
        if (sdFlag != DX_SBRT_SECURITY_DISABLE_FLAG_OFF) {
            return DX_SBRT_ILLEGAL_LCS_FOR_OPERATION_ERR;
        }
        /* FALLTHROUGH */

    /* If lifecycle is "DM" or "secure", verify the following */
    case DX_SBRT_DEVICE_MANUFACTURE_LCS:
        /* Check Provision (Scp) error bit */
        DX_SBRT_IS_OTP_PROV_ERROR(error);
        if (error) {
            return DX_SBRT_ILLEGAL_SCP_VALUE_ERR;
        }
        break;
    default:
        break;
    }

    return DX_SUCCESS;
}

DxError_t DX_SBRT_GetPubKeyHash(DxSbPubKeyIndexType_t keyIndex, uint32_t *hashedPubKey, uint32_t hashResultSizeWords)
{
    uint32_t i, address, totalZeros = 0, zerosHash0, zerosHash1;
    uint32_t regVal = 0, cntZero = 0;
    uint32_t oemFlag = 0;
    DxError_t error  = DX_SUCCESS;

    /* Check input variables */
    if (hashedPubKey == DX_NULL) {
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* verify a valid configuration: 1 key of 256b or 2 keys of 128b */
    switch (hashResultSizeWords) {
    case DX_SBRT_256B_HASH_SIZE_IN_WORDS:
        if (keyIndex != DX_SB_HASH_BOOT_KEY_256B)
            return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
        break;
    case DX_SBRT_128B_HASH_SIZE_IN_WORDS:
        if ((keyIndex != DX_SB_HASH_BOOT_KEY_0_128B) && (keyIndex != DX_SB_HASH_BOOT_KEY_1_128B))
            return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
        break;
    default:
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* Get the current lifecycle */
    error = DX_SBRT_GetLcs(&regVal);
    if (error != DX_SUCCESS) {
        return error;
    }

    /* case SD lifecycle, the key is not programmed yet */
    if (regVal == DX_SBRT_SECURITY_DISABLED_LCS)
        return DX_SBRT_HASH_NOT_PROGRAMMED_ERR;

    /* Set the operation to read */
    address = (keyIndex == DX_SB_HASH_BOOT_KEY_1_128B ? DX_OTP_HASH_INDEX_1_OFFSET : DX_OTP_HASH_INDEX_0_OFFSET);

    /* Read the HASH from the OTP */
    for (i = 0; i < hashResultSizeWords; i++) {
        error = DX_HAL_ReadOTPWord(address + i, &regVal);
        if (error != DX_SUCCESS)
            return error;

        *(hashedPubKey + i) = regVal;

        /* Accumulate number of zeroes */
        DX_SBRT_COUNT_ZEROES(regVal, cntZero);

    } /* End of for loop */

    /* Read OEM programmer flags and get number of zeroes set in the OTP */
    error = DX_HAL_ReadOTPWord(DX_OTP_OEM_FLAG_OFFSET, &oemFlag);
    if (error != DX_SUCCESS)
        return error;

    zerosHash0 = DX_CC_REG_FLD_GET(0, OTP_OEM_FLAG, HBK0, oemFlag);
    zerosHash1 = DX_CC_REG_FLD_GET(0, OTP_OEM_FLAG, HBK1, oemFlag);

    switch (hashResultSizeWords) {
    case DX_SBRT_256B_HASH_SIZE_IN_WORDS:
        if (zerosHash1 == DX_SBRT_HBK1_NOT_EXIST) {
            totalZeros = zerosHash0;
        } else {
            // this case may occurs from DX_SBRT_GetProvisionKey
            totalZeros = zerosHash0 + zerosHash1;
        }
        break;
    case DX_SBRT_128B_HASH_SIZE_IN_WORDS:
        if (keyIndex == DX_SB_HASH_BOOT_KEY_0_128B) {
            totalZeros = zerosHash0;
        } else {
            totalZeros = zerosHash1;
        }
        break;
    default:
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* Verify the number of "0" bits in the hash key */
    if (totalZeros != cntZero) {
        return DX_SBRT_ILLEGAL_OEM_HASH_VALUE_ERR;
    }

    return DX_SUCCESS;
}

DxError_t DX_SBRT_GetCodeEncryptionKey(DxMngAesKey_t codeEncryptionKey)
{
    DxError_t error = DX_SUCCESS;
    uint32_t i, address;
    uint32_t kceZero, regVal = 0, cntZero = 0;
    uint32_t oemFlag = 0;

    /* Check input variables */
    if (codeEncryptionKey == DX_NULL) {
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }
    error = DX_SBRT_GetLcs(&regVal);
    if (error != DX_SUCCESS)
        return error;

    if (regVal == DX_SBRT_RMA_LCS) {
        DX_PAL_MemSet((uint8_t *)codeEncryptionKey, 0x0, sizeof(DxMngAesKey_t));
        return DX_SUCCESS;
    }

    /* Set the operation to read */
    address = DX_OTP_KCE_OFFSET;

    /* Read Kce from OTP */
    for (i = 0; i < AES_KEY_SIZE_IN_WORDS; i++) {
        error = DX_HAL_ReadOTPWord(address + i, &regVal);
        if (error != DX_SUCCESS)
            return error;

        *(codeEncryptionKey + i) = regVal;

        /* Accumulate number of zeroes */
        DX_SBRT_COUNT_ZEROES(regVal, cntZero);

    } /* End of for loop */

    /* Read OEM programmer flags and get number of zeroes set in the OTP */
    error = DX_HAL_ReadOTPWord(DX_OTP_OEM_FLAG_OFFSET, &oemFlag);
    if (error != DX_SUCCESS)
        return error;

    kceZero = DX_CC_REG_FLD_GET(0, OTP_OEM_FLAG, KCE, oemFlag);

    /* Verify the number of "0" bits in the hash key */
    if (cntZero != kceZero) {
        return DX_SBRT_ILLEGAL_OEM_KCE_VALUE_ERR;
    }

    return DX_SUCCESS;
}

DxError_t DX_SBRT_GetSwVersion(DxSbSwVersionId_t counterId, uint32_t *swVersion)
{
    uint32_t i, regVal = 0;
    uint32_t versionBitCount = 0;
    uint32_t cntrWidth, cntrOffset, cntrSwVersion;
    DxError_t error = DX_SUCCESS;

    /* check input variables */
    if (swVersion == DX_NULL) {
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* check for legal counter number */
    switch (counterId) {
    case DX_SW_VERSION_COUNTER1:
        cntrWidth  = DX_SB_VERSION_COUNTER1_WIDTH;
        cntrOffset = DX_OTP_VERSION_COUNTER1_OFFSET;
        break;
    case DX_SW_VERSION_COUNTER2:
        cntrWidth  = DX_SB_VERSION_COUNTER2_WIDTH;
        cntrOffset = DX_OTP_VERSION_COUNTER2_OFFSET;
        break;
    default:
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* Verify that the HW finished initialization */
    DX_CCLIB_WAIT_ON_LCS_VALID_BIT();

    /* Read the SW version from the OTP, and accumulate number of ones */
    cntrSwVersion = 0;
    for (i = 0; i < cntrWidth; i++) {
        error = DX_HAL_ReadOTPWord(cntrOffset + i, &regVal);
        if (error != DX_SUCCESS)
            return error;

        /* return the number of 1 bits */
        COUNT_ONE_BITS(regVal, versionBitCount);
        cntrSwVersion += versionBitCount;
    }

    *swVersion = cntrSwVersion;

    return DX_SUCCESS;
}

DxError_t DX_SBRT_SetSwVersion(DxSbSwVersionId_t counterId, uint32_t swVersion)
{
    DxError_t error = DX_SUCCESS;
    uint32_t i, regVal = 0;
    uint32_t cntrWidth, cntrOffset;

    /* check for legal counter number */
    switch (counterId) {
    case DX_SW_VERSION_COUNTER1:
        if (swVersion > DX_SBRT_SW_REVOCATION_MAX_NUM_OF_BITS_CNTR1)
            return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
        cntrWidth  = DX_SB_VERSION_COUNTER1_WIDTH;
        cntrOffset = DX_OTP_VERSION_COUNTER1_OFFSET;
        break;
    case DX_SW_VERSION_COUNTER2:
        if (swVersion > DX_SBRT_SW_REVOCATION_MAX_NUM_OF_BITS_CNTR2)
            return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
        cntrWidth  = DX_SB_VERSION_COUNTER2_WIDTH;
        cntrOffset = DX_OTP_VERSION_COUNTER2_OFFSET;
        break;
    default:
        return DX_SBRT_ILLEGAL_INPUT_PARAM_ERR;
    }

    /* Write new SW version to otp */
    for (i = 0; i < cntrWidth; i++) {
        /* convert to base-1 representation */
        regVal = DX_SBRT_ALL_ONES_VALUE >> (DX_SBRT_ALL_ONES_NUM_BITS - min(swVersion, DX_SBRT_ALL_ONES_NUM_BITS));
        swVersion -= min(swVersion, DX_SBRT_ALL_ONES_NUM_BITS);

        error = DX_HAL_WriteOTPWord(cntrOffset + i, regVal);
        /* in case of failure in OTP write... */
        if (error != DX_SUCCESS)
            return error;
    }

    return DX_SUCCESS;
}
