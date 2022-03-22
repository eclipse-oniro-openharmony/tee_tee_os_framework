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
#include "dx_pal_types.h"
#include "secureboot_error.h"
#include "crypto_driver_defs.h"
#include "nvm.h"
#include "nvm_defs.h"
#include "nvm_error.h"
#include "util.h"
#include "bootimagesverifier_error.h"
#include "sbrt_management_defs.h"
#include "sbrt_management_error.h"
#include "sbrt_management_api.h"

/* *********************** Defines **************************** */

/* *********************** Enums **************************** */

/* *********************** Typedefs **************************** */

/* *********************** Global Data **************************** */

/* *********************** Public functions **************************** */

/* *********************** Private functions **************************** */

/*
 * @brief The NVM_ReadHASHPubKey function is a NVM interface function -
 *        The function retrieves the HASH of the device Public key (N & E) from the SRAM/NVM
 *        In case the flag DX_NO_PUB_KEY_VERIFICATION is set the function will return a
 *        constant pre-defined value.

 * @param[in] pubKeyIndex -  Index of HASH in the OTP
 *
 * @param[out] PubKeyHASH   -  the public key HASH.
 *
 * @param[in] hashSizeInWords -  hash size (valid values: 4W, 8W)
 *
 * @return DxError_t - On success the value DX_SUCCESS is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_ReadHASHPubKey(uint32_t pubKeyIndex, HASH_Result_t PubKeyHASH, uint32_t hashSizeInWords)
{
    DxError_t error = DX_SUCCESS;
    int i;

    error = DX_SBRT_GetPubKeyHash(pubKeyIndex, PubKeyHASH, hashSizeInWords);
    if (error != DX_SUCCESS)
        return error;

    for (i = 0; i < hashSizeInWords; i++) {
        PubKeyHASH[i] = UTIL_REVERT_UINT32_BYTES(PubKeyHASH[i]);
    }

    return error;
}

/*
 * @brief The NVM_ReadAESKey function is a NVM interface function -
 *        The function retrieves the AES CTR 128 bit key from the NVM
 *
  @param[out] AESKey   -  Kce from OTP for SW image decryption
 *
 * @return DxError_t - On success the value DX_SUCCESS is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_ReadAESKey(AES_Key_t AESKey)
{
    DxError_t error = DX_SUCCESS;
    int i;

    error = DX_SBRT_GetCodeEncryptionKey(AESKey);
    for (i = 0; i < AES_KEY_SIZE_IN_WORDS; i++) {
        AESKey[i] = UTIL_REVERT_UINT32_BYTES(AESKey[i]);
    }

    return error;
}

#ifndef DX_OTP_SW_VERSION_NOT_SUPPORTED
/*
 * @brief The NVM_GetSwVersion function is a NVM interface function -
 *        The function retrieves the SW version from the SRAM/NVM.
 *        In case of OTP, we support up to 16 anti-rollback counters (taken from the certificate)
 *
 * @param[in] counterId -  relevant only for OTP (valid values: 1,2)
 *
 * @param[out] swVersion   -  the minimum SW version
 *
 * @return DxError_t - On success the value DX_SUCCESS is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_GetSwVersion(DxSbSwVersionId_t counterId, uint32_t *swVersion)
{
    uint32_t swVersionNum = 0;
    DxError_t error       = DX_SUCCESS;

    /* get FW minimum version according to counter ID */
    error = DX_SBRT_GetSwVersion(counterId, &swVersionNum);
    if (error)
        return error;

    *swVersion = swVersionNum;

    return error;
}

/*
 * @brief The NVM_SetSwVersion function is a NVM interface function -
 *        The function writes the SW version into the SRAM/NVM.
 *       In case of OTP, we support up to 16 anti-rollback counters (taken from the certificate)
 *
 * @param[in] counterId -  relevant only for OTP (valid values: 1,2)
 *
 * @param[in] swVersion   -  the minimum SW version
 *
 * @return DxError_t - On success the value DX_SUCCESS is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_SetSwVersion(DxSbSwVersionId_t counterId, uint32_t swVersion)
{
    DxError_t error = DX_SUCCESS;
    uint32_t otpVer = 0;

    /* Set SW version according to counter ID */
    error = DX_SBRT_SetSwVersion(counterId, swVersion);
    if (error)
        return error;

    /* Verify that version was witten correctly */
    error = DX_SBRT_GetSwVersion(counterId, &otpVer);
    if (error)
        return error;
    if (otpVer != swVersion)
        return DX_BOOT_IMG_VERIFIER_OTP_VERSION_FAILURE;

    return error;
}

#endif
