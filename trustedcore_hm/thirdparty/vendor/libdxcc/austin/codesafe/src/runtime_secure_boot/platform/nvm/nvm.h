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

#ifndef _NVM__H
#define _NVM__H

#ifdef __cplusplus
extern "C" {
#endif

#include "dx_crypto_boot_defs.h"
/* ------------------------------------
    DEFS
------------------------------------- */

/*
 * @brief This function reads the LCS
 *
 * @param[in/out] lcs_ptr  -pointer to memory to store the LCS
 *
 * @return DxError_t - On success the value DX_OK is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_ReadRKEK(uint8_t *rkek_ptr);

/*
 * @brief The NVM_ReadHASHPubKey function is a NVM interface function -
 *        The function retrieves the HASH of the device Public key (N & E) from the SRAM/NVM
 *        In case the flag DX_NO_PUB_KEY_VERIFICATION is set the function will return a
 *        constant pre-defined value.
 *
 * @param[in] pubKeyIndex -  Index of HASH in the OTP
 *
 * @param[out] PubKeyHASH   -  the public key HASH.
 *
 * @param[in] hashSizeInWords -  hash size (valid values: 4W, 8W)
 *
 * @return DxError_t - On success the value DX_OK is returned, and on failure   -a value from NVM_error.h
 */

DxError_t NVM_ReadHASHPubKey(uint32_t pubKeyIndex, HASH_Result_t PubKeyHASH, uint32_t hashSizeInWords);

/*
 * @brief The NVM_GetSwVersion function is a NVM interface function -
 *        The function retrieves the SW version from the SRAM/NVM.
 *       In case of OTP, we support up to 16 anti-rollback counters (taken from the certificate)
 *
 *
 * @param[in] counterId -  relevant only for OTP (valid values: 1,2)
 *
 * @param[out] swVersion   -  the minimum SW version
 *
 * @return DxError_t - On success the value DX_OK is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_GetSwVersion(DxSbSwVersionId_t counterId, uint32_t *swVersion);

/*
 * @brief The NVM_SetSwVersion function is a NVM interface function -
 *        The function writes the SW version into the SRAM/NVM.
 *       In case of OTP, we support up to 16 anti-rollback counters (taken from the certificate)
 *
 *
 * @param[in] counterId -  relevant only for OTP (valid values: 1,2)
 *
 * @param[in] swVersion   -  the minimum SW version
 *
 * @return DxError_t - On success the value DX_OK is returned, and on failure   -a value from NVM_error.h
 */
DxError_t NVM_SetSwVersion(DxSbSwVersionId_t counterId, uint32_t swVersion);

/*
 * @brief The GEN_SelectPubKey function selects the public key according to the ROM selector value.
 *
 *        N_ptr is changed to the selected key in the ROM array.
 *
 *
 */
void NVM_SelectPubKey(unsigned long hwBaseAddress, uint32_t **N_ptr); // check

#ifdef __cplusplus
}
#endif

#endif
