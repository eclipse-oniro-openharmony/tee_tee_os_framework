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

#ifndef _SECURE_BOOT_BASE_FUNC_H
#define _SECURE_BOOT_BASE_FUNC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "crypto_driver_defs.h"
#include "secureboot_defs.h"
#include "cc_plat.h"

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/*
 * @brief This function calculates the HASH over the PubKey (N, big endian) || Np (reversed - little endian).
 *
 * @param[in] NAndRevNp_ptr - pointer to N public key and Np in the certificate
 * @param[out] hashResult - a pointer to HASH of the public key
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DX_SB_CalcPublicKeyHASH(uint32_t *NAndRevNp_ptr, HASH_Result_t hashResult);

/*
 * @brief This function calculates the HASH over the PubKey (N, big endian) || Np (reversed - little endian).
 *        The function gets the Public key pointer and Np (Barrett n value) from the certificate calculates hash on it
 * and compare it to the HASH from the OTP/NVM.
 *
 * @param[in] NAndRevNp_ptr - pointer to N public key and Np in the certificate
 * @param[in] NHASH_ptr - a pointer to HASH of the public key
 * @param[in] HashSize - hash size (to compare)
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DX_SB_CalcPublicKeyHASHAndCompare(uint32_t *NAndRevNp_ptr, HASH_Result_t NHASH_ptr, uint32_t HashSize);

/*
 * @brief This function calculates the HASH over the given data and than verify
 *       RSA signature on that hashed data
 *
 * @param[in] pData - pointer to the data to be verified
 * @param[in] pNParams - a pointer to the public key parameters
 * @param[in] pSignature - a pointer to the signature structure
 * @param[in] sizeOfData - size of the data to calculate the HASH on (in bytes)
 * @param[in] RSAAlg - RSA algorithm to use
 * @param[in] workspace_ptr - pointer ro workspace buffer
 * @param[in] workspaceSize - workspzace size
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */
DxError_t DX_SB_VerifySignature(uint32_t *pData, DxSbNParams_t *pNParams, DxSbSignature_t *pSignature,
                                uint32_t sizeOfData, DxSbRsaAlg_t RSAAlg, uint32_t *workspace_ptr,
                                uint32_t workspaceSize);

/*
 * @brief This function load the SW component to RAM, calculates HASH on it and compares the
 *        result with the given HASH (taken from the certificate).
 *        This function calculates the HASH simultaneously to reading data from the Flash.
 *
 *
 * @param[in] preHashflashRead_func - User's Flash read function used to read data from the flash to memory location.
 *          this is the first function used (before the hash)
 * @param[in] preHashUserContext - User's context for the usage of preHashflashRead_func
 * @param[in] hashOutputSize - hash output size (defined according to given HASH algorithm) in bytes
 * @param[in] recHashData_ptr - a pointer to record hash data and memory load address
 * @param[in] recAddInfo_ptr - a pointer to record data (storage address and length)
 * @param[in] aesKey - pointer to code encryption key for sw component
 * @param[in] isSwComponentEncrypted - indicator if SW image is encrypted
 * @param[in] nonce - nonce used in composing iv for sw components decryption
 * @param[out] swCompLoadAddress - the final address that the sw comp was loaded to
 * @param[in] workspace_ptr - temporary buffer to load the SW components to (SW components without
 *            loading address).
 * @param[in] workspaceSize - the temporary buffer size in bytes, minimal allowed size is
 *            DX_DOUBLE_BUFFER_MAX_SIZE_IN_BYTES
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from BootImagesVerifier_error.h
 */

DxError_t DX_SB_CalcHASHOnSWRecDecryptAndCompare(DxSbFlashReadFunc preHashflashRead_func, void *preHashUserContext,
                                                 uint32_t hashOutputSize, uint32_t *recHashData_ptr,
                                                 uint32_t *recAddInfo_ptr, AES_Key_t *aesKey,
                                                 uint8_t isSwComponentEncrypted, DxSbNonce_t nonce,
                                                 uint32_t *workspace_ptr, uint32_t workspaceSize);

/* !
 * @brief verify NV counter extension against OTP
 *
 * @param[in] pCertNvCounter    - NV counter fields read from certificate
 * @param[in] initFlag        - initial flag - is set to 0 if its the first certificate.
 * @param[in] prevNvCounterId    - relevant only for chain verification - the previous sw id
 * @param[out] otpVersion    - the sw version saved in the otp
 *
 * @return uint32_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_SB_VerifyNvCounter(DxSbSwVersion_t *pCertNvCounter, uint8_t initFlag, DxSbSwVersionId_t prevNvCounterId,
                                uint32_t *otpVersion);

/* !
 * @brief Set NV counter to the OTP (if needed)
 *
 * @param[in] pCertNvCounter    - NV counter fields read from certificate
 * @param[in] otpVersion    - the sw version saved in the otp
 *
 * @return uint32_t         - On success: the value DX_OK is returned,
 *                       On failure: a value from sbrom_management_error.h
 */
DxError_t DX_SB_SetNvCounter(DxSbSwVersion_t *pCertNvCounter, uint32_t otpVersion);

#ifdef __cplusplus
}
#endif

#endif
