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

#ifndef _BOOT_IMAGES_VERIFIER_API_H
#define _BOOT_IMAGES_VERIFIER_API_H

#ifdef __cplusplus
extern "C" {
#endif

/* ----------------------------
      PUBLIC FUNCTIONS
----------------------------------- */

/*
 * @brief This is the initialization function. must be called at the beginning of the SB process.
 *        The function initializes the internal data fields.
 *
 *
 * @param[in/out] certPkgData - certificate data structure
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from bootimagesverifier_error.h
 */
DxError_t DX_SBRT_CertChainVerificationInit(DxSbCertInfo_t *certPkgInfo);

/*
 * @brief This function verifies a given certificate (either key certificate or content certificate)
 *        The function verifies the following:
 *        1. The public key as saved in the certificate versus the HASHd public key that is saved in the NVM/OTP (or
 * given in certPkgInfo)
 *        2. The RSA signature
 *        3. The SW version (in the certificate) that should be bigger than the otp minimum sw version
 *        4. Each of the SW components HASH (in case of content certificate)
 *
 *
 * @param[in] flashRead_func - User's Flash read function used to read data from the flash to memory location
 * @param[in] userContext - User's context for the usage of flashRead_func
 * @param[in] certPtr - pointer to certificate
 * @param[in] certSize - size of the certificate
 * @param[in/out] certPkgInfo - public key hash (in or out)
 * @param[in] workspace_ptr - temporary buffer to load the certificate and SW components to
 * @param[in] workspaceSize - the temporary buffer size in bytes
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from bootimagesverifier_error.h
 */
DxError_t DX_SBRT_CertVerifySingle(DxSbFlashReadFunc flashReadFunc, void *userContext, uint8_t *certPtr,
                                   uint32_t certSize, DxSbCertInfo_t *certPkgInfo, uint32_t *pWorkspace,
                                   uint32_t workspaceSize);

/*
 * @brief This function returns the size in words of a certificate
 *        The function verifies the following:
 *        1. That certificate header , and certicate type are valid
 *
 *
 * @param[in] pCert - the certificate address (after it has been loaded to memory)
 * @param[out] pCertSizeWords - pointer that returns certificate size in words
 *
 * @return DxError_t - On success the value DX_OK is returned,
 *         on failure - a value from bootimagesverifier_error.h
 */
DxError_t DX_SBRT_GetCertSize(uint32_t *pCert, uint32_t *pCertSizeWords);

#ifdef __cplusplus
}
#endif

#endif
