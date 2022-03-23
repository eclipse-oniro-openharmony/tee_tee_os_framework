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

#ifndef _COMMON_CRYPTO_X509_H
#define _COMMON_CRYPTO_X509_H

#include <stdint.h>
#include "dx_crypto_x509_defs.h"

/*
 * @brief free X509 certificate
 *
 * @param[in/out] ppCertBuff          - x.509 certificate
 */
/* ****************************************************** */
int32_t DX_Common_x509_free(uint8_t **ppCertBuff);

/*
 * @brief Creates X509 certificate and set its header fields
 *
 * @param[in/out] ppCertBuff     - x.509 certificate
 * @param[in] certType           - certificate type
 */
/* ****************************************************** */
int32_t DX_Common_x509_CreateAndSetHeader(uint8_t **ppCertBuff, DxX509CertType_t certType);

/*
 * @brief Add ASN.1 critical integer extension to X.509V3 certificate
 *
 * @param[in/out] pCertBuff          - x.509 certificate
 * @param[in] certType                 - certificate type
 * @param[in] extType                 - extension type
 * @param[in] val                 - Extension value
 */
/* ****************************************************** */
int32_t DX_Common_x509_AddIntegerExtension(uint8_t *pCertBuff, DxX509CertType_t certType, DxX509ExtType_t extType,
                                           int32_t val);

/*
 * @brief Add critical DER extension to X.509V3 certificate
 *
 * @param[in/out] pCertBuff          - x.509 certificate
 * @param[in] certType                 - certificate tyoes
 * @param[in] extType                 - extension type
 * @param[in] pVal                 - Extension data
 * @param[in] valLen                 - extension data length
 */
/* ****************************************************** */
int32_t DX_Common_x509_AddStringExtension(uint8_t *pCertBuff, DxX509CertType_t certType, DxX509ExtType_t extType,
                                          uint8_t *pVal, uint32_t valLen);

/*
 * @brief Add subject public key to the X509 certificate
 *     and sign the certificate
 *
 * @param[in/out] pCertBuff      - x.509 certificate
 * @param[in] pKeyPairFileName   - key pair file name in PEM format
 * @param[in] pKeyPairPwd       - passphrase of key pair
 */
/* ****************************************************** */
int32_t DX_Common_x509_SetKeyAndSign(uint8_t *pCertBuff, uint8_t *pKeyPairFileName, uint8_t *pKeyPairPwd);

/*
 * @brief Add subject public key to the X509 certificate
 *     sign the certificate
 *
 * @param[in/out] ppCertBuff      - x.509 certificate
 * @param[in] certType           - certificate type
 * @param[in] pKeyPairFileName   - key pair file name in PEM format
 * @param[in] pKeyPairPwd       - passphrase of key pair
 * @param[out] pOutCertSize     - certificate size in PEM format
 */
/* ****************************************************** */
int32_t DX_Common_x509_ResignAndPem(uint8_t **pCertBuff, DxX509CertType_t certType, uint8_t *pKeyPairFileName,
                                    uint8_t *pKeyPairPwd, uint32_t *pOutCertSize);

/*
 * @brief build package for the certificate
 *
 * @param[in] ppCertBuff          - the x509 certificate  in PEM format
 * @param[in] certSize         - certificate size
 * @param[in] certType           - certificate type
 * @param[in] encFlag           - indicates whether images were encrypted
 * @param[in] hbkType           - hbk type to use by target, in the verification
 * @param[in] pAddData        - additional data to add to package
 * @param[in] addDataSize        - length of additional data
 * @param[in] outPkgFile        - package file name to write the package to
 */
/* ****************************************************** */
int32_t DX_Common_x509_BuildCertPkg(uint8_t **ppCertBuff, uint32_t certSize, DxX509CertType_t certType, uint8_t encFlag,
                                    uint8_t hbkType, uint8_t *pAddData, uint32_t addDataSize, uint8_t *outPkgFile);

#endif
