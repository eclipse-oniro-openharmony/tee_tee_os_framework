/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_X509_H
#define H_CMSCBB_X509_H
#include "../cmscbb_common/cmscbb_list.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CMSCBB_X509_KU_ENCIPHER_ONLY 0x0001
#define CMSCBB_X509_KU_CRL_SIGN      0x0002
#define CMSCBB_X509_KU_KEY_CERT_SIGN 0x0004
#define CMSCBB_X509_KU_KEY_AGREEMENT 0x0008
#define CMSCBB_X509_KU_DATA_ENCIPHERMENT 0x0010
#define CMSCBB_X509_KU_KEY_ENCIPHERMENT  0x0020
#define CMSCBB_X509_KU_NON_REPUDIATION   0x0040
#define CMSCBB_X509_KU_DIGITAL_SIGNATURE 0x0080
#define CMSCBB_X509_KU_DECIPHER_ONLY 0x0100

#define CMSCBB_PKI_XKU_SSL_SERVER 0x01
#define CMSCBB_PKI_XKU_SSL_CLIENT 0x02
#define CMSCBB_PKI_XKU_SMIME      0x04
#define CMSCBB_PKI_XKU_CODE_SIGN  0x08
#define CMSCBB_PKI_XKU_SGC       0x10
#define CMSCBB_PKI_XKU_OCSP_SIGN 0x20
#define CMSCBB_PKI_XKU_TIMESTAMP 0x40
#define CMSCBB_PKI_XKU_IPSECIKE  0x80
#define CMSCBB_PKI_XKU_ANYEXTENDEDKEYUSAGE 0x100

#define CMSCBB_X509_EXT_KU_CODE_SIGNING (CMSCBB_X509_KU_DIGITAL_SIGNATURE)
#define CMSCBB_X509_EXT_KU_TIMESTAMP_OCSPSIGNING  (CMSCBB_X509_KU_DIGITAL_SIGNATURE | CMSCBB_X509_KU_NON_REPUDIATION)

/*
 * Prototype    : CmscbbX509IsSelfSigned
 * Description  : Check if the certificate is self signed.
 * Params
 *   [IN] pCert: X509 certificate
 *   [OUT] isSelfSigned: selfsigned or not
 * Return Value : CMSCBB_ERROR_CODE
 * History
 *   Date              Author     Modification
 *   2015/11/10 17:14  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbX509IsSelfSigned(CmscbbX509Cert* pCert, CVB_BOOL* isSelfSigned);

/*
 * Prototype    : CmscbbX509DecodeCert
 * Description  : decode DER encoded certificate
 * Params
 *   [IN] pbEncodedCert: encode certificate 
 *   [IN] nEncodedLength: the length of encode certificate
 *   [OUT] ppCert: X509 certificate
 *   [OUT] bytesDecoded: bytes decode from pbEncodedCert
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 16:02  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbX509DecodeCert(const CVB_BYTE* pbEncodedCert, CVB_UINT32 nEncodedLength, CmscbbX509Cert** ppCert, CVB_UINT32* bytesDecoded);

/*
 * Prototype    : CmscbbX509FreeCert
 * Description  : free certificate structure
 * Params
 *   [IN] pCert: X509 certificate
 * Return Value : CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 16:08  t00307193  Create
 */
CVB_VOID CmscbbX509FreeCert(CmscbbX509Cert* pCert);

/*
 * Prototype    : CmscbbX509DecodeCrl
 * Description  : decode DER encoded CRL
 * Params
 *   [IN] pbEncodedCrl: encode crl
 *   [IN] nEncodedLen: length of encode crl
 *   [OUT] ppCrl: X509 crl
 *   [OUT] bytesDecoded: bytes decode from pbEncodedCrl
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 16:09  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbX509DecodeCrl(const CVB_BYTE* pbEncodedCrl, CVB_UINT32 nEncodedLen, CmscbbX509Crl** ppCrl, CVB_UINT32* bytesDecoded);

/*
 * Prototype    : CmscbbX509FreeCrl
 * Description  : free crl structure
 * Params
 *   [IN] pCrl: ppCrl: X509 crl
 * Return Value : CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 17:04  t00307193  Create
 */
CVB_VOID CmscbbX509FreeCrl(CmscbbX509Crl* pCrl);

/*
 * Prototype    : CmscbbCompareX509Name
 * Description  : Compare two x509 name to get if they are identical.
 * Params
 *   [IN] pNameExpect: Expect X509 name
 *   [IN] pNameActual: Actual X509 name
 * Return Value : CVB_SUCCESS if identical, otherwise not.
 *   Date              Author     Modification
 *   2015/11/10 15:17  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbCompareX509Name(const CmscbbX509Name* pNameExpect, const CmscbbX509Name* pNameActual);

/*
 * Prototype    : CmscbbX509ExtractPublicKey
 * Description  : Get public key data blob from certificate.
 * Params
 *   [IN] pCert: X509 certificate
 *   [OUT] e: a big int
 *   [OUT] n: another big int
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 15:27  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbX509ExtractPublicKey(const CmscbbX509Cert* pCert, CmscbbBigInt* e, CmscbbBigInt* n);

/*
 * Prototype    : CmscbbX509PubKeyVerify
 * Description  : <TODO>
 * Params
 *   [IN] pbSrc: src content
 *   [IN] nSrc: src content length
 *   [IN] pbSig:  signed content
 *   [IN] nSig: length of  signed content
 *   [IN] pPubKey: public key
 *   [IN] hashAlgo: asn object id
 *   [IN] pResult:result if success  return CVB_SUCCESS
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/12/21 9:57  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbX509PubKeyVerify(const CVB_BYTE* pbSrc, CVB_UINT32 nSrc, const CVB_BYTE* pbSig, CVB_UINT32 nSig, const CmscbbX509PublicKey* pPubKey, const CmscbbAsnOid* algoId, CVB_BOOL* pResult);

/*
 * Prototype    : CmscbbConvertFromX509Name
 * Description  : <TODO>
 * Params
 *   [IN] pName: X509 Name
 *   [OUT] pszReadableName: convert from pName
 *   [OUT] pNameLen: length of pszReadableName
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/08/17 9:55  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbConvertFromX509Name(const CmscbbX509Name* pName, CVB_CHAR** pszReadableName, CVB_UINT32* pNameLen);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* H_CMSCBB_X509_H */
