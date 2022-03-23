/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_PKI_COMMON_H
#define H_CMSCBB_PKI_COMMON_H
#include "../cmscbb_common/cmscbb_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Prototype    : CmscbbPkiInit
 * Description  : Initialize PKI context.
 * Params
 *   [IN] pVrf: PKI context
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:20  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbPkiInit(CMSCBB_VRF* pVrf);

/*
 * Prototype    : CmscbbPkiStoreAddCert
 * Description  : Add certificate into store
 * Params
 *   [IN] pVrf: PKI context
 *   [IN] pCert: Add certificate pointer
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:21  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbPkiStoreAddCert(const CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert);

/*
 * Prototype    : CmscbbPkiStoreAddCrl
 * Description  : Add CRL into store.
 * Params
 *   [IN] pVrf: PKI context
 *   [IN] pCrl: Add CRL pointer
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:22  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbPkiStoreAddCrl(const CMSCBB_VRF* pVrf, CmscbbX509Crl* pCrl);

/*
 * Prototype    : CmscbbPkiVerifyCert
 * Description  : Verify a certificate
 * Params
 *   [IN] pVrf: PKI context
 *   [IN] pCert: Verify certificate pointer
 *   [OUT] result: Verify result
 * Return Value : CMSCBB_ERROR_CODE
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:23  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbPkiVerifyCert(CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert, CVB_BOOL reset_depth, CVB_BOOL isTsRelative, CVB_BOOL* result);

/*
 * Prototype    : CmscbbPkiFindCertByIssuerSn
 * Description  : Find the certificate from store by name and serial number.
 * Params
 *   [IN] pVrf: PKI context
 *   [IN] issuer: Certificate name pointer
 *   [IN] sn:  Certificate serial number pointer
 * Return Value : matched certificate, or CVB_NULL if not found.
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:24  t00307193  Create
 */
CmscbbX509Cert* CmscbbPkiFindCertByIssuerSn(const CMSCBB_VRF* pVrf, const CmscbbX509Name* issuer, const CmscbbAsnBigint* sn);

/*
 * Prototype    : CmscbbPkiFindCrlIssuer
 * Description  : Find author certificate of the CRL.
 * Params
 *   [IN] pVrf: PKI context
 *   [IN] pCrl: CRL pointer
 * Return Value : The author certificate, or CVB_NULL if not found
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:25  t00307193  Create
 */
CmscbbX509Cert* CmscbbPkiFindCrlIssuer(const CMSCBB_VRF* pVrf, const CmscbbX509Crl* pCrl);

/*
 * Prototype    : CmscbbPkiUninit
 * Description  : Uninitialize the PKI context.
 * Params
 *   [IN] pVrf: PKI context
 * Return Value : CVB_VOID
 * History      
 *   Date              Author     Modification
 *   2015/11/10 17:27  t00307193  Create
 */
CVB_VOID CmscbbPkiUninit(CMSCBB_VRF* pVrf);


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !H_CMSCBB_PKI_COMMON_H */
