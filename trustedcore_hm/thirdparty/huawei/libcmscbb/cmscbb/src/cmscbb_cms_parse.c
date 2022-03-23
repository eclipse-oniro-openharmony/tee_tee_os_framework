/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../cms/cmscbb_cms_parse.h"
#include "../cmscbb_common/cmscbb_list.h"
#include "../asn1/cmscbb_asn1_decode.h"
#include "../x509/cmscbb_x509.h"

 /*
  * Prototype    : InternalDecodeCert
  * Description  : Decode certificate in CMS
  * Params
  *   [IN] pAsnOcts: asn objects
  *   [OUT] ppCert: X509 certificates
  *   [OUT] bytesDecoded: decoded result
  * Return Value : CMSCBB_ERROR_CODE
  *   Date              Author     Modification
  *   2015/11/10 20:16  t00307193  Create
  */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodeCertByAsnOcts(const CmscbbAsnOcts* pAsnOcts, CmscbbX509Cert** ppCert, CVB_UINT32* bytesDecoded)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_BER_TAG tagExpect;

    tagExpect.cls = g_itemCmscbbX509Cert.ber_class;
    tagExpect.form = g_itemCmscbbX509Cert.ber_form;
    tagExpect.code = g_itemCmscbbX509Cert.ber_code;

    if (CmscbbMemCmp(&(tagExpect), &(pAsnOcts->tag), sizeof(CMSCBB_BER_TAG)) != 0) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CERT_DECODE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_DECODE);
    }

    ret = CmscbbX509DecodeCert(pAsnOcts->octs, pAsnOcts->len, ppCert, bytesDecoded);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalDecodeCert
 * Description  : Decode certificate in CMS
 * Params
 *   [IN] pRawCerts:X509 certificate raw bundle
 *   [IN] pCerts: X509 certificates
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 20:16  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodeCert(const CmscbbX509CertRawBundle* pRawCerts, CmscbbX509CertBundle* pCerts)
{
    CMSCBB_ERROR_CODE ret = 0;
    CVB_INT iter;

    for (iter = 0; iter < (CVB_INT)pRawCerts->bundle.num; ++iter) {
        CmscbbX509Cert* pCert = CVB_NULL;
        CVB_UINT32 nDecoded = 0;
        ret = InternalDecodeCertByAsnOcts(&(pRawCerts->bundle.data[iter]), &pCert, &nDecoded);
        if (CVB_FAILED(ret)) {
            CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_DECODE, "");
            break;
        }

        ret = CMSCBB_LIST_ADD(&(pCerts->certs), pCert);
        if (CVB_FAILED(ret)) {
            CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_DECODE, "");
            CmscbbX509FreeCert(pCert);
            break;
        }
    }

    if (ret != CVB_SUCCESS) {
        CMSCBB_LIST_FREE(pCerts, CmscbbX509FreeCert);
        return CMSCBB_ERR_PKI_CMS_DECODE;
    }

    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbPkcs7DecodeSigned(const CVB_BYTE* pbEncodedP7, CVB_UINT32 nEncodedLength, CmscbbPkcs7Content** ppSign, CVB_UINT32* bytesDecoded)
{
    CmscbbPkcs7Content* pDest = CVB_NULL;
    CMSCBB_ERROR_CODE ret;
    CmscbbX509CertRawBundle* pRawCerts = CVB_NULL;

    if (pbEncodedP7 == CVB_NULL || nEncodedLength == 0 || ppSign == CVB_NULL || bytesDecoded == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    ret = CmscbbAsnDecode(pbEncodedP7, nEncodedLength, &g_itemCmscbbPkcs7Content, CVB_ASN_NORMAL, (CVB_VOID**)(&pDest), bytesDecoded);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CMS_DECODE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_DECODE);
    }

    pRawCerts = &(pDest->signed_data.raw_certs);
    if (pRawCerts->bundle.num > 0) {
        ret = InternalDecodeCert(pRawCerts, &(pDest->signed_data.certificates));
        if (CVB_FAILED(ret)) {
            CmscbbPkcs7FreeSigned(pDest);
            return CMSCBB_ERR_PKI_CMS_DECODE;
        }
    }
#ifdef CVB_DEBUG
    CVB_INT iter;
    for (iter = 0; iter < (CVB_INT)pDest->signed_data.signer_infos.infos.num; ++iter) {
        CmscbbPkcs7SignedInfo* si = &(pDest->signed_data.signer_infos.infos.data[iter]);
        CVB_UINT32 name_len = 0;
        (CVB_VOID)CmscbbConvertFromX509Name(&(si->issuerSn.issuer), &si->_Issuer, &name_len);
    }
#endif /* CVB_DEBUG */

    *ppSign = (CmscbbPkcs7Content*)pDest;
    return CVB_SUCCESS;
}

CVB_VOID CmscbbPkcs7FreeSigned(CmscbbPkcs7Content* pSigned)
{
    if (pSigned == CVB_NULL) {
        return;
    }

#ifdef CVB_DEBUG
    CVB_INT iter;
    for (iter = 0; iter < (CVB_INT)pSigned->signed_data.signer_infos.infos.num; ++iter) {
        CmscbbPkcs7SignedInfo* si = &(pSigned->signed_data.signer_infos.infos.data[iter]);
        CmscbbFree(si->_Issuer);
    }
#endif /* CVB_DEBUG */

    CMSCBB_LIST_FREE(&(pSigned->signed_data.certificates.certs), CmscbbX509FreeCert);

    CmscbbAsnFree(pSigned, &g_itemCmscbbPkcs7Content, CVB_ASN_NORMAL);
}
