/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../x509/cmscbb_x509.h"
#include "../asn1/cmscbb_asn1_decode.h"
#include "../asn1/cmscbb_asn1_utils.h"

CMSCBB_ERROR_CODE CmscbbX509IsSelfSigned(CmscbbX509Cert *pCert, CVB_BOOL *isSelfSigned)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BOOL verify_result = CVB_FALSE;

    if (pCert == CVB_NULL || isSelfSigned == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    *isSelfSigned = CVB_FALSE;
    /* check if the certificate already verified */
    if (pCert->pIssuer == pCert) {
        *isSelfSigned = CVB_TRUE;
        return CVB_SUCCESS;
    }

    /* name check */
    if (CmscbbCompareX509Name(&(pCert->toBeSigned.subject), &(pCert->toBeSigned.issuer)) != 0) {
        return CVB_SUCCESS;
    }

    ret = CmscbbX509PubKeyVerify(pCert->rawSigned.octs, pCert->rawSigned.len, pCert->signature.octs,
        pCert->signature.len, &pCert->toBeSigned.subjectPubKey.subjectPublicKey,
        &(pCert->algorithm.algorithm), &verify_result);

    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* set the issuer if verify passed */
    if (verify_result == CVB_TRUE) {
        *isSelfSigned = CVB_TRUE;
        pCert->pIssuer = pCert;
    } else {
        *isSelfSigned = CVB_FALSE;
    }
    return CVB_SUCCESS;
}

#ifdef CVB_DEBUG
CVB_VOID InternalExtractCertName(CmscbbX509Cert *pDest)
{
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 name_len = 0;

    if (pDest == CVB_NULL) {
        return;
    }

    ret = CmscbbConvertFromX509Name(&(pDest->toBeSigned.issuer), &(pDest->toBeSigned._Issuer), &name_len);
    if (CVB_FAILED(ret)) {
        CVB_LOG_WARNING(ret, CVB_NULL);
    }
    ret = CmscbbConvertFromX509Name(&(pDest->toBeSigned.subject), &(pDest->toBeSigned._Subject), &name_len);
    if (CVB_FAILED(ret)) {
        CVB_LOG_WARNING(ret, CVB_NULL);
    }
}
#endif /* CVB_DEBUG */

CMSCBB_ERROR_CODE CmscbbX509DecodeCert(const CVB_BYTE *pbEncodedCert, CVB_UINT32 nEncodedLength, CmscbbX509Cert **ppCert, CVB_UINT32 *bytesDecoded)
{
    CmscbbX509Cert *pDest = CVB_NULL;
    CMSCBB_ERROR_CODE ret;

    if (pbEncodedCert == CVB_NULL || nEncodedLength == 0 || ppCert == CVB_NULL || bytesDecoded == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = CmscbbAsnDecode(pbEncodedCert, nEncodedLength, &g_itemCmscbbX509Cert, CVB_ASN_NORMAL, (CVB_VOID **)(&pDest), bytesDecoded);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

#ifdef CVB_DEBUG
    InternalExtractCertName(pDest);
#endif /* CVB_DEBUG */

    pDest->iRef = 1;
    *ppCert = pDest;

    return CVB_SUCCESS;
}

CVB_VOID CmscbbX509FreeCert(CmscbbX509Cert *pCert)
{
    if (pCert == CVB_NULL) {
        return;
    }

    --pCert->iRef;
    if (pCert->iRef <= 0) {
#ifdef CVB_DEBUG
        CmscbbFree(pCert->toBeSigned._Issuer);
        CmscbbFree(pCert->toBeSigned._Subject);
#endif /* CVB_DEBUG */

        CmscbbAsnFree(pCert, &g_itemCmscbbX509Cert, CVB_ASN_NORMAL);
    }
}

CMSCBB_ERROR_CODE CmscbbX509DecodeCrl(const CVB_BYTE *pbEncodedCrl, CVB_UINT32 nEncodedLen, CmscbbX509Crl **ppCrl, CVB_UINT32 *bytesDecoded)
{
    CmscbbX509Crl *pDest = CVB_NULL;
    CMSCBB_ERROR_CODE ret;

    if (pbEncodedCrl == CVB_NULL || nEncodedLen == 0 || ppCrl == CVB_NULL || bytesDecoded == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = CmscbbAsnDecode(pbEncodedCrl, nEncodedLen, &g_itemCmscbbX509Crl, CVB_ASN_NORMAL, (CVB_VOID **)(&pDest), bytesDecoded);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

#ifdef CVB_DEBUG   
    CVB_UINT32 name_len = 0;
    (CVB_VOID)CmscbbConvertFromX509Name(&(pDest->tbsCertList.issuer), &(pDest->tbsCertList._Issuer), &name_len);   
#endif /* CVB_DEBUG */

    pDest->iRef = 1;
    *ppCrl = pDest;
    return CVB_SUCCESS;
}

CVB_VOID CmscbbX509FreeCrl(CmscbbX509Crl *pCrl)
{
    if (pCrl == CVB_NULL) {
        return;
    }

    --pCrl->iRef;
    if (pCrl->iRef <= 0) {
#ifdef CVB_DEBUG
        CmscbbFree(pCrl->tbsCertList._Issuer);
#endif
        CmscbbAsnFree(pCrl, &g_itemCmscbbX509Crl, CVB_ASN_NORMAL);
    }
}

CMSCBB_ERROR_CODE CmscbbCompareX509Name(const CmscbbX509Name *pNameExpect, const CmscbbX509Name *pNameActual)
{
    CVB_INT iter;

    if (pNameExpect == CVB_NULL || pNameActual == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    if (pNameExpect->names.num != pNameActual->names.num) {
        CVB_LOG_DEBUG(CMSCBB_ERR_UNDEFINED, CVB_NULL);
        return (CMSCBB_ERR_UNDEFINED);
    }

    for (iter = 0; iter != (CVB_INT)pNameActual->names.num; ++iter) {
        const CmscbbX509AttrBundle *pAttrExp = &(pNameExpect->names.data[iter]);
        const CmscbbX509AttrBundle *pAttrActual = &(pNameActual->names.data[iter]);

        if (CMSCBB_COMPARE_ASN_OID(&(pAttrExp->attrs.data[0].id), &(pAttrActual->attrs.data[0].id)) != 0) {
            CVB_LOG_DEBUG(CMSCBB_ERR_UNDEFINED, CVB_NULL);
            return (CMSCBB_ERR_UNDEFINED);
        }
        if (CmscbbCompareAsnOcts(&(pAttrExp->attrs.data[0].value), &(pAttrActual->attrs.data[0].value)) != 0) {
            CVB_LOG_DEBUG(CMSCBB_ERR_UNDEFINED, CVB_NULL);
            return (CMSCBB_ERR_UNDEFINED);
        }
    }

    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbX509ExtractPublicKey(const CmscbbX509Cert *pCert, CmscbbBigInt *e, CmscbbBigInt *n)
{
    CMSCBB_ERROR_CODE ret;
    const CmscbbRsaPublicKey *pRsaPubkey = CVB_NULL;

    if (pCert == CVB_NULL || e == CVB_NULL || n == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pRsaPubkey = &pCert->toBeSigned.subjectPubKey.subjectPublicKey.rsaPubKey;

    e->uiLength = pRsaPubkey->publicExponent.len;
    if (pRsaPubkey->publicExponent.len > CMSCBB_MAX_INT_DIGITS) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CERT_INVALID_CONTENT, CVB_NULL);
        return CMSCBB_ERR_PKI_CERT_INVALID_CONTENT;
    }
    ret = (CMSCBB_ERROR_CODE)memcpy_s(e->aVal, CMSCBB_MAX_INT_DIGITS, pRsaPubkey->publicExponent.octs, pRsaPubkey->publicExponent.len);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    n->uiLength = pRsaPubkey->modules.len;
    if (pRsaPubkey->modules.len > CMSCBB_MAX_INT_DIGITS) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CERT_INVALID_CONTENT, CVB_NULL);
        return CMSCBB_ERR_PKI_CERT_INVALID_CONTENT;
    }
    ret = (CMSCBB_ERROR_CODE)memcpy_s(n->aVal, CMSCBB_MAX_INT_DIGITS, pRsaPubkey->modules.octs, pRsaPubkey->modules.len);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    return CVB_SUCCESS;
}

#if defined(CVB_DEBUG) || CMSCBB_SUPPORT_CRL_COMPARE
#define CVB_MAX_ATTR_LEN 128

CVB_STATIC CVB_UINT32 InternalGetMaxAttrLen(CVB_UINT32 nAttrCap, CVB_UINT32 nPrefix, CVB_UINT32 nAttrLen)
{
    CVB_UINT32 ret = nAttrCap - nPrefix;
    if (nAttrLen >= ret) {
        CVB_LOG_WARNING(CMSCBB_ERR_SYS_STR, "attribute name too long, which is invalid.");
        return ret - 1;
    }

    return nAttrLen;
}

/*
 * Prototype    : InternalMakeReadableAttr
 * Description  : <TODO>
 * Params
 *   [IN] pszReadableAttr: readable attribute
 *   [IN] pAttr: X509 certificate attribute
 *   [IN] pszPrefix: prefix of pszReadableAttr
 * Return Value : CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 18:12  t00307193  Create
 */
CVB_STATIC CVB_VOID InternalMakeReadableAttr(CVB_CHAR *pszReadableAttr, CVB_UINT32 nAttrCap, const CmscbbX509AttrEntry *pAttr, const CVB_CHAR *pszPrefix)
{
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 nPrefix = CmscbbStrlen(pszPrefix);
    CVB_UINT32 nAttrLen;

    ret = (CMSCBB_ERROR_CODE)memcpy_s(pszReadableAttr, (CVB_SIZE_T)nAttrCap, pszPrefix, nPrefix);
    if (CVB_FAILED(ret)) {
        return;
    }

    nAttrLen = InternalGetMaxAttrLen(nAttrCap, nPrefix, pAttr->value.len);
    ret = (CMSCBB_ERROR_CODE)memcpy_s(pszReadableAttr + nPrefix, (CVB_SIZE_T)nAttrCap - nPrefix, pAttr->value.octs, nAttrLen);
    if (CVB_FAILED(ret)) {
        return;
    }

    pszReadableAttr[nPrefix + nAttrLen] = 0;
}

/*
 * Prototype    : InternalConvertFromNameAttribute
 * Description  : Convert name attribute to readable string
 * Params
 *   [IN] pAttr: X509 certificate attribute
 *   [IN] pszReadableAttr: readable attribute
 *   [IN] pAttrLen: length of attrbute bytes
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 19:05  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalConvertFromNameAttribute(const CmscbbX509AttrEntry *pAttr,
    CVB_CHAR *pszReadableAttr, CVB_UINT32 nAttrCap, const CVB_UINT32 *pAttrLen)
{
    CMSCBB_AOIDS attr_id;

    if (pAttr == CVB_NULL || pszReadableAttr == CVB_NULL || pAttrLen == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    attr_id = CmscbbFindAoid(&(pAttr->id));
    if (attr_id == AOID_UNKNOWN) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CERT_DECODE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_DECODE);
    } else if (attr_id == AOID_AT_COMMONNAME) {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"CN=");
    } else if (attr_id == AOID_AT_LOCALITYNAME) {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"L=");
    } else if (attr_id == AOID_AT_STATEORPROVINCENAME) {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"S=");
    } else if (attr_id == AOID_AT_ORGANIZATIONNAME) {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"O=");
    } else if (attr_id == AOID_AT_ORGANIZATIONALUNITNAME) {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"OU=");
    } else if (attr_id == AOID_AT_COUNTRYNAME) {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"C=");
    } else if (attr_id == AOID_PKCS9_AT_EMAILADDRESS) {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"E=");
    } else {
        InternalMakeReadableAttr(pszReadableAttr, nAttrCap, pAttr, (const CVB_CHAR *)"X=");
    }

    return CVB_SUCCESS;
}

#define CVB_MAX_X509_NAME_LEN MAX_ISSUER_NAME_LENGTH
CMSCBB_ERROR_CODE CmscbbConvertFromX509Name(const CmscbbX509Name *pName, CVB_CHAR **ppReadableName, CVB_UINT32 *pNameLen)
{
    CMSCBB_ERROR_CODE ret;
    CVB_INT iter;
    CVB_CHAR *pszName = CVB_NULL;

    if (pName == CVB_NULL || ppReadableName == CVB_NULL || pNameLen == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = CmscbbMallocWith0((CVB_VOID **)&pszName, CVB_MAX_X509_NAME_LEN);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    for (iter = 0; iter < (CVB_INT)pName->names.num; ++iter) {
        CVB_INT iterAttr;
        const CmscbbX509AttrBundle *pAttrs = &(pName->names.data[iter]);

        for (iterAttr = 0; iterAttr < (CVB_INT)pAttrs->attrs.num; ++iterAttr) {
            const CmscbbX509AttrEntry *pAttr = &(pAttrs->attrs.data[iterAttr]);
            CVB_CHAR szAttr[CVB_MAX_ATTR_LEN] = {0};
            CVB_UINT32 nAttrLen = 0;

            ret = InternalConvertFromNameAttribute(pAttr, szAttr, CVB_MAX_ATTR_LEN, &nAttrLen);
            CVB_GOTO_ERR_IF_FAIL(ret);

            if (CmscbbStrlen(pszName) + CmscbbStrlen(szAttr) + 1 >= CVB_MAX_X509_NAME_LEN) {
                break;
            }

            if (pszName[0] != 0) {
                ret = (CMSCBB_ERROR_CODE)strcat_s(pszName, CVB_MAX_X509_NAME_LEN, ",");
                CVB_GOTO_ERR_IF_FAIL(ret);
            }
            ret = (CMSCBB_ERROR_CODE)strcat_s(pszName, CVB_MAX_X509_NAME_LEN, szAttr);
            CVB_GOTO_ERR_IF_FAIL(ret);
        }
    }

    *ppReadableName = pszName;
    *pNameLen = CmscbbStrlen(pszName);
    goto CVB_FINAL;
CVB_ERR:
    CmscbbFree(pszName);
CVB_FINAL:
    return ret;
}
#endif

/*
 * Prototype    : InternalGetBigIntFromOcts
 * Description  : get big int from  asn object
 * Params
 *   [OUT] e: a big int get from asn big int
 *   [IN] pAsnBigint: asn object stored big int
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 19:06  t00307193  Create
 */
#define LENGTH_EXPONENT 3
CVB_STATIC CMSCBB_ERROR_CODE InternalGetBigIntFromOcts(CmscbbBigInt *e, const CmscbbAsnBigint *pAsnBigint)
{
    CMSCBB_ERROR_CODE ret;

    if (CMSCBB_MAX_INT_DIGITS < pAsnBigint->len) {
        CVB_LOG_ERROR1(CMSCBB_ERR_UNDEFINED, "Unsupported key length %d", pAsnBigint->len << LENGTH_EXPONENT);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    e->uiLength = pAsnBigint->len;
    if (pAsnBigint->len > CMSCBB_MAX_INT_DIGITS) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CERT_INVALID_CONTENT, CVB_NULL);
        return CMSCBB_ERR_PKI_CERT_INVALID_CONTENT;
    }
    ret = (CMSCBB_ERROR_CODE)memcpy_s(e->aVal, CMSCBB_MAX_INT_DIGITS, pAsnBigint->octs, pAsnBigint->len);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    return CVB_SUCCESS;
}

CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParmX509PKeyVerify(const CVB_BYTE *pbSrc, const CVB_BYTE *pbSig, const CmscbbX509PublicKey *pPubKey, const CVB_BOOL *pResult)
{
    if (pbSrc == CVB_NULL || pbSig == CVB_NULL || pPubKey == CVB_NULL || pResult == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbX509PubKeyVerify(const CVB_BYTE *pbSrc, CVB_UINT32 nSrc, const CVB_BYTE *pbSig, CVB_UINT32 nSig, const CmscbbX509PublicKey *pPubKey, const CmscbbAsnOid *algoId, CVB_BOOL *pResult)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_CRYPTO_VRF_CTX vrf_ctx = CVB_NULL;
    const CmscbbRsaPublicKey *pRsaPubKey = CVB_NULL;
    CmscbbBigInt e = {0};
    CmscbbBigInt n = {0};
    CVB_INT result = CVB_FALSE;
    CMSCBB_AOIDS hashAlgo;

    ret = InternalCheckParmX509PKeyVerify(pbSrc, pbSig, pPubKey, pResult);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    hashAlgo = CmscbbGetHashAoidFromSign(algoId);
    if (hashAlgo == AOID_UNKNOWN) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_HASH_ALGO, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_HASH_ALGO);
    }

    pRsaPubKey = &pPubKey->rsaPubKey;
    ret = InternalGetBigIntFromOcts(&e, &(pRsaPubKey->publicExponent));
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    ret = InternalGetBigIntFromOcts(&n, &(pRsaPubKey->modules));
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbCryptoVerifyCreateCtx(&vrf_ctx);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbCryptoVerifyInit(vrf_ctx, &e, &n, (CVB_UINT32)hashAlgo);
    if (CVB_FAILED(ret)) {
        CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbCryptoVerifyUpdate(vrf_ctx, pbSrc, nSrc);
    if (CVB_FAILED(ret)) {
        CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbCryptoVerifyFinal(vrf_ctx, pbSig, nSig, &result);
    if (CVB_FAILED(ret)) {
        CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    CmscbbCryptoVerifyDestroyCtx(vrf_ctx);

    *pResult = (CVB_BOOL)result;
    return CVB_SUCCESS;
}
