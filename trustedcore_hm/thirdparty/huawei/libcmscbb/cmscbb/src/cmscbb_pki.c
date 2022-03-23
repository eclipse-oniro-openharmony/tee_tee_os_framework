/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../pki/cmscbb_pki.h"
#include "../cmscbb_common/cmscbb_common.h"
#include "../cmscbb_common/cmscbb_list.h"
#include "../x509/cmscbb_x509.h"
#include "../asn1/cmscbb_asn1_utils.h"

#define CVB_MAX_VERIFY_DEPTH 10

typedef struct cmscbb_pki_store_st {
    LIST_OF(CmscbbX509Cert) cert_store;
    LIST_OF(CmscbbX509Crl) crl_store;
} CMSCBB_PKI_STORE;

typedef struct cmscbb_pki_st {
    CMSCBB_PKI_STORE pki_store;
} CMSCBB_PKI;

CMSCBB_ERROR_CODE CmscbbPkiInit(CMSCBB_VRF* pVrf)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_PKI* pPki = CVB_NULL;

    if (pVrf == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = CmscbbMallocWith0((CVB_VOID**)&pPki, sizeof(CMSCBB_PKI));
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    pVrf->pki_ctx = (CVB_VOID*)pPki;

    return CVB_SUCCESS;
}

CVB_VOID CmscbbPkiUninit(CMSCBB_VRF* pVrf)
{
    CMSCBB_PKI* pki = CVB_NULL;
    if (pVrf == CVB_NULL) {
        return;
    }

    pki = (CMSCBB_PKI*)pVrf->pki_ctx;
    if (pki == CVB_NULL) {
        return;
    }

    /* free trust store */
    CMSCBB_LIST_FREE(&(pki->pki_store.cert_store), CmscbbX509FreeCert);
    CMSCBB_LIST_FREE(&(pki->pki_store.crl_store), CmscbbX509FreeCrl);

    CmscbbFree((CVB_VOID*)(pVrf->pki_ctx));
    pVrf->pki_ctx = CVB_NULL;
}

CMSCBB_ERROR_CODE CmscbbPkiStoreAddCert(const CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_PKI* pki = CVB_NULL;
    LIST_OF(CmscbbX509Cert)* cert_list;
    CVB_INT iter;

    if (pVrf == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pki = (CMSCBB_PKI*)pVrf->pki_ctx;
    if (pCert == CVB_NULL || pki == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    /* check duplicate certificate in store */
    cert_list = &(pki->pki_store.cert_store);
    for (iter = 0; iter < (CVB_INT)cert_list->num; ++iter) {
        const CmscbbX509Cert* pTempCert = cert_list->data[iter];

        /* check duplicate */
        if (CMSCBB_COMPARE_ASN_BITS(&pTempCert->signature, &pCert->signature) == 0) {
            return CMSCBB_ERR_PKI_CERT_ALREADY_EXIST;
        }
    }

    ret = CMSCBB_LIST_ADD(cert_list, pCert);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* add certificate reference */
    ++pCert->iRef;
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbPkiStoreAddCrl(const CMSCBB_VRF* pVrf, CmscbbX509Crl* pCrl)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_PKI* pki = CVB_NULL;
    LIST_OF(CmscbbX509Crl)* crl_list;
    CVB_INT iter;

    if (pVrf == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pki = (CMSCBB_PKI*)pVrf->pki_ctx;
    if (pCrl == CVB_NULL || pki == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    /* check duplicate CRL */
    crl_list = &(pki->pki_store.crl_store);
    for (iter = 0; iter < (CVB_INT)crl_list->num; ++iter) {
        const CmscbbX509Crl* pTempCrl = crl_list->data[iter];

        /* check duplicate */
        if (CMSCBB_COMPARE_ASN_BITS(&pTempCrl->signature, &pCrl->signature) == 0) {
            return CMSCBB_ERR_PKI_CRL_ALREADY_EXIST;
        }
    }

    ret = CMSCBB_LIST_ADD(crl_list, pCrl);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* Add CRL reference */
    ++pCrl->iRef;
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckCertIssuer
 * Description  : check subject certificate's issuer by signature
 * Params
 *   [IN] pSubjCert:  subject X509 certificate 
 *   [IN] pAuthorCert: author X509 certificate 
 * Return Value : CMSCBB_ERROR_CODE
 * Remarks      : only check the signature, no attributes check,
 *   attributes should be check by situation.
 *
 *   Date              Author     Modification
 *   2015/10/14 12:19  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckCertIssuer(CmscbbX509Cert* pSubjCert, const CmscbbX509Cert* pAuthorCert)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BOOL verify_result = CVB_FALSE;

    if (pSubjCert->pIssuer != CVB_NULL) {
        if (pSubjCert->pIssuer == pAuthorCert) {
            /* already checked */
            return CVB_SUCCESS;
        } else {
            return CMSCBB_ERR_PKI_CERT_INVALID_ISSUER;
        }
    }

    /* compare issuer and subject */
    ret = CmscbbCompareX509Name(&(pSubjCert->toBeSigned.issuer), &(pAuthorCert->toBeSigned.subject));
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    if (((CVB_UINT32)pAuthorCert->toBeSigned.extensions.ku & CMSCBB_X509_KU_KEY_CERT_SIGN) == 0) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE);
    }
#if CMSCBB_ALLOW_NO_CHECK_TSA_CRL
    if (((CVB_UINT32)pAuthorCert->toBeSigned.extensions.ku & CMSCBB_X509_KU_CRL_SIGN) == 0) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE);
    }
#endif

    ret = CmscbbX509PubKeyVerify(pSubjCert->rawSigned.octs, pSubjCert->rawSigned.len, pSubjCert->signature.octs, pSubjCert->signature.len,
                                 &(pAuthorCert->toBeSigned.subjectPubKey.subjectPublicKey), &(pSubjCert->algorithm.algorithm), &verify_result);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    if (verify_result != CVB_TRUE) {
        return CMSCBB_ERR_PKI_CERT_INVALID_ISSUER;
    }

    pSubjCert->pIssuer = pAuthorCert;
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalFindCertIssuer
 * Description  : find certificate issuer from store
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pSubjectCert: subject X509 certificate 
 * Return Value : Issuer of the certificate, or CVB_NULL if not found
 *   Date              Author     Modification
 *   2015/11/11 12:22  t00307193  Create
 */
CVB_STATIC CmscbbX509Cert* InternalFindCertIssuer(const CMSCBB_VRF* pVrf, CmscbbX509Cert* pSubjectCert)
{
    CMSCBB_PKI* pki = (CMSCBB_PKI*)pVrf->pki_ctx;
    CVB_INT iter;
    CmscbbX509Cert* pIssuerCert = CVB_NULL;

    for (iter = 0; iter < (CVB_INT)(pki->pki_store.cert_store.num); ++iter) {
        CmscbbX509Cert* pCert = pki->pki_store.cert_store.data[iter];

        if ((CVB_BOOL)pCert->toBeSigned.extensions.ca_info.isCa != CVB_TRUE) {
            continue;
        }

        if (InternalCheckCertIssuer(pSubjectCert, pCert) == CVB_SUCCESS) {
            pIssuerCert = pCert;
            break;
        }
    }

    return pIssuerCert;
}

/*
 * Prototype    : InternalCheckCrlIssuer
 * Description  : check key usage and verify the CRL.
 * Params
 *   [IN] pCrl:X509 crl
 *   [IN] pAuthorCert: author X509 certificate 
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckCrlIssuer(const CmscbbX509Crl* pCrl, const CmscbbX509Cert* pAuthorCert)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BOOL isSignatureValid = CVB_FALSE;

    ret = CmscbbCompareX509Name(&(pCrl->tbsCertList.issuer), &(pAuthorCert->toBeSigned.subject));
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    if (((CVB_UINT32)pAuthorCert->toBeSigned.extensions.ku & CMSCBB_X509_KU_CRL_SIGN) == 0) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE);
    }

    ret = CmscbbX509PubKeyVerify(pCrl->rawSigned.octs, pCrl->rawSigned.len, pCrl->signature.octs, pCrl->signature.len,
                                 &(pAuthorCert->toBeSigned.subjectPubKey.subjectPublicKey), &(pCrl->algorithm.algorithm), &isSignatureValid);
    if (CVB_FAILED(ret) || isSignatureValid != CVB_TRUE) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CRL_INVALID_ISSUER, CVB_NULL);
        return (CMSCBB_ERR_PKI_CRL_INVALID_ISSUER);
    }

    return CVB_SUCCESS;
}

CmscbbX509Cert* CmscbbPkiFindCrlIssuer(const CMSCBB_VRF* pVrf, const CmscbbX509Crl* pCrl)
{
    CMSCBB_PKI* pki = CVB_NULL;
    CVB_INT iter;
    CmscbbX509Cert* pAuthorCert = CVB_NULL;

    if (pVrf == CVB_NULL) {
        return CVB_NULL;
    }

    pki = (CMSCBB_PKI*)pVrf->pki_ctx;
    if (pki == CVB_NULL || pCrl == CVB_NULL) {
        return CVB_NULL;
    }

    for (iter = 0; iter < (CVB_INT)(pki->pki_store.cert_store.num); ++iter) {
        CmscbbX509Cert* pCert = pki->pki_store.cert_store.data[iter];
        if (InternalCheckCrlIssuer(pCrl, pCert) == CVB_SUCCESS) {
            pAuthorCert = pCert;
            break;
        }
    }

    return pAuthorCert;
}

/*
 * Prototype    : InternalFindCertRoot
 * Description  : Find root of the certificate.
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pCert: X509 certificate
 *   [IN] findDepth: current find depth
 * Return Value : Root certificate, or CVB_NULL if not found.
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CmscbbX509Cert* InternalFindCertRoot(CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert, CVB_INT findDepth)
{
    CmscbbX509Cert* pIssuer = CVB_NULL;
    CmscbbX509Cert* pRoot = CVB_NULL;

    CVB_BOOL isSelfSigned = CVB_FALSE;
    CVB_INT nextDepth = findDepth;

    /* return if find depth is too high */
    if (nextDepth < 0 || nextDepth > CVB_MAX_VERIFY_DEPTH) {
        CVB_LOG_ERROR(CMSCBB_ERR_UNDEFINED, "find path too deep.");
        return CVB_NULL;
    }

    ++nextDepth;

    /* if cert is root, return itself */
    if (CmscbbX509IsSelfSigned(pCert, &isSelfSigned) != CVB_SUCCESS) {
        return CVB_NULL;
    }

    if (isSelfSigned) {
        return pCert;
    }

    /* find issuer of the certificate */
    pIssuer = InternalFindCertIssuer(pVrf, pCert);
    if (pIssuer == CVB_NULL) {
        return CVB_NULL;
    }

    /* recursively find the issuer's root */
    pRoot = InternalFindCertRoot(pVrf, pIssuer, nextDepth);
    return pRoot;
}

/* certificate is within CRL scope, serials number included */
#define CVB_CRL_SCORE_SCOPE		0x080
/* CRL times valid */
#define CVB_CRL_SCORE_TIME      0x040
/* crl has same issuer with certificate */
#define CVB_CRL_SCORE_ISSUER    0x020
#if CMSCBB_SUPPORT_INDIRECT_CRL
/* indirect crl */
#define CVB_CRL_SCORE_INDIRECT  0x010
#endif

/* CMSCBB_CRL_SCORE_INFO */
typedef struct cmscbb_crl_score_info_st {
    CVB_UINT32 crlScore;    /* CRL score */
    CmscbbX509Crl* pCrl;  /* the CRL */
} CMSCBB_CRL_SCORE_INFO;
DECLARE_LIST_OF(CMSCBB_CRL_SCORE_INFO);

/*
 * Prototype    : InternalCrlScoreSortDesc
 * Description  : callback implement for list sort
 * Params
 *   [IN] pCsi1: crl score information 1 
 *   [IN] pCsi2: crl score information 2
 * Return Value : compare result.
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CVB_INT InternalCrlScoreSortDesc(const CMSCBB_CRL_SCORE_INFO* pCsi1, const CMSCBB_CRL_SCORE_INFO* pCsi2)
{
    /* sort in descending order */
    if (pCsi1->crlScore > pCsi2->crlScore) {
        return -1;
    } else if (pCsi1->crlScore == pCsi2->crlScore) {
        return 0;
    } else {
        return 1;
    }
}

CVB_STATIC CVB_BOOL InternalIsIndirectCrl(const CmscbbX509Crl* pCrl)
{
#if CMSCBB_SUPPORT_INDIRECT_CRL
    /* check if the CRL is indirect for the certificate,
         * both the CRL's indirect flag is on and its issuer name different with certificate's */
    return (CVB_BOOL)pCrl->tbsCertList.extensions.idp.indirectCRL;
#else
    (CVB_VOID)pCrl;
    return CVB_FALSE;
#endif
}
/*
 * Prototype    : InternalCrlGetIssuerScore
 * Description  : check issuer of crl, and give a relative score
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pCrl: X509 crl
 *   [IN] pCert: X509 certificate
 *   [IN] pCrtRoot:X095 Root crl
 *   [OUT] score: crl score
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCrlGetIssuerScore(CMSCBB_VRF* pVrf, const CmscbbX509Crl* pCrl, const CmscbbX509Cert* pCert, const CmscbbX509Cert* pCrtRoot, CVB_UINT32* score)
{
    CmscbbX509Cert* pCrlRoot = CVB_NULL;
    CmscbbX509Cert* pAuthorCert = CVB_NULL;
    CVB_BOOL equalIssuerName = CVB_FALSE;
    CVB_BOOL indirectCrl;
    const CmscbbX509Name* pCertIssuer;

    pCertIssuer = &(pCert->toBeSigned.issuer);
    if (pCertIssuer->names.num == 0) {
        return CMSCBB_ERR_UNDEFINED;
    }

    if (CmscbbCompareX509Name(pCertIssuer, &(pCrl->tbsCertList.issuer)) == 0) {
        equalIssuerName = CVB_TRUE;
    }

    indirectCrl = InternalIsIndirectCrl(pCrl);
    if (equalIssuerName != CVB_TRUE && indirectCrl != CVB_TRUE) {
        return CMSCBB_ERR_UNDEFINED;
    }

    /* verify signature */
    pAuthorCert = CmscbbPkiFindCrlIssuer(pVrf, pCrl);
    if (pAuthorCert == CVB_NULL) {
        return CMSCBB_ERR_UNDEFINED;
    }

    /* must issued by the same root */
    pCrlRoot = InternalFindCertRoot(pVrf, pAuthorCert, 0);
    if (pCrtRoot != pCrlRoot) {
        return CMSCBB_ERR_UNDEFINED;
    }

    if (equalIssuerName == CVB_TRUE) {
        *score |= CVB_CRL_SCORE_ISSUER;
    }

#if CMSCBB_SUPPORT_INDIRECT_CRL
    if (indirectCrl == CVB_TRUE) {
        *score |= CVB_CRL_SCORE_INDIRECT;
    }
#endif

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCrlGetScore
 * Description  : get total score for the CRL
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pCrl: X509 crl
 *   [IN] pCert: X509 certificate
 *   [IN] pCrtRoot: X509 crl root
 * Return Value : the score of the CRL
 * Remarks      : If the CRL's revoke list contains cert, it could be the best crl for the cert even CRL expired
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CVB_INT InternalCrlGetScore(CMSCBB_VRF* pVrf, const CmscbbX509Crl* pCrl, const CmscbbX509Cert* pCert, const CmscbbX509Cert* pCrtRoot)
{
    CVB_UINT32 crlScore = 0;
    CVB_TIME_T tmNextUpdate = 0;

    /* get score relative to issuer */
    if (CVB_FAILED(InternalCrlGetIssuerScore(pVrf, pCrl, pCert, pCrtRoot, &crlScore))) {
        return 0;
    }

    if (crlScore == 0) {
        CVB_LOG_WARNING(0, "invalid issuer score.");
        return 0;
    }

    /* get score relative to revoke info */
    if (pCrl->tbsCertList.revokedCerts.revoked_list.num > 0) {
        CVB_INT iter;
        const SET_OF(CmscbbX509RevokeEntry)* pRevokedList;

        /* find cert revoke info */
        pRevokedList = &(pCrl->tbsCertList.revokedCerts.revoked_list);
        for (iter = 0; iter < (CVB_INT)pRevokedList->num; ++iter) {
            const CmscbbX509RevokeEntry* pRevoked = &(pRevokedList->data[iter]);
            if (CmscbbCompareAsnOcts((const CmscbbAsnOcts*) &pRevoked->userCert, (const CmscbbAsnOcts*) &(pCert->toBeSigned.serialNumber)) == 0) {
                /* found certificate */
                crlScore |= CVB_CRL_SCORE_SCOPE;
                break;
            }
        }
    }

    /* check time */
    if (CmscbbConvertDatetimeToTime(&(pCrl->tbsCertList.nextUpdateTime), &tmNextUpdate) != CVB_SUCCESS) {
        return 0;
    }

    if (tmNextUpdate >= pVrf->base_time) {
        crlScore |= CVB_CRL_SCORE_TIME;
    } else {
        CVB_LOG_WARNING(CMSCBB_ERR_PKI_CRL_HAS_EXPIRED, "Found an expired CRL, it most likely cause NO CRL error.");
        if ((crlScore & CVB_CRL_SCORE_SCOPE) == 0) {
            /* reset the score for expired CRL whose revoke list not contain the cert */
            crlScore = 0;
        }
    }

    return (CVB_INT)crlScore;
}

/*
 * Prototype    : InternalGetScoredCrl
 * Description  : filter CRLs in store according to the score.
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pCert:X509 certificate
 *   [IN] crlSiList:list of crl score information
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalGetScoredCrl(CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert, LIST_OF(CMSCBB_CRL_SCORE_INFO)* crlSiList)
{
    CMSCBB_ERROR_CODE ret = 0;
    CMSCBB_PKI* pki = (CMSCBB_PKI*)(pVrf->pki_ctx);
    const CmscbbX509Cert* pCrtRoot;
    CVB_INT iter;

    /* find the best CRL for cert */
    pCrtRoot = InternalFindCertRoot(pVrf, pCert, 0);
    if (pCrtRoot == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CERT_ISSUER_NOT_FOUND, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_ISSUER_NOT_FOUND);
    }

    for (iter = 0; iter < (CVB_INT)pki->pki_store.crl_store.num; ++iter) {
        CmscbbX509Crl* pCrl;
        CVB_UINT32 crlScore;

        pCrl = pki->pki_store.crl_store.data[iter];
        if (pCrl == CVB_NULL) {
            continue;
        }

        /* get CRL score */
        crlScore = (CVB_UINT32)InternalCrlGetScore(pVrf, pCrl, pCert, pCrtRoot);

        if (crlScore > 0) {
            CMSCBB_CRL_SCORE_INFO* pCrlScoreInfo = CVB_NULL;
            ret = CmscbbMallocWith0((CVB_VOID**)&pCrlScoreInfo, sizeof(CMSCBB_CRL_SCORE_INFO));
            if (CVB_FAILED(ret)) {
                CVB_LOG_DEBUG(ret, CVB_NULL);
                return ret;
            }

            pCrlScoreInfo->crlScore = crlScore;
            pCrlScoreInfo->pCrl = pCrl;
            ret = CMSCBB_LIST_ADD(crlSiList, pCrlScoreInfo);
            if (CVB_FAILED(ret)) {
                CmscbbFree(pCrlScoreInfo);
                return ret;
            }
        }
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalFindBestCrlOfCert
 * Description  : find best CRL for the certificate
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pCert: X509 certificate
 * Return Value : The best CRL, or CVB_NULL if not found.
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CmscbbX509Crl* InternalFindBestCrlOfCert(CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert, CVB_BOOL isTsRelative)
{
    CMSCBB_ERROR_CODE ret;
    LIST_OF(CMSCBB_CRL_SCORE_INFO) crlSiList = {0};
    CmscbbX509Crl* bestCrl = CVB_NULL;
    CVB_INT iter;

    ret = InternalGetScoredCrl(pVrf, pCert, &crlSiList);
    CVB_GOTO_ERR_IF_FAIL(ret);

    /* sort the CRL by score in descending order */
    ret = CMSCBB_LIST_SORT(&crlSiList, InternalCrlScoreSortDesc);
    CVB_GOTO_ERR_IF_FAIL(ret);

    /* the valid CRL with highest score is the best */
    for (iter = 0; iter < (CVB_INT)crlSiList.num; ++iter) {
        CVB_BOOL result = CVB_FALSE;
        CmscbbX509Cert* pAuthorCert = CVB_NULL;
        CMSCBB_CRL_SCORE_INFO* pCrlSi = crlSiList.data[iter];

        if (pCrlSi == CVB_NULL || pCrlSi->pCrl == CVB_NULL) {
            continue;
        }

        pAuthorCert = CmscbbPkiFindCrlIssuer(pVrf, pCrlSi->pCrl);
        if (pAuthorCert == CVB_NULL) {
            CVB_LOG_INFO(0, "There's no issuer found for the scored CRL");
            continue;
        }

        ret = CmscbbPkiVerifyCert(pVrf, pAuthorCert, CVB_FALSE, isTsRelative, &result);
        if (!CVB_FAILED(ret) && result == CVB_TRUE) {
            bestCrl = pCrlSi->pCrl;
            break;
        } else {
            CVB_LOG_INFO(ret, "Failed to verify issuer of scored CRL.");
        }
    }

    if (crlSiList.num == 0) {
        CVB_LOG_ERROR(ret, "Can't find CRL for certificate.");
        pVrf->last_err = CMSCBB_ERR_PKI_CERT_NO_CRL;
    } else if (bestCrl == CVB_NULL) {
        CVB_LOG_ERROR(ret, "Verify CRL failed.");
        pVrf->last_err = (ret != CVB_SUCCESS) ? ret : CMSCBB_ERR_PKI_CRL_INVALID_ISSUER;
    }

    goto CVB_FINAL;
CVB_ERR:
    pVrf->last_err = ret;
CVB_FINAL:
    CMSCBB_LIST_FREE(&crlSiList, CmscbbFree);
    return bestCrl;
}

/*
 * Prototype    : InternalIsCertRevoked
 * Description  : Check if the certificate is revoked
 * Params
 *   [IN] pCert:  X509 certificate
 *   [IN] base_time: base time
 *   [IN] isTsRelative: if usage of certificate relatived with timestamp  
 *   [IN] pRevoked: X509 revoked Item
 * Return Value : return CVB_SUCESS if not revoked.
 *   Date              Author     Modification
 *   2015/11/11 12:23  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalIsCertRevoked(const CmscbbX509Cert* pCert, CVB_TIME_T base_time, CVB_BOOL isTsRelative, const CmscbbX509RevokeEntry* pRevoked)
{
    CMSCBB_ERROR_CODE ret = 0;
    CVB_TIME_T revokeTime = 0;

    /* revoke sn match */
    if (CmscbbCompareAsnOcts(&pRevoked->userCert, &(pCert->toBeSigned.serialNumber)) == 0) {
        /* for ts relative, check reason */
        if (isTsRelative == CVB_TRUE || pCert->toBeSigned.extensions.ca_info.isCa) {
            CmscbbX509RevokeReason reason = (CmscbbX509RevokeReason)pRevoked->attrs.reason;

            if (reason != RVRS_AFFILIATIONCHANGED && reason != RVRS_SUPERSEDED && reason != RVRS_CESSATIONOFOPERATION) {
                return CMSCBB_ERR_PKI_CERT_REVOKED;
            }
        }

        /* check revoke time */
        ret = CmscbbConvertDatetimeToTime(&(pRevoked->revocationDate), &revokeTime);
        if (CVB_FAILED(ret)) {
            CVB_LOG_DEBUG(ret, CVB_NULL);
            return ret;
        }

        if (base_time >= revokeTime) {
            return CMSCBB_ERR_PKI_CERT_REVOKED; /* it's revoked certificate */
        }
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckCrlOfCert
 * Description  : check revoke status of certificate
 * Params
 *   [IN] pVrf: data for verify context 
 *   [IN] pCert: X509 certificate
 *   [OUT] ppCrl: output the best CRL for the certificate
 * Return Value : CMSCBB_ERR_PKI_CERT_REVOKED if the certificate revoked
 *   CVB_SUCCESS if not revoked, or other indicate error.
 *   Date              Author     Modification
 *   2015/11/11 12:24  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckCrlOfCert(CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert, CVB_BOOL isTsRelative, CmscbbX509Crl** ppCrl)
{
    CMSCBB_ERROR_CODE ret = 0;
    CmscbbX509Crl* pCrl = CVB_NULL;
    CVB_INT iter;
    SET_OF(CmscbbX509RevokeEntry)* pRevokedList = CVB_NULL;

    pCrl = InternalFindBestCrlOfCert(pVrf, pCert, isTsRelative);
    if (pCrl == CVB_NULL) {
        CVB_LOG_DEBUG(pVrf->last_err, CVB_NULL);
        return (pVrf->last_err);
    }

    /* check revocation list */
    if (pCrl->tbsCertList.revokedCerts.revoked_list.num > 0) {
        pRevokedList = &(pCrl->tbsCertList.revokedCerts.revoked_list);
        for (iter = 0; iter < (CVB_INT)pRevokedList->num; ++iter) {
            CmscbbX509RevokeEntry* pRevoked = &(pRevokedList->data[iter]);

            ret = InternalIsCertRevoked(pCert, pVrf->base_time, isTsRelative, pRevoked);
            if (ret == CMSCBB_ERR_PKI_CERT_REVOKED) {
                CVB_LOG_ERROR(ret, "The certificate was revoked.\r\n");
                break;
            }

            if (CVB_FAILED(ret)) {
                CVB_LOG_DEBUG(ret, CVB_NULL);
                return ret;
            }
        }
    }

    *ppCrl = pCrl;
    return ret;
}

/*
 * Prototype    : InternalCheckCertDate
 * Description  : check if the certificate is valid in date time.
 * Params
 *   [IN] pSubjCert: X509 subject certificate
 *   [IN] base_time: base time
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:24  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckCertDate(const CmscbbX509Cert* pSubjCert, CVB_TIME_T base_time)
{
    CMSCBB_ERROR_CODE ret;
    CVB_TIME_T tm_validate_from = 0;
    CVB_TIME_T tm_validate_to = 0;

    /* check cert time */
    ret = CmscbbConvertDatetimeToTime(&(pSubjCert->toBeSigned.validity.notBefore), &tm_validate_from);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    ret = CmscbbConvertDatetimeToTime(&(pSubjCert->toBeSigned.validity.notAfter), &tm_validate_to);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    if (base_time < tm_validate_from) {
        return CMSCBB_ERR_PKI_CERT_DATETIME_NO_VALID_YET;
    }

    if (base_time > tm_validate_to) {
        return CMSCBB_ERR_PKI_CERT_DATETIME_EXPIRED;
    }

    return CVB_SUCCESS;
}

CVB_STATIC CVB_BOOL InternalDetermineCheckCrl(CVB_BOOL check_crl, const CmscbbX509Cert* pSubjCert)
{
    CVB_BOOL ret = check_crl;
#if CMSCBB_ALLOW_NO_CHECK_TSA_CRL
    if (check_crl) {
        if (pSubjCert->toBeSigned.extensions.exku == CMSCBB_PKI_XKU_TIMESTAMP) {
            ret = CVB_FALSE;
        }
    }
#endif

    (CVB_VOID)pSubjCert;
    return ret;
}

/*
 * Prototype    : InternalVerifyCertificate
 * Description  : verify certificate itself
 * Params
 *   [IN] pVrf: data for verify context 
 *   [IN] pSubjCert: X509 subject certificate
 *   [IN] ppAuthor: athor X509 certificate
 *   [IN] verifyDone: if verify success return CVB_SUCCESS
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/12/14 15:16  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalVerifyCertificate(CMSCBB_VRF* pVrf, CmscbbX509Cert* pSubjCert, CVB_BOOL isTsRelative, CmscbbX509Cert** ppAuthor, CVB_BOOL *verifyDone)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BOOL isSelfSigned = CVB_FALSE;
    CmscbbX509Cert* pAuthorCert = CVB_NULL;

#if CMSCBB_ENABLE_VERIFY_WITHOUT_CRL
    CVB_BOOL check_crl = CVB_FALSE;
#else
    CVB_BOOL check_crl = CVB_TRUE;
#endif

    ret = InternalCheckCertDate(pSubjCert, pVrf->base_time);
    if (CVB_FAILED(ret)) {
        CVB_LOG_WARNING(ret, "Check date for certificate failed, verify may fail.");
        return ret;
    }

    ret = CmscbbX509IsSelfSigned(pSubjCert, &isSelfSigned);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    if (isSelfSigned) {
        *verifyDone = CVB_TRUE;
        return CVB_SUCCESS;
    }

    check_crl = InternalDetermineCheckCrl(check_crl, pSubjCert);
    if (check_crl) { /* Check_crl will change the value when the CMSCBB_ALLOW_NO_CHECK_TSA_CRL macro is turned on */
        CmscbbX509Crl* pCrl = CVB_NULL;
        /* check CRL */
        ret = InternalCheckCrlOfCert(pVrf, pSubjCert, isTsRelative, &pCrl);
        if (CVB_FAILED(ret)) {
            CVB_LOG_DEBUG(ret, CVB_NULL);
            return ret;
        }

#if CMSCBB_SUPPORT_INDIRECT_CRL
        if ((CVB_BOOL)pCrl->tbsCertList.extensions.idp.indirectCRL == CVB_FALSE) {
            *verifyDone = CVB_TRUE;
            return CVB_SUCCESS;
        }
#else
    *verifyDone = CVB_TRUE;
    return CVB_SUCCESS;
#endif
    }

    /* check issuer */
    pAuthorCert = InternalFindCertIssuer(pVrf, pSubjCert);
    if (pAuthorCert == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CERT_ISSUER_NOT_FOUND, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_ISSUER_NOT_FOUND);
    }

    *ppAuthor = pAuthorCert;
    return CVB_SUCCESS;
}

CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamPkiVerifyCert(const CMSCBB_VRF* pVrf, const CmscbbX509Cert* pCert, const CVB_BOOL* result)
{
    if (pVrf == CVB_NULL || pCert == CVB_NULL || result == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbPkiVerifyCert(CMSCBB_VRF* pVrf, CmscbbX509Cert* pCert, CVB_BOOL reset_depth, CVB_BOOL isTsRelative, CVB_BOOL* result)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbX509Cert* pSubjCert = pCert;

    ret = InternalCheckParamPkiVerifyCert(pVrf, pCert, result);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    *result = CVB_FALSE;

    if (reset_depth) {
        pVrf->curr_depth = 0;
    }

    if (CVB_MAX_VERIFY_DEPTH < pVrf->curr_depth) {
        CVB_LOG_ERROR(0, "The path of certificate is too deep.");
        return CMSCBB_ERR_PKI_CERT_DEPTH;
    }

    /* increase depth */
    ++pVrf->curr_depth;
    CVB_LOG_DEBUG1(0, "Current depth of certificate path is: %d.", pVrf->curr_depth);

    /* check code sign extension */
    while (pSubjCert != CVB_NULL) {
        CmscbbX509Cert* pAuthorCert = CVB_NULL;
        CVB_BOOL verifyDone = CVB_FALSE;
        ret = InternalVerifyCertificate(pVrf, pSubjCert, isTsRelative, &pAuthorCert, &verifyDone);
        if (CVB_FAILED(ret)) {
            CVB_LOG_INFO(ret, "Failed to verify certificate itself");
            break;
        }

        if (verifyDone) {
            break;
        }

        /* continue validate issuer */
        pSubjCert = pAuthorCert;
    }

    if (CVB_FAILED(ret)) {
        *result = CVB_FALSE;
    } else {
        *result = CVB_TRUE;
    }

    --pVrf->curr_depth; /* decrease depth */
    return ret;
}

CVB_STATIC CVB_BOOL InternalCheckParamPkiFindCertByIssuerSN(const CMSCBB_VRF* pVrf, const CmscbbX509Name* issuer, const CmscbbAsnBigint* sn)
{
    if (pVrf == CVB_NULL || issuer == CVB_NULL || sn == CVB_NULL || issuer->names.num == 0 || sn->len == 0) {
        return CVB_FALSE;
    }
    return CVB_TRUE;
}

CmscbbX509Cert* CmscbbPkiFindCertByIssuerSn(const CMSCBB_VRF* pVrf, const CmscbbX509Name* issuer, const CmscbbAsnBigint* sn)
{
    CmscbbX509Cert* certExpected = CVB_NULL;
    CVB_INT iter;
    const LIST_OF(CmscbbX509Cert)* pCerts;
    CMSCBB_PKI* pki = CVB_NULL;

    if (!InternalCheckParamPkiFindCertByIssuerSN(pVrf, issuer, sn)) {
        return CVB_NULL;
    }

    pki = (CMSCBB_PKI*)pVrf->pki_ctx;
    if (CVB_NULL == pki) {
        return CVB_NULL;
    }

    pCerts = &(pki->pki_store.cert_store);
    for (iter = 0; iter < (CVB_INT)(pCerts->num); ++iter) {
        CmscbbX509Cert* pCert = pCerts->data[iter];
        if (pCert == CVB_NULL) {
            continue;
        }

        if (CmscbbCompareX509Name(issuer, &(pCert->toBeSigned.issuer)) == 0 &&
            CmscbbCompareAsnOcts(sn, &(pCert->toBeSigned.serialNumber)) == 0) {
            certExpected = pCert;
            break;
        }
    }
    return certExpected;
}
