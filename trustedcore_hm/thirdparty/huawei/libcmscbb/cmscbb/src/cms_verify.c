/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "cms_verify.h"
#include "../pki/cmscbb_pki.h"
#include "../x509/cmscbb_x509.h"
#include "cmscbb_cms_def.h"
#include "../asn1/cmscbb_asn1_utils.h"
#include "../asn1/cmscbb_asn1_decode.h"
#include "../cmscbb_common/cmscbb_base64.h"
#include "../cms/cmscbb_cms_parse.h"
#include "tee_log.h"

#if CMSCBB_SUPPORT_FILE
CVB_STATIC CMSCBB_ERROR_CODE InternalReadFile(const CVB_CHAR* pszFilePath, CVB_BYTE** data, CVB_INT32* size);
#endif
#if CMSCBB_SUPPORT_PEM
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodeCertCrl(CMSCBB_VRF* pVrf, const CVB_BYTE* pbContent,
    CVB_UINT32 nContentLength, LIST_OF(CmscbbX509Cert)* pCertList, LIST_OF(CmscbbX509Crl)* pCrlList);
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodePemCertCrl(CMSCBB_VRF* pVrf, const CVB_BYTE* pbContent,
    CVB_UINT32 nContentLength, LIST_OF(CmscbbX509Cert)* pCertList, LIST_OF(CmscbbX509Crl)* pCrlList);
#define CVB_MIN_PEM_LEN 38  /* sizeof("-----BEGIN XXX-----\r\n-----END XXX-----") */
#define CVB_PEM_SYMBOL "-----BEGIN"
#define CVB_PEM_SYMBOL_END "-----END"
#define CVB_PEM_SPLIT "-----"
#define CVB_PEM_SYMBOL_CMS "-----BEGIN CMS-----"
#define CVB_PEM_SYMBOL_CMS_END "-----END CMS-----"
#define CVB_PEM_SYMBOL_CMS_LEN 19
#define CVB_PEM_SYMBOL_PKCS7 "-----BEGIN PKCS7-----"
#define CVB_PEM_SYMBOL_PKCS7_END "-----END PKCS7-----"
#define CVB_PEM_SYMBOL_PKCS7_LEN 21
#define CVB_PEM_SYMBOL_CERT "-----BEGIN CERTIFICATE-----"
#define CVB_PEM_SYMBOL_CERT_END "-----END CERTIFICATE-----"
#define CVB_PEM_SYMBOL_CERT_LEN 27
#define CVB_PEM_SYMBOL_CRL "-----BEGIN X509 CRL-----"
#define CVB_PEM_SYMBOL_CRL_END "-----END X509 CRL-----"
#define CVB_PEM_SYMBOL_CRL_LEN 24
#endif

#if CMSCBB_NEED_RELOCATE
/*
 * Prototype    : InternalDoRelocateAll
 * Description  : Address redirection switch.
 * The values of static variable (CMSCBB_NEED_RELOCATE) for pointer types in some embedded environments are determined at compile time.
 * However, only the offset of the relative 0 addresses of these pointers is recorded at compile time.
 * The runtime program loaded the base site is not starting from 0,
 * In this case, you need to turn on the address redirection feature, And when creating a context, you need to pass in a real program-loading base address.
 * The function RelocateTemplate will overload in different cases.
 * Params
 *   [IN] reloc_off: which indicates  the offset of pointers' location
 *   Date              Author     Modification
 *   2015/11/10 10:09  t00307193  Create
 */
CVB_STATIC CVB_VOID InternalDoRelocateAll(CVB_ULONG reloc_off)
{
    if (reloc_off == 0) {
        return;
    }

    RelocateTemplate(&g_itemCmscbbX509Cert, reloc_off);
    RelocateTemplate(&g_itemCmscbbX509ExtensionEntry, reloc_off);
    RelocateTemplate(&g_itemCmscbbPkcs7Content, reloc_off);
    RelocateTemplate(&g_itemCmscbbTimestampInfo, reloc_off);
    RelocateTemplate(&g_itemCmscbbAsnOcts, reloc_off);
    RelocateTemplate(&g_itemCmscbbX509Crl, reloc_off);
    RelocateTemplate(&g_itemCmscbbX509BasicConstraints, reloc_off);
    RelocateTemplate(&g_itemCmscbbAsnBits, reloc_off);
    RelocateTemplate(&g_itemCmscbbAsnOidBundle, reloc_off);
#if CMSCBB_SUPPORT_INDIRECT_CRL
    RelocateTemplate(&g_itemCmscbbX509IssuingDistPoint, reloc_off);
#endif
    RelocateTemplate(&g_itemCmscbbAsnEnum, reloc_off);

    if (g_cvbOidReloced == CVB_FALSE) {
        int iter;
        for (iter = 0; iter < (CVB_INT)g_cvbOidCount; ++iter) {
            g_cvbOIDTable[iter].stAsnOid.octs += reloc_off;
        }
        g_cvbOidReloced = CVB_TRUE;
    }
}
#endif

CMSCBB_ERROR_CODE CmscbbVerifyCreateCtx(CMSCBB_VRF_CTX* pCtx, const CmscbbCtxCreateParams* pParams)
{
    CMSCBB_VRF* pVrf = CVB_NULL;
    CMSCBB_ERROR_CODE ret;

    if (pCtx == CVB_NULL || pParams == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    if (pParams->st_size != sizeof(CmscbbCtxCreateParams)) {
        return CMSCBB_ERR_CONTEXT_INVALID_STRUCT;
    }

    /* for pCtx not created yet, so use functions directly from pParms */
    ret = CmscbbMallocWith0((CVB_VOID**)&pVrf, sizeof(CMSCBB_VRF));
    if (CVB_FAILED(ret)) {
        return ret;
    }

    ret = CmscbbPkiInit(pVrf);
    if (CVB_FAILED(ret)) {
        CmscbbFree(pVrf);
        return ret;
    }

    pVrf->st_size = sizeof(CMSCBB_VRF);

    /* all finished */
    *pCtx = (CMSCBB_VRF_CTX)pVrf;

#if CMSCBB_DELAY_ADDRESS_SET
    CmscbbAsn1TemplInit();
    CmscbbCmsTemplInit();
    CmscbbX509TemplInit();
#endif

#if CMSCBB_NEED_RELOCATE
    InternalDoRelocateAll(pParams->relocBase);
#endif
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckVerifyOjbect
 * Description  : Check the context verify  is legal or not
 
 * Params
 *   [IN] pVrf: data for verify context
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:09  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckVerifyOjbect(const CMSCBB_VRF* pVrf)
{
    if (pVrf == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_BASE;
    }
    if (pVrf->st_size != sizeof(CMSCBB_VRF)) {
        return CMSCBB_ERR_CONTEXT_INVALID_STRUCT;
    }
    return CVB_SUCCESS;
}



#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : InternalCheckParamVerifyAddCertFile
 * Description  :  When File Interface switch (CMSCBB_SUPPORT_FILE) is turned on,
 * check the context verify  is legal , then check cert file is not null
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pszCertFile: cert file data
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:09  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyAddCertFile(const CMSCBB_VRF* pVrf, const CVB_CHAR* pszCertFile)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (pszCertFile == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyAddCertFile(CMSCBB_VRF_CTX ctx, const CVB_CHAR* pszCertFile)
{
    CVB_BYTE* pbData = CVB_NULL;
    CVB_INT32 nFileSize = 0;
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;

    ret = InternalCheckParamVerifyAddCertFile(pVrf, pszCertFile);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    ret = InternalReadFile(pszCertFile, &pbData, &nFileSize);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbVerifyAddCert(ctx, pbData, (CVB_UINT32)nFileSize);
    CmscbbFree(pbData);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
    }

    return ret;
}
#endif

/*
 * Prototype    : InternalAddCertToStore
 * Description  : Add non-ca certificates into store
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN,OUT] certList: a list of x509cert 
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:09  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalAddCertToStore(const CMSCBB_VRF* pVrf, const LIST_OF(CmscbbX509Cert) *certList, CVB_BOOL allow_root)
{
    CMSCBB_ERROR_CODE ret = CVB_SUCCESS;
    CVB_INT iter = 0;

    if (certList->num == 0) {
        return CMSCBB_ERR_UNDEFINED;
    }

    for (; iter < (CVB_INT)certList->num; ++iter) {
        CmscbbX509Cert* pCert = certList->data[iter];
        CVB_BOOL isSelfSigned = CVB_FALSE;

        if (pCert == CVB_NULL) {
            continue;
        }

        if (!allow_root) {
            ret = CmscbbX509IsSelfSigned(pCert, &isSelfSigned);
            if (CVB_FAILED(ret)) {
                CVB_LOG_ERROR(ret, "Failed to check self sign for certificate.");
                break;
            }
            if (isSelfSigned == CVB_TRUE) {
                CVB_LOG_WARNING(0, "There is a root certificate, which is not allowed when add crl or cms.");
                continue;
            }
        }

        ret = CmscbbPkiStoreAddCert(pVrf, pCert);
        if (ret == CMSCBB_ERR_PKI_CERT_ALREADY_EXIST) {
            CVB_LOG_INFO(0, "There is a duplicate certificate.");
            ret = 0;
        }
        if (CVB_FAILED(ret)) {
            CVB_LOG_ERROR(ret, "Failed to add certificate into PKI context.");
            break;
        }
    }

    return ret;
}
/*
 * Prototype    : InternalCheckParamVerfiyAddCert
 * Description  : Check verify context and X509Certificate
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbCert: X509Certificate data
 *   [IN] nCertLength : length of X509Certificate data
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:09  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyAddCert(const CMSCBB_VRF* pVrf, const CVB_BYTE* pbCert, CVB_UINT32 nCertLength)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (pbCert == CVB_NULL || nCertLength == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyAddCert(CMSCBB_VRF_CTX ctx, const CVB_BYTE* pbCert, CVB_UINT32 nCertLength)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    LIST_OF(CmscbbX509Cert) certList = {0};

    ret = InternalCheckParamVerifyAddCert(pVrf, pbCert, nCertLength);
    if (CVB_FAILED(ret)) {
        return ret;
    }

#if CMSCBB_SUPPORT_PEM
    /* ignore the CRL */
    ret = InternalDecodeCertCrl(pVrf, pbCert, nCertLength, &certList, CVB_NULL);
#else
    ret = InternalDecodeStreamCertCrl(pVrf, pbCert, nCertLength, &certList, CVB_NULL);
#endif
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = InternalAddCertToStore(pVrf, &certList, CVB_TRUE);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    goto CVB_FINAL;
CVB_ERR:
    ;
CVB_FINAL:
    CMSCBB_LIST_FREE(&certList, CmscbbX509FreeCert);
    return ret;
}


#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : InternalCheckParamVerifyAddCrlFile
 * Description  : Check verify context and crl file
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbCert: crl file data
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:09  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyAddCrlFile(const CMSCBB_VRF* pVrf, const CVB_CHAR* pszCrlFile)
{
    if (pVrf == CVB_NULL || pszCrlFile == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    if (pVrf->st_size != sizeof(CMSCBB_VRF)) {
        return CMSCBB_ERR_CONTEXT_INVALID_STRUCT;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyAddCrlFile(CMSCBB_VRF_CTX ctx, const CVB_CHAR* pszCrlFile)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BYTE* pbData = CVB_NULL;
    CVB_INT32 fileBytes = 0;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;

    ret = InternalCheckParamVerifyAddCrlFile(pVrf, pszCrlFile);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    ret = InternalReadFile(pszCrlFile, &pbData, &fileBytes);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbVerifyAddCrl(ctx, pbData, (CVB_UINT32)fileBytes);
    CmscbbFree(pbData);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    return CVB_SUCCESS;
}
#endif

/*
 * Prototype    : InternalAddCrlToStore
 * Description  : Add CRL list into store
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN,OUT] crlList: a list of X509crl 
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalAddCrlToStore(const CMSCBB_VRF* pVrf, const LIST_OF(CmscbbX509Crl) *crlList)
{
    CMSCBB_ERROR_CODE ret;
    CVB_INT iter = 0;

    for (; iter < (CVB_INT)crlList->num; ++iter) {
        CmscbbX509Crl* pCrl = crlList->data[iter];
        if (pCrl == CVB_NULL) {
            continue;
        }

        ret = CmscbbPkiStoreAddCrl(pVrf, pCrl);
        if (ret == CMSCBB_ERR_PKI_CRL_ALREADY_EXIST) {
            CVB_LOG_INFO(ret, "CRL already existed.");
        } else if (CVB_FAILED(ret)) {
            return ret;
        }
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckParamVerifyAddCrl
 * Description  : Add CRL list into store
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN,OUT] crlList: a list of X509crl
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyAddCrl(const CMSCBB_VRF* pVrf, const CVB_BYTE* pbCrlAdd, CVB_UINT32 nCrlLength)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (pbCrlAdd == CVB_NULL || nCrlLength == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyAddCrl(CMSCBB_VRF_CTX ctx, const CVB_BYTE* pbCrl, CVB_UINT32 nCrlLength)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    LIST_OF(CmscbbX509Cert) certList = {0};
    LIST_OF(CmscbbX509Crl) crlList = {0};

    ret = InternalCheckParamVerifyAddCrl(pVrf, pbCrl, nCrlLength);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    if (pVrf->crl_frozen) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CRL_POOL_FROZEN, CVB_NULL);
        return CMSCBB_ERR_PKI_CRL_POOL_FROZEN;
    }

#if CMSCBB_SUPPORT_PEM
    ret = InternalDecodeCertCrl(pVrf, pbCrl, nCrlLength, &certList, &crlList);
#else
    ret = InternalDecodeStreamCertCrl(pVrf, pbCrl, nCrlLength, &certList, &crlList);
#endif

    CVB_GOTO_ERR_WITH_LOG_IF(CVB_FAILED(ret) || 0 == crlList.num, CMSCBB_ERR_PKI_CRL_DECODE);

    ret = InternalAddCrlToStore(pVrf, &crlList);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = InternalAddCertToStore(pVrf, &certList, CVB_FALSE);
    if (CVB_FAILED(ret)) {
        CVB_LOG_WARNING(ret, "Failed to add certificate into store.");
        ret = 0; /* ignore error */
    }

    goto CVB_FINAL;

CVB_ERR:
    ;
CVB_FINAL:
    CMSCBB_LIST_FREE(&certList, CmscbbX509FreeCert);
    CMSCBB_LIST_FREE(&crlList, CmscbbX509FreeCrl);
    return ret;
}


#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : InternalCloseFile
 * Description  : Close file when read file and update context is over
 * Params
 *   [IN] fpSrc: a file handle
 * Return Value : CVB_STATIC CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 10:06  t00307193  Create
 */
CVB_STATIC CVB_VOID InternalCloseFile(CVB_FILE_HANDLE fpSrc)
{
    CMSCBB_ERROR_CODE retcode = CmscbbFileClose(fpSrc);
    if (CVB_FAILED(retcode)) {
        CVB_LOG_WARNING(retcode, NULL);
    }
}

/*
 * Prototype    : InternalUpdateContent
 * Description  : Read content file and update into verify context
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] srcfile: source file to update signature context
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:26  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalUpdateContent(CMSCBB_VRF* pVrf, const CVB_CHAR* srcfile)
{
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 nRead;
    CVB_FILE_HANDLE fpSrc;
    const CVB_UINT32 nReadBuf = 4096;
    CVB_BYTE* pbReadBuf = CVB_NULL;
    CMSCBB_VRF_CTX ctx = (CMSCBB_VRF_CTX)pVrf;

    if (srcfile == CVB_NULL || *srcfile == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_SYS_FILE_OPEN, "Empty file path.");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    fpSrc = CmscbbFileOpen(srcfile, (const CVB_CHAR*)"rb");
    if (fpSrc == CVB_NULL) {
        CVB_LOG_ERROR1(CMSCBB_ERR_SYS_FILE_OPEN, "Can't open file '%s'.", srcfile);
        return CMSCBB_ERR_SYS_FILE_OPEN;
    }

    ret = CmscbbMalloc((CVB_VOID**)(&pbReadBuf), nReadBuf);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    nRead = (CVB_UINT32)CmscbbFileRead(pbReadBuf, nReadBuf, fpSrc);
    while (nRead != 0) {
        ret = CmscbbVerifyDetachSignatureUpdate(ctx, pbReadBuf, (CVB_INT32)nRead);
        CVB_GOTO_ERR_IF_FAIL_LOG(ret);

        nRead = (CVB_UINT32)CmscbbFileRead(pbReadBuf, nReadBuf, fpSrc);
    }

    goto CVB_FINAL;
CVB_ERR:
    ;
CVB_FINAL:
    InternalCloseFile(fpSrc);
    CmscbbFree(pbReadBuf);
    return ret;
}


/*
 * Prototype    : InternalCheckParamVerifyDetachSignatureQuick
 * Description  : When  verifying a separate signature,it needs a check for some parameters
 * Params
 *   [IN] ctx: Validation context
 *   [IN] srcfile: Verify the source file path of the signature file
 *   [IN] sigfile: CMS-formatted signature file path
 *   [OUT] result: Return validation result, 1 is passed, 0 is not passed
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:26  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyDetachSignatureQuick(const CMSCBB_VRF* pVrf, const CVB_CHAR* srcfile, const CVB_CHAR* sigfile, const CVB_INT32* result)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (srcfile == CVB_NULL || sigfile == CVB_NULL || result == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureQuick(CMSCBB_VRF_CTX ctx, const CVB_CHAR* srcfile, const CVB_CHAR* sigfile, CVB_INT32* result)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    CVB_BYTE* pbSig = CVB_NULL;
    CVB_INT32 nSig = 0;

    ret = InternalCheckParamVerifyDetachSignatureQuick(pVrf, srcfile, sigfile, result);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    *result = CVB_FALSE;
    ret = InternalReadFile(sigfile, &pbSig, &nSig);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CmscbbVerifyDetachSignatureBegin(ctx, pbSig, (CVB_UINT32)nSig);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = InternalUpdateContent(pVrf, srcfile);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CmscbbVerifyDetachSignatureFinal(ctx, result);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    goto CVB_FINAL;
CVB_ERR:
    ;
CVB_FINAL:
    CmscbbFree(pbSig);
    return ret;
}
#endif

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
/*
 * Prototype    : InternalGetDigestFromSignerInfo
 * Description  : get digest value from signer info
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] si: pkcs7 signer information
 *   [OUT] ppDigestInfo: digest information from pkcs7 signer information
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 10:54  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalGetDigestFromSignerInfo(const CmscbbPkcs7SignedInfo* si, CMSCBB_VERIFY_DIGEST_INFO** ppDigestInfo)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VERIFY_DIGEST_INFO* pDigestInfo = CVB_NULL;

    *ppDigestInfo = CVB_NULL;

    ret = CmscbbMallocWith0((CVB_VOID**)&pDigestInfo, sizeof(CMSCBB_VERIFY_DIGEST_INFO));
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    pDigestInfo->nDigestAlgID = CmscbbGetHashAoidFromSign(&(si->digest_algo.algorithm));
    CVB_GOTO_ERR_WITH_LOG_IF(AOID_UNKNOWN == pDigestInfo->nDigestAlgID, CMSCBB_ERR_PKI_CMS_DIGEST_ALGO_NOT_SUPPORT);

    pDigestInfo->nDigestSize = si->auth_attrs.hash_value.len;
    CVB_GOTO_ERR_WITH_LOG_IF(si->auth_attrs.hash_value.len > CMSCBB_MAX_DIGEST_SIZE, CMSCBB_ERR_SYS_MEM_COPY);

    ret = (CMSCBB_ERROR_CODE)memcpy_s(pDigestInfo->pbDigest, CMSCBB_MAX_DIGEST_SIZE, si->auth_attrs.hash_value.octs, si->auth_attrs.hash_value.len);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    *ppDigestInfo = pDigestInfo;
    goto CVB_FINAL;
CVB_ERR:
    InternalFreeMdInfo(pDigestInfo);
CVB_FINAL:
    return ret;
}
#endif

#if CMSCBB_SUPPORT_NO_SIGNED_ATTR
/*
 * Prototype    : InternalCreateVerifyHandle
 * Description  : internal create rsa verify handler
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] si: pkcs7 signer information
 *   [IN] pCert: X509 certificate
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 * Remarks      : this used to verify CMS without signed attribute
 *   Date              Author     Modification
 *   2015/11/10 10:56  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCreateVerifyHandle(CMSCBB_VRF* pVrf, const CmscbbPkcs7SignedInfo* si, const CmscbbX509Cert* pCert)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VERIFY_DIGEST_INFO* pDigestInfo = CVB_NULL;
    CmscbbBigInt e = {0};
    CmscbbBigInt n = {0}; /* public key elements */
    CMSCBB_AOIDS hashAlgo;
    CMSCBB_CRYPTO_VRF_CTX vrf_ctx = CVB_NULL;

    ret = CmscbbMallocWith0((CVB_VOID**)&pDigestInfo, sizeof(CMSCBB_VERIFY_DIGEST_INFO));
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    hashAlgo = CmscbbGetHashAoidFromSign(&(si->digest_algo.algorithm));
    CVB_GOTO_ERR_WITH_LOG_IF(AOID_UNKNOWN == hashAlgo, CMSCBB_ERR_PKI_CMS_HASH_ALGO);

    ret = CmscbbX509ExtractPublicKey(pCert, &e, &n);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CmscbbCryptoVerifyCreateCtx(&vrf_ctx);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CmscbbCryptoVerifyInit(vrf_ctx, &e, &n, (CVB_UINT32)hashAlgo);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    /* not support RSA encryption length more than 2048 bit */
    CVB_GOTO_ERR_WITH_LOG_IF(si->encrypted_digest.len > CMSCBB_MAX_CRYPT_SIZE, CMSCBB_ERR_PKI_CRYPTO_DIGEST_INIT);

    ret = (CMSCBB_ERROR_CODE)memcpy_s((CVB_VOID*)pDigestInfo->pbSignature, CMSCBB_MAX_CRYPT_SIZE, si->encrypted_digest.octs, si->encrypted_digest.len);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CMSCBB_LIST_ADD(&(pVrf->vrf_proc.md_info_list), pDigestInfo);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    pDigestInfo->nSignature = si->encrypted_digest.len;
    pDigestInfo->vrfCtx = vrf_ctx;
    goto CVB_FINAL;
CVB_ERR:
    InternalFreeMdInfo(pDigestInfo);
    CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
CVB_FINAL:
    return ret;
}
#endif

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
/*
 * Prototype    : InternalAddSignerInfoToVerifyProcess
 * Description  : internal create hash handler
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] si: pkcs7 signer information
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 * Remarks      : this used to verify CMS with signed attributes
 *   Date              Author     Modification
 *   2015/11/10 11:03  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalAddSignerInfoToVerifyProcess(CMSCBB_VRF* pVrf, const CmscbbPkcs7SignedInfo* si)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VERIFY_DIGEST_INFO* pDigestInfo = CVB_NULL;
    CMSCBB_VERIFY_DIGEST_INFO* pExist = CVB_NULL;
    CMSCBB_CRYPTO_MD_CTX md_ctx = CVB_NULL;
    CVB_INT iter = 0;

    ret = InternalGetDigestFromSignerInfo(si, &pDigestInfo);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    /* check if already have the signature with same digest algorithm */
    for (; iter < (CVB_INT)pVrf->vrf_proc.md_info_list.num; ++iter) {
        CMSCBB_VERIFY_DIGEST_INFO* pTempDi = pVrf->vrf_proc.md_info_list.data[iter];
        if (pTempDi == CVB_NULL) {
            continue;
        }
        if (pTempDi->nDigestAlgID == pDigestInfo->nDigestAlgID) {
            CVB_GOTO_ERR_WITH_LOG_IF(pTempDi->nDigestSize != pDigestInfo->nDigestSize, CMSCBB_ERR_PKI_CMS_DIGEST_VALUE_CONFLICT);
            CVB_GOTO_ERR_WITH_LOG_IF(0 != CmscbbMemCmp(pTempDi->pbDigest, pDigestInfo->pbDigest, pDigestInfo->nDigestSize), CMSCBB_ERR_PKI_CMS_DIGEST_VALUE_CONFLICT);
            pExist = pTempDi;
            break;
        }
    }

    if (pExist == CVB_NULL) {
        ret = CmscbbMdCreateCtx(&md_ctx);
        CVB_GOTO_ERR_IF_FAIL_LOG(ret);

        pDigestInfo->digestCtx = md_ctx;
        ret = CmscbbMdInit(md_ctx, (CVB_UINT32)pDigestInfo->nDigestAlgID);
        CVB_GOTO_ERR_IF_FAIL_LOG(ret);

        ret = CMSCBB_LIST_ADD(&(pVrf->vrf_proc.md_info_list), pDigestInfo);
        CVB_GOTO_ERR_IF_FAIL_LOG(ret);
    } else {
        InternalFreeMdInfo(pDigestInfo);
    }

    return ret;
CVB_ERR:
    InternalFreeMdInfo(pDigestInfo);
    return ret;
}
#endif

/*
 * Prototype    : InternalExtractCertsIntoVerifyContext
 * Description  : extract certificates from signer info into verify context
 * Params
 *   [IN] pVrf: data for verify context 
 *   [IN] p7signed: pckcs7 context info
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 11:22  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalExtractCertsIntoVerifyContext(const CMSCBB_VRF* pVrf, const CmscbbPkcs7Content* p7signed)
{
    const LIST_OF(CmscbbX509Cert)* certs = &(p7signed->signed_data.certificates.certs);

    if (certs->num == 0) {
        CVB_LOG_INFO(0, "No certificate contained in the CMS.");
        return CVB_SUCCESS;
    }

    return InternalAddCertToStore(pVrf, certs, CVB_FALSE);
}

/*
 * Prototype    : InternalHashContent
 * Description  : get hash value of the content
 * Params
 *   [IN] pbContent:content object
 *   [IN] nContent: the length of context object
 *   [IN] hashAlgoId: ASN object hash id
 *   [OUT] pbDigest: digest object 
 *   [OUT] nDigest: the length of digest object 
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 11:29  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalHashContent(const CVB_BYTE* pbContent, CVB_UINT32 nContent, CMSCBB_AOIDS hashAlgoId, CVB_BYTE* pbDigest, CVB_UINT32* nDigest, const CVB_UINT32* pbMaxLength)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_CRYPTO_MD_CTX md_ctx = CVB_NULL;


    ret = CmscbbMdCreateCtx(&md_ctx);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbMdInit(md_ctx, (CVB_UINT32)hashAlgoId);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CmscbbMdUpdate(md_ctx, pbContent, nContent);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CmscbbMdFinal(md_ctx, pbDigest, nDigest, pbMaxLength);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    goto CVB_FINAL;
CVB_ERR:
    ;
CVB_FINAL:
    CmscbbMdDestoryCtx(md_ctx);
    return ret;
}

static void dump_data(const uint8_t* data, uint32_t len)
{
    uint32_t i;
    tloge("buffer len %d\n", len);
    if ((NULL == data) || (0 == len)) return;
    uint32_t loop = len / 8;
    for (i = 0; i < loop*8; i=i+8)
        tloge("%x %x %x %x %x %x %x %x", *(data + i), *(data + i + 1), *(data + i + 2), *(data + i + 3),*(data + i + 4), *(data + i + 5),*(data + i + 6), *(data + i + 7));
    for(i = loop*8; i < len; i++) tloge("%x", *(data + i));
    tloge("\n");
    return;
}

/*
 * Prototype    : InternalVerifyTstInfo
 * Description  : verify TST info in timestamp
 * Params
 *   [IN] pVrf: data for verify context 
 *   [IN] encodedTsInfo: encoded content in timestamp, which should be CmscbbTimestampInfo
 *   [IN] si: signer info in CMS
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 11:29  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalVerifyTstInfo(CMSCBB_VRF* pVrf, const CmscbbAsnOcts* encoded_ts_info, const CmscbbPkcs7SignedInfo* si)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbTimestampInfo* tstInfo = CVB_NULL;
    CMSCBB_AOIDS hashAlgoId;
    CVB_BYTE pbDigest[CMSCBB_MAX_DIGEST_SIZE] = {0};
    CVB_UINT32 nDigest = 0;
    CVB_UINT32 pbDigestMaxLen = CMSCBB_MAX_DIGEST_SIZE;

    CVB_UINT32 nDecoded = 0;
    CmscbbDatetime dateTs = {0};
    CVB_TIME_T timeSign;

    /* decode TST info */
    ret = CmscbbAsnDecode(encoded_ts_info->octs, encoded_ts_info->len, &g_itemCmscbbTimestampInfo, CVB_ASN_NORMAL, (CVB_VOID**)&tstInfo, &nDecoded);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    hashAlgoId = CmscbbGetHashAoidFromSign(&(tstInfo->msg_imprint.hash_algo.algorithm));
    CVB_GOTO_ERR_WITH_LOG_IF(AOID_UNKNOWN == hashAlgoId, CMSCBB_ERR_PKI_CERT_SIG_ALGO);

    /* hash signature value in parent(CMS) signer info */
    ret = InternalHashContent(si->encrypted_digest.octs, si->encrypted_digest.len, hashAlgoId, pbDigest, &nDigest, &pbDigestMaxLen);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    if (tstInfo->msg_imprint.hash_value.len != nDigest || CmscbbMemCmp(tstInfo->msg_imprint.hash_value.octs, pbDigest, nDigest) != 0) {
        ret = CMSCBB_ERR_PKI_TST_INFO_VERIFY;
        dump_data(si->encrypted_digest.octs, si->encrypted_digest.len);
        dump_data(tstInfo->msg_imprint.hash_value.octs, tstInfo->msg_imprint.hash_value.len);
        dump_data(pbDigest, nDigest);
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_TST_INFO_VERIFY, "the timestamp not match with target cms.");
        goto CVB_ERR;
    }

    /* set timestamp time into verify parameter */
    ret = CmscbbConvertFromTime(&(tstInfo->time), &dateTs);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    timeSign = CmscbbMktime(&dateTs);
    pVrf->base_time = timeSign;
    goto CVB_FINAL;
CVB_ERR:
    ;
CVB_FINAL:
    CmscbbAsnFree(tstInfo, &g_itemCmscbbTimestampInfo, CVB_ASN_NORMAL);
    return ret;
}

/*
 * Prototype    : InternalVerifyIssuerCert
 * Description  : verify certificate as an issuer
 * Params
 *   [IN] pVrf: data for verify context 
 *   [IN] cert: X509 certificate
 *   [IN] expExtKu: expected key usage
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/12/26 10:17  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalVerifyIssuerCert(CMSCBB_VRF* pVrf, CmscbbX509Cert* cert, CVB_UINT32 expExtKu)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BOOL isCertValid = CVB_FALSE;

    if (((CVB_UINT32)cert->toBeSigned.extensions.ku & CMSCBB_X509_KU_DIGITAL_SIGNATURE) == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE);
    }
    if (((CVB_UINT32)cert->toBeSigned.extensions.exku & expExtKu) == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CERT_UNMATCHED_PURPOSE);
    }

    ret = CmscbbPkiVerifyCert(pVrf, cert, CVB_TRUE, expExtKu == CMSCBB_PKI_XKU_TIMESTAMP ? CVB_TRUE : CVB_FALSE, &isCertValid);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    if (isCertValid == CVB_FALSE) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CERT_VERIFY_FAILED, CVB_NULL);
        return CMSCBB_ERR_PKI_CERT_VERIFY_FAILED;
    }

    return CVB_SUCCESS;
}

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
#define TAG_MASK 0xFF
#define CLS_BIT_POS 6
#define FORM_BIT_POS 5
/*
 * Prototype    : CmscbbPkcs7DetachedSignatureVerify
 * Description  : verify certificate
 * Params
 *   [IN] si: signer info in CMS
 *   [IN] cert: X509 certificate
 *   [OUT] r_result: verify result
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/12/26 10:17  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbPkcs7DetachedSignatureVerify(const CmscbbPkcs7SignedInfo* si, const CmscbbX509Cert* pCert, CVB_INT* r_result)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbBigInt e = {0};
    CmscbbBigInt n = {0};
    CMSCBB_AOIDS hashAlgo;
    CMSCBB_CRYPTO_VRF_CTX vrf_ctx = CVB_NULL;
    CVB_BYTE tagCode;
#if !CMSCBB_SUPPORT_DIGEST_STREAM_MODE
    CVB_BYTE* pbContentTemp = CVB_NULL;
#endif

    if (si == CVB_NULL || pCert == CVB_NULL || r_result == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    hashAlgo = CmscbbGetHashAoidFromSign(&(si->digest_algo.algorithm));
    if (hashAlgo == AOID_UNKNOWN) {
        CVB_LOG_DEBUG(CMSCBB_ERR_PKI_CMS_HASH_ALGO, CVB_NULL);
        return CMSCBB_ERR_PKI_CMS_HASH_ALGO;
    }

    ret = CmscbbX509ExtractPublicKey(pCert, &e, &n);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* use public key to verify signer info */
    ret = CmscbbCryptoVerifyCreateCtx(&vrf_ctx);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    *r_result = CVB_FALSE;

    {
        tagCode = TAG_MASK & (CVB_BYTE)(((((CVB_BYTE)si->rawSigned.tag.cls) << CLS_BIT_POS) & CMSCBB_TAG_CLASS_MASK)
        | ((((CVB_BYTE)si->rawSigned.tag.form) << FORM_BIT_POS) & CMSCBB_TAG_PC_MASK) | (CVB_BYTE)si->rawSigned.tag.code);

        ret = CmscbbCryptoVerifyInit(vrf_ctx, &e, &n, (CVB_UINT32)hashAlgo);
        if (CVB_FAILED(ret)) {
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "Failed to init verify context.");
            return ret;
        }

    #if CMSCBB_SUPPORT_DIGEST_STREAM_MODE
        /* the tag type of signed attribute is implicit, so send real tag code */
        ret = CmscbbCryptoVerifyUpdate(vrf_ctx, &tagCode, 1);
        if (CVB_FAILED(ret)) {
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "Failed to init verify context.");
            return ret;
        }

        ret = CmscbbCryptoVerifyUpdate(vrf_ctx, si->rawSigned.octs + 1, si->rawSigned.len - 1);
        if (CVB_FAILED(ret)) {
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "Failed to init verify context.");
            return ret;
        }
        ret = CmscbbCryptoVerifyFinal(vrf_ctx, si->encrypted_digest.octs, si->encrypted_digest.len, r_result);
        if (CVB_FAILED(ret)) {
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "Failed to init verify context.");
            return ret;
        }
    #else
        ret = CmscbbMallocWith0((CVB_VOID**)&pbContentTemp, si->rawSigned.len + 1);
        if (CVB_FAILED(ret)) {
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "CmscbbMallocWith0 failed!");
            return (ret);
        }
        pbContentTemp[0] = tagCode;
        ret = (CMSCBB_ERROR_CODE)memcpy_s((CVB_VOID *) &(pbContentTemp[1]), si->rawSigned.len - 1, (const CVB_VOID *)(si->rawSigned.octs + 1), si->rawSigned.len - 1);
        if (CVB_FAILED(ret)) {
            CmscbbFree(pbContentTemp);
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "CmscbbMallocWith0 failed!");
            return (ret);
        }
        pbContentTemp[si->rawSigned.len] = '\0';

        /* the tag type of signed attribute is implicit, so send real tag code */
        ret = CmscbbCryptoVerifyUpdate(vrf_ctx, pbContentTemp, si->rawSigned.len);
        if (CVB_FAILED(ret)) {
            CmscbbFree(pbContentTemp);
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "Failed to init verify context.");
            return ret;
        }

        ret = CmscbbCryptoVerifyFinal(vrf_ctx, si->encrypted_digest.octs, si->encrypted_digest.len, r_result);
        if (CVB_FAILED(ret)) {
            CmscbbFree(pbContentTemp);
            CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
            CVB_LOG_ERROR(ret, "Failed to init verify context.");
            return ret;
        }

        CmscbbFree(pbContentTemp);
    #endif
    }

    CmscbbCryptoVerifyDestroyCtx(vrf_ctx);
    return CVB_SUCCESS;
}
#endif

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
/*
 * Prototype    : InternalVerifyAttributeSign
 * Description  : verify Signer attribute
 * Params
 *   [IN] signerInfoTs: signer info in CMS with timestamps
 *   [IN] cert: X509 certificate
 *   [IN] encodedTsInfo: encode timestamp information
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/12/26 10:17  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalVerifyAttributeSign(const CmscbbPkcs7SignedInfo *signerInfoTs, const CmscbbX509Cert *cert, const CmscbbAsnOcts *encodedTsInfo)
{
    CMSCBB_ERROR_CODE ret;
    CVB_INT vrf_result = 0;
    CMSCBB_VERIFY_DIGEST_INFO *pDigestInfo = CVB_NULL;
    CVB_BYTE pbDigest[CMSCBB_MAX_DIGEST_SIZE] = {0};
    CVB_UINT32 nDigest = 0;
    CVB_UINT32 pbDigestMaxLen = CMSCBB_MAX_DIGEST_SIZE;

    if (signerInfoTs->rawSigned.octs == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_DECODE, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_DECODE);
    }

    ret = CmscbbPkcs7DetachedSignatureVerify(signerInfoTs, cert, &vrf_result);
    if (CVB_FAILED(ret) || (CVB_BOOL)vrf_result != CVB_TRUE) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_VERIFY_FAILED, CVB_NULL);
        return CMSCBB_ERR_PKI_CMS_VERIFY_FAILED;
    }

    ret = InternalGetDigestFromSignerInfo(signerInfoTs, &pDigestInfo);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    ret = InternalHashContent(encodedTsInfo->octs, encodedTsInfo->len, pDigestInfo->nDigestAlgID, pbDigest, &nDigest, &pbDigestMaxLen);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, "verify timestamp digest failed.");
        InternalFreeMdInfo(pDigestInfo);
        return ret;
    }

    if (pDigestInfo->nDigestSize != nDigest || CmscbbMemCmp(pDigestInfo->pbDigest, pbDigest, nDigest) != 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_TST_CONTENT_VERIFY, "verify timestamp signature failed.");
        InternalFreeMdInfo(pDigestInfo);
        return CMSCBB_ERR_PKI_TST_CONTENT_VERIFY;
    }

    InternalFreeMdInfo(pDigestInfo);
    return CVB_SUCCESS;
}
#endif

/*
 * Prototype    : InternalVerifyTsSignerInfo
 * Description  : verify signer info in timestamp
 * Params
 *   [IN] pVrf:  data for verify context
 *   [IN] si_ts: signer info in CMS with timestamps
 *   [IN] encoded_ts_info: encode timstamp information
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 11:43  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalVerifyTsSignerInfo(CMSCBB_VRF *pVrf, const CmscbbPkcs7SignedInfo *si_ts, const CmscbbAsnOcts *encoded_ts_info)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbX509Cert *cert;

    cert = CmscbbPkiFindCertByIssuerSn(pVrf, &(si_ts->issuerSn.issuer), &(si_ts->issuerSn.sn));
    if (cert == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_TST_ISSUER_NOT_FOUND, CVB_NULL);
        return CMSCBB_ERR_PKI_TST_ISSUER_NOT_FOUND;
    }

    ret = InternalVerifyIssuerCert(pVrf, cert, CMSCBB_PKI_XKU_TIMESTAMP);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
    if (si_ts->auth_attrs.hash_value.octs != CVB_NULL) {
        ret = InternalVerifyAttributeSign(si_ts, cert, encoded_ts_info);
        if (CVB_FAILED(ret)) {
            CVB_LOG_ERROR(ret, CVB_NULL);
            return ret;
        }
    } else {
        CVB_BOOL result = CVB_FALSE;
        ret = CmscbbX509PubKeyVerify(encoded_ts_info->octs, encoded_ts_info->len, si_ts->encrypted_digest.octs,
                                     si_ts->encrypted_digest.len, &cert->toBeSigned.subjectPubKey.subjectPublicKey, &(si_ts->digest_algo.algorithm), &result);
        if (CVB_FAILED(ret)) {
            CVB_LOG_ERROR(ret, CVB_NULL);
            return ret;
        }

        if (result != 1) {
            return CMSCBB_ERR_PKI_TST_CONTENT_VERIFY;
        }
    }
#else
    CVB_BOOL result = CVB_FALSE;
    ret = CmscbbX509PubKeyVerify(encoded_ts_info->octs, encoded_ts_info->len, si_ts->encrypted_digest.octs,
        si_ts->encrypted_digest.len, &cert->toBeSigned.subjectPubKey.subjectPublicKey, &(si_ts->digest_algo.algorithm), &result);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    if (result != 1) {
        return CMSCBB_ERR_PKI_TST_CONTENT_VERIFY;
    }
#endif

#if CMSCBB_ALLOW_NO_CHECK_TSA_CRL
    if (cert->toBeSigned.serialNumber.len > CMSCBB_MAX_SN_LEN) {
        CVB_LOG_ERROR(CMSCBB_ERR_SYS_MEM_COPY, CVB_NULL);
        return CMSCBB_ERR_SYS_MEM_COPY;
    }
    ret = (CMSCBB_ERROR_CODE)memcpy_s(pVrf->tsa_cert_sn.sn, CMSCBB_MAX_SN_LEN, cert->toBeSigned.serialNumber.octs, cert->toBeSigned.serialNumber.len);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(CMSCBB_ERR_SYS_MEM_COPY, CVB_NULL);
        return ret;
    }
    pVrf->tsa_cert_sn.snLenth = cert->toBeSigned.serialNumber.len;
#endif

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalVerifyTimeStamp
 * Description  : verify timestamp
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] si: signer info in CMS with timestamps
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 11:47  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalVerifyTimeStamp(CMSCBB_VRF* pVrf, const CmscbbPkcs7SignedInfo* si)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbPkcs7Content* pkcs7Ts = CVB_NULL;
    CVB_UINT32 nDecoded = 0;
    SET_OF(CmscbbPkcs7SignedInfo)* signerInfos = CVB_NULL;
    CVB_INT iter = 0;
    CmscbbAsnOcts* encodedTsInfo = CVB_NULL;

    /* get timestamp from CMS */
    ret = CmscbbPkcs7DecodeSigned(si->unauth_attrs.timestamp.octs, si->unauth_attrs.timestamp.len, &pkcs7Ts, &nDecoded);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    /* get encoded TST info from timestamp */
    ret = CmscbbAsnDecode(pkcs7Ts->signed_data.content.content.octs, pkcs7Ts->signed_data.content.content.len,
                          &g_itemCmscbbAsnOcts, CVB_ASN_NORMAL, (CVB_VOID**)&encodedTsInfo, &nDecoded);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = InternalVerifyTstInfo(pVrf, encodedTsInfo, si);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = InternalExtractCertsIntoVerifyContext(pVrf, pkcs7Ts);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    signerInfos = &(pkcs7Ts->signed_data.signer_infos.infos);
    for (; iter < (CVB_INT)signerInfos->num; ++iter) {
        ret = InternalVerifyTsSignerInfo(pVrf, &(signerInfos->data[iter]), encodedTsInfo);
        CVB_GOTO_ERR_IF_FAIL_LOG(ret);
    }

    goto CVB_FINAL;
CVB_ERR:
    ;
CVB_FINAL:
    CmscbbAsnFree(encodedTsInfo, &g_itemCmscbbAsnOcts, CVB_ASN_NORMAL);
    CmscbbPkcs7FreeSigned(pkcs7Ts);
    return ret;
}


#if CMSCBB_SUPPORT_PEM
/*
 * Prototype    : InternalBase64Decode
 * Description  : decode base64 stream
 * Params
 *   [IN] pszB64Begin: begin of base64 stream
 *   [IN] pszB64End: end of base64 stream
 *   [OUT] ppbDer: decode result
 *   [OUT] pDer: the length of decode result
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 11:47  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalBase64Decode(const CVB_CHAR* pszB64Begin, const CVB_CHAR* pszB64End, CVB_BYTE** ppbDer, CVB_UINT32* pDer)
{
    CVB_UINT32 nDer = 0;
    CVB_BYTE* pbDer = CVB_NULL;
    CMSCBB_ERROR_CODE ret;

    ret = CmscbbBase64Decode(pszB64Begin, (CVB_UINT32)(pszB64End - pszB64Begin), CVB_NULL, &nDer);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }
    if (nDer == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_INVALID_PEM, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_INVALID_PEM);
    }

    ret = CmscbbMalloc((CVB_VOID**)&pbDer, nDer);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbBase64Decode(pszB64Begin, (CVB_UINT32)(pszB64End - pszB64Begin), pbDer, &nDer);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        CmscbbFree(pbDer);
        return ret;
    }

    *ppbDer = pbDer;
    *pDer = nDer;
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalPemDecodeCms
 * Description  : decode PEM format CMS
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pszPem: pem header 
 *   [IN] nSigLength: signed of  length
 *   [OUT] p7signed: pkcs7 singed content
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 12:01  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalPemDecodeCms(CMSCBB_VRF* pVrf, const CVB_CHAR* pszPem, CVB_UINT32 nSigLength, CmscbbPkcs7Content** p7signed)
{
    CMSCBB_ERROR_CODE ret;
    const CVB_CHAR* pszB64Begin = CVB_NULL;
    const CVB_CHAR* pszB64End = CVB_NULL;
    CVB_BYTE* pbDer = CVB_NULL;
    CVB_UINT32 nDer = 0;
    CVB_UINT32 nDecoded = 0;
    CVB_UINT32 nEncoded;

    /* check the PEM header, get base64 encoded content */
    if (CmscbbStrNCmp(pszPem, (const CVB_CHAR*)CVB_PEM_SYMBOL_CMS, CVB_PEM_SYMBOL_CMS_LEN) == 0) {
        pszB64Begin = pszPem + CVB_PEM_SYMBOL_CMS_LEN;

        pszB64End = CmscbbStrStr(pszPem, (const CVB_CHAR*)CVB_PEM_SYMBOL_CMS_END);
        if (CVB_NULL == pszB64End) {
            CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_INVALID_PEM, CVB_NULL);
            return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
        }
    } else if (CmscbbStrNCmp(pszPem, (const CVB_CHAR*)CVB_PEM_SYMBOL_PKCS7, CVB_PEM_SYMBOL_PKCS7_LEN) == 0) {
        pszB64Begin = pszPem + CVB_PEM_SYMBOL_PKCS7_LEN;
        pszB64End = CmscbbStrStr(pszPem, (const CVB_CHAR*)CVB_PEM_SYMBOL_PKCS7_END);
        if (CVB_NULL == pszB64End) {
            CVB_LOG_ERROR(CMSCBB_ERR_UNDEFINED, CVB_NULL);
            return (CMSCBB_ERR_UNDEFINED);
        }
    } else {
        return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
    }

    nEncoded = (CVB_UINT32)(pszB64End - pszB64Begin);
    if (nEncoded > nSigLength) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_INVALID_PEM, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_INVALID_PEM);
    }

    ret = InternalBase64Decode(pszB64Begin, pszB64End, &pbDer, &nDer);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbPkcs7DecodeSigned(pbDer, nDer, p7signed, &nDecoded);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CMSCBB_LIST_ADD(&(pVrf->raw_set), pbDer);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    return CVB_SUCCESS;
CVB_ERR:
    CmscbbFree(pbDer);
    if (p7signed != CVB_NULL) {
        CmscbbPkcs7FreeSigned(*p7signed);
        *p7signed = CVB_NULL;
    }
    return ret;
}
#endif

/*
 * Prototype    : InternalVerifyCms
 * Description  : verify CMS
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] p7signed: pkcs7 signed content
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 12:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalVerifyCms(CMSCBB_VRF* pVrf, const CmscbbPkcs7Content* p7signed)
{
    CMSCBB_ERROR_CODE ret;
    CVB_INT iter = 0;
    const SET_OF(CmscbbPkcs7SignedInfo)* signerInfos;
    ret = InternalExtractCertsIntoVerifyContext(pVrf, p7signed);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    signerInfos = &(p7signed->signed_data.signer_infos.infos);
    for (; iter < (CVB_INT)(signerInfos->num); ++iter) {
        const CmscbbPkcs7SignedInfo* si = &(signerInfos->data[iter]);
        CmscbbX509Cert* cert = CVB_NULL;

        /* if verify succeed, the pVrf will be assigned with timestamp time */
        ret = InternalVerifyTimeStamp(pVrf, si);
        if (CVB_FAILED(ret)) {
            CVB_LOG_ERROR(ret, CVB_NULL);
            return ret;
        }

        cert = CmscbbPkiFindCertByIssuerSn(pVrf, &(si->issuerSn.issuer), &(si->issuerSn.sn));
        if (cert == CVB_NULL) {
            CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_ISSUER_NOT_FOUND, CVB_NULL);
            return (CMSCBB_ERR_PKI_CMS_ISSUER_NOT_FOUND);
        }

        /* author certificate must have extent usage of code sign */
        ret = InternalVerifyIssuerCert(pVrf, cert, CMSCBB_PKI_XKU_CODE_SIGN);
        if (CVB_FAILED(ret)) {
            CVB_LOG_ERROR(ret, CVB_NULL);
            return ret;
        }

        /* there are two kind of signer info, one have signed attribute, the other don't; they have different way to verify */
        if (si->auth_attrs.hash_value.octs != CVB_NULL) {
#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
            CVB_INT vrf_result = 0;

            if (si->rawSigned.octs == CVB_NULL) {
                CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_DECODE, CVB_NULL);
                return (CMSCBB_ERR_PKI_CMS_DECODE);
            }

            ret = CmscbbPkcs7DetachedSignatureVerify(si, cert, &vrf_result);
            if (CVB_FAILED(ret) || (CVB_BOOL)vrf_result != CVB_TRUE) {
                CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_VERIFY_FAILED, CVB_NULL);
                return (CMSCBB_ERR_PKI_CMS_VERIFY_FAILED);
            }

            ret = InternalAddSignerInfoToVerifyProcess(pVrf, si);
            if (CVB_FAILED(ret)) {
                CVB_LOG_ERROR(ret, CVB_NULL);
                return ret;
            }
#else
            return CMSCBB_ERR_PKI_CMS_VERIFY_FAILED;
#endif
        } else {
#if CMSCBB_SUPPORT_NO_SIGNED_ATTR
            ret = InternalCreateVerifyHandle(pVrf, si, cert);
            if (CVB_FAILED(ret)) {
                CVB_LOG_ERROR(ret, CVB_NULL);
                return ret;
            }
#else
            return CMSCBB_ERR_PKI_CMS_VERIFY_FAILED;
#endif
        }
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckParamVerifyDetachSignatureBegin
 * Description  : check verification signatures parameters
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] p7signed: Signature data in CMS format
 *   [IN] nSigLength: The length of the signature data
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 12:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyDetachSignatureBegin(const CMSCBB_VRF* pVrf, const CVB_BYTE* pbSignature, CVB_UINT32 nSigLength)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (pbSignature == CVB_NULL || nSigLength == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureBegin(CMSCBB_VRF_CTX ctx, const CVB_BYTE* pbSignature, CVB_UINT32 nSigLength)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    CmscbbPkcs7Content* p7signed = CVB_NULL;
    CVB_UINT32 nDecoded = 0;

    ret = InternalCheckParamVerifyDetachSignatureBegin(pVrf, pbSignature, nSigLength);
    if (CVB_FAILED(ret)) {
        return ret;
    }

#if CMSCBB_ALLOW_NO_CHECK_TSA_CRL
    ret = (CMSCBB_ERROR_CODE)memset_s(&pVrf->tsa_cert_sn, sizeof(CmscbbSerialNum), 0, sizeof(CmscbbSerialNum));
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }
#endif

#if CMSCBB_SUPPORT_PEM
    if (nSigLength < CVB_MIN_PEM_LEN) {
        return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
    }

    if (CmscbbStrNCmp((const CVB_CHAR*)pbSignature, (const CVB_CHAR*)CVB_PEM_SYMBOL,
                      (CVB_SIZE_T)CmscbbStrlen((const CVB_CHAR*)CVB_PEM_SYMBOL)) == 0) {
        CVB_BYTE* pbPemContent = CVB_NULL;
        ret = CmscbbMallocWith0((CVB_VOID**)&pbPemContent, nSigLength + 1); /* The string must end with 0 to ensure Strstr is not crossed */
        if (CVB_FAILED(ret)) {
            CVB_LOG_WARNING(ret, CVB_NULL);
            return ret;
        }

        ret = (CMSCBB_ERROR_CODE)memcpy_s((CVB_VOID*)pbPemContent, nSigLength, (const CVB_VOID*)pbSignature, nSigLength);
        if (CVB_FAILED(ret)) {
            CmscbbFree((CVB_VOID*)pbPemContent);
            return ret;
        }
        ret = InternalPemDecodeCms(pVrf, (const CVB_CHAR*)pbPemContent, nSigLength, &p7signed);
        CmscbbFree((CVB_VOID*)pbPemContent);
    } else {
        ret = CmscbbPkcs7DecodeSigned(pbSignature, nSigLength, &p7signed, &nDecoded);
    }
#else
    ret = CmscbbPkcs7DecodeSigned(pbSignature, nSigLength, &p7signed, &nDecoded);
#endif

    if (p7signed == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_NO_SIGNER_INFO, NULL);
        return CMSCBB_ERR_PKI_CMS_NO_SIGNER_INFO;
    }
    if (CVB_FAILED(ret)) {
        CmscbbPkcs7FreeSigned(p7signed);
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_NO_SIGNER_INFO, NULL);
        return CMSCBB_ERR_PKI_CMS_NO_SIGNER_INFO;
    }

    ret = InternalVerifyCms(pVrf, p7signed);
    CmscbbPkcs7FreeSigned(p7signed);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, NULL);
        return ret;
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckParmVerifyDetachSignatureUpdate
 * Description  : check parameter when update the contents of the signature
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbContent: The data for the signature content
 *   [IN] nContentLength: The length of the signed content fragment data
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:31  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParmVerifyDetachSignatureUpdate(const CMSCBB_VRF* pVrf, const CVB_BYTE* pbContent, CVB_INT32 nContentLength)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (pbContent == CVB_NULL || nContentLength == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureUpdate(CMSCBB_VRF_CTX ctx, const CVB_BYTE* pbContent, CVB_INT32 nContentLength)
{
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    CMSCBB_ERROR_CODE ret;
    LIST_OF(CMSCBB_VERIFY_DIGEST_INFO)* pDigestInfoList;
    CVB_INT iter = 0;

    ret = InternalCheckParmVerifyDetachSignatureUpdate(pVrf, pbContent, nContentLength);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    pDigestInfoList = &(pVrf->vrf_proc.md_info_list);
    if (pDigestInfoList->num == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_UPDATE_FAILED, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_UPDATE_FAILED);
    }

    for (; iter < (CVB_INT)pDigestInfoList->num; ++iter) {
        CMSCBB_VERIFY_DIGEST_INFO* pDigestInfo = pDigestInfoList->data[iter];
        if (pDigestInfo->digestCtx != CVB_NULL) {
#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
            /* CMS with signed attributes */
            ret = CmscbbMdUpdate(pDigestInfo->digestCtx, pbContent, (CVB_UINT32)nContentLength);
            if (CVB_FAILED(ret)) {
                CVB_LOG_ERROR(ret, CVB_NULL);
                return ret;
            }
#else
            return CMSCBB_ERR_PKI_CMS_UPDATE_FAILED;
#endif
        } else {
#if CMSCBB_SUPPORT_NO_SIGNED_ATTR
            if (pDigestInfo->vrfCtx == CVB_NULL) {
                return CMSCBB_ERR_PKI_CMS_UPDATE_FAILED;
            }
            /* CMS no signed attributes */
            ret = CmscbbCryptoVerifyUpdate(pDigestInfo->vrfCtx, pbContent, (CVB_UINT32)nContentLength);
            if (CVB_FAILED(ret)) {
                CVB_LOG_ERROR(ret, CVB_NULL);
                return ret;
            }
#else
            return CMSCBB_ERR_PKI_CMS_UPDATE_FAILED;
#endif
        }
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckParamVerifyDetachSignatureFinal
 * Description  : check paramters when verify detach signatures
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] result: Validation results, 1 means pass, 0 means no.
 * Return Value : return cvb_success correctly, error return error code
 * Remarks      : <TODO>
 *   Date              Author     Modification
 *   2015/11/09 18:35  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyDetachSignatureFinal(const CMSCBB_VRF* pVrf, const CVB_INT32* result)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (result == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureFinal(CMSCBB_VRF_CTX ctx, CVB_INT32* result)
{
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    CMSCBB_ERROR_CODE ret;
    LIST_OF(CMSCBB_VERIFY_DIGEST_INFO)* pDigestInfoList;
    CVB_INT iter = 0;

    ret = InternalCheckParamVerifyDetachSignatureFinal(pVrf, result);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    *result = CVB_TRUE;

    pDigestInfoList = &(pVrf->vrf_proc.md_info_list);
    for (; iter < (CVB_INT)pDigestInfoList->num; ++iter) {
        CMSCBB_VERIFY_DIGEST_INFO* pDigestInfo = pDigestInfoList->data[iter];

        if (pDigestInfo->digestCtx != CVB_NULL) {
#       if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
            CVB_BYTE pbDigest[CMSCBB_MAX_DIGEST_SIZE] = {0};
            CVB_UINT32 nDigestLen = 0;
            CVB_UINT32 digestMaxLen = CMSCBB_MAX_DIGEST_SIZE;

            ret = CmscbbMdFinal(pDigestInfo->digestCtx, pbDigest, &nDigestLen, &digestMaxLen);
            if (CVB_FAILED(ret)) {
                break;
            }

            if (pDigestInfo->nDigestSize != nDigestLen) {
                *result = CVB_FALSE;
                break;
            }

            if (CmscbbMemCmp(pbDigest, pDigestInfo->pbDigest, pDigestInfo->nDigestSize) != 0) {
                *result = CVB_FALSE;
                break;
            }
#       else
            ret = CMSCBB_ERR_PKI_CMS_VERIFY_FAILED;
            break;
#       endif
        } else {
#       if CMSCBB_SUPPORT_NO_SIGNED_ATTR
            CVB_INT sigValid = 0;
            if (pDigestInfo->vrfCtx == CVB_NULL) {
                ret = CMSCBB_ERR_PKI_CMS_VERIFY_FAILED;
                break;
            }

            ret = CmscbbCryptoVerifyFinal(pDigestInfo->vrfCtx, pDigestInfo->pbSignature, pDigestInfo->nSignature, &sigValid);
            if (CVB_FAILED(ret)) {
                break;
            }

            *result = sigValid;
#       else
            ret = CMSCBB_ERR_PKI_CMS_VERIFY_FAILED;
            break;
#       endif
        }
    }

    CMSCBB_LIST_FREE(pDigestInfoList, InternalFreeMdInfo);

    if (CVB_FAILED(ret)) {
        *result = CVB_FALSE;
        CVB_LOG_ERROR(ret, "Verify Signature Content failed.");
        return ret;
    }
    return CVB_SUCCESS;
}

#if CMSCBB_ALLOW_NO_CHECK_TSA_CRL
/*
 * Prototype    : InternalCheckParamVerifyGetTsaCertSn
 * Description  : check paramters when verify detach signatures
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] sn: serials number type
 * Return Value : return cvb_success correctly, error return error code
 * Remarks      : <TODO>
 *   Date              Author     Modification
 *   2015/11/09 18:35  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamVerifyGetTsaCertSn(const CMSCBB_VRF* pVrf, const CmscbbSerialNum* sn)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (sn == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : CmscbbVerifyGetTsaCertSn
 * Description  : verify detach signatures with serials number type
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] sn: serials number type.
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:35  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyGetTsaCertSn(CMSCBB_VRF_CTX ctx, CmscbbSerialNum* sn)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;

    ret = InternalCheckParamVerifyGetTsaCertSn(pVrf, sn);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    if (pVrf->tsa_cert_sn.snLenth == 0) {
        return CMSCBB_ERR_PKI_TST_ISSUER_NOT_FOUND;
    }

    ret = (CMSCBB_ERROR_CODE)memcpy_s(sn->sn, CMSCBB_MAX_SN_LEN, pVrf->tsa_cert_sn.sn, pVrf->tsa_cert_sn.snLenth);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    sn->snLenth = pVrf->tsa_cert_sn.snLenth;
    return CVB_SUCCESS;
}
#endif

/*
 * Prototype    : InternalFreeMdInfo
 * Description  : free CMSCBB_VERIFY_DIGEST_INFO
 * Params
 *   [IN] pDigestInfo: verify digest info
 * Return Value : CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 14:52  t00307193  Create
 */
CVB_STATIC CVB_VOID InternalFreeMdInfo(CMSCBB_VERIFY_DIGEST_INFO* pDigestInfo)
{
    if (pDigestInfo == CVB_NULL) {
        return;
    }

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
    if (pDigestInfo->digestCtx != CVB_NULL) {
        CmscbbMdDestoryCtx(pDigestInfo->digestCtx);
    }
#endif

#if CMSCBB_SUPPORT_NO_SIGNED_ATTR
    if (pDigestInfo->vrfCtx != CVB_NULL) {
        CmscbbCryptoVerifyDestroyCtx(pDigestInfo->vrfCtx);
    }
#endif
    CmscbbFree(pDigestInfo);
}

CMSCBB_ERROR_CODE CmscbbVrfCtxFree(CMSCBB_VRF_CTX ctx)
{
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;

    if (pVrf == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    CmscbbPkiUninit(pVrf);

    CMSCBB_LIST_FREE(&(pVrf->vrf_proc.md_info_list), InternalFreeMdInfo);

#if (CMSCBB_SUPPORT_PEM || CMSCBB_CACHE_ASN_DATA)
    CMSCBB_LIST_FREE(&(pVrf->raw_set), CmscbbFree);
#endif

    CmscbbFree(pVrf);

    return CVB_SUCCESS;
}

const CVB_CHAR* CmscbbGetVersion(CVB_VOID)
{
    return (const CVB_CHAR*)CMSCBB_VERSION;
}


#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : CmscbbDecodeCrlFile
 * Description  : check paramter
 * Params
 *   [IN] ctx: Validation context
 *   [IN] crlFile: CRL file path
 *   [OUT] pResult:  Parse the result, including all CRL information in the file
 * Return Value : return cvb_success correctly, error return error code
 * Remarks      :The CRL file may have merged a CRL published by multiple root CAs, so the return result is a list of CRL information
 *   Date              Author     Modification
 *   2015/11/09 18:42  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamDecodeCrlFile(const CMSCBB_VRF* pVrf, const CVB_CHAR* crlFile)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (crlFile == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbDecodeCrlFile(CMSCBB_VRF_CTX ctx, const CVB_CHAR* crlFile, CmscbbCrlBundleInfo** pResult)
{
    CVB_BYTE* pbData = CVB_NULL;
    CVB_INT32 fileBytes = 0;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    CMSCBB_ERROR_CODE ret;

    ret = InternalCheckParamDecodeCrlFile(pVrf, crlFile);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    if (pResult == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = InternalReadFile(crlFile, &pbData, &fileBytes);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    ret = CmscbbDecodeCrl(ctx, pbData, (CVB_UINT32)fileBytes, pResult);
    CmscbbFree(pbData);

    return ret;
}
#endif

#if CMSCBB_SUPPORT_CRL_COMPARE
/*
 * Prototype    : InternalDestoryRevokeList
 * Description  : Destroying CRL comparison information
 * Params
 *   [IN] revokeList: a revoke list 
 * Return Value : CVB_STATIC CVB_VOID
 *   Date              Author     Modification
 *   2016/08/09 10:23  t00307193  Create
 */
CVB_STATIC CVB_VOID InternalDestoryRevokeList(CmscbbRevokeList* revokeList)
{
    CmscbbFree(revokeList->snList);
    revokeList->snList = CVB_NULL;
}

/*
 * Prototype    : InternalGetRevokeList
 * Description  : Copy the revocation information in the CRL to the CRL information structure
 * Params
 *   [IN] pRevokeList: revoke list
 *   [IN] pX509Revoke: x509 certificate need to revoke
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2016/05/19 16:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalGetRevokeList(CmscbbRevokeList* pRevokeList, const CmscbbX509Revoked* pX509Revoke)
{
    CMSCBB_ERROR_CODE ret;
    CVB_INT iter;
    CVB_INT nRevoked = (CVB_INT)pX509Revoke->revoked_list.num;

    if (nRevoked <= 0) {
        return CVB_SUCCESS;
    }

    /* create revoke list memory */
    ret = CmscbbMallocWith0((CVB_VOID**)&pRevokeList->snList, (CVB_UINT32)nRevoked * sizeof(CmscbbSerialNum));
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    for (iter = 0; iter < nRevoked; ++iter) {
        /* get next empty revoke info entry */
        CmscbbSerialNum* pRevokeInfo = pRevokeList->snList + pRevokeList->revokeCount;
        const CmscbbX509RevokeEntry* pRevokeEntry = &(pX509Revoke->revoked_list.data[iter]);

        if (pRevokeEntry->userCert.len == 0) {
            continue;
        }

        if (pRevokeEntry->userCert.len > CMSCBB_MAX_SN_LEN) {
            continue;
        }

        ret = (CMSCBB_ERROR_CODE)memcpy_s(pRevokeInfo->sn, CMSCBB_MAX_SN_LEN, pRevokeEntry->userCert.octs, pRevokeEntry->userCert.len);
        if (CVB_FAILED(ret)) {
            pRevokeInfo->snLenth = 0;
        } else {
            pRevokeInfo->snLenth = pRevokeEntry->userCert.len;
        }
        ++pRevokeList->revokeCount;
    }

    return CVB_SUCCESS;
}

/* get issuer name */
CVB_STATIC CVB_VOID InternalGetCrlIssuerName(CmscbbCrlInfo* pCrlInfo, const CmscbbX509Crl* pCrl)
{
    CMSCBB_ERROR_CODE ret;

    CVB_CHAR* pIssuer = CVB_NULL;
    CVB_UINT32 nIssuerLen = 0;

    ret = CmscbbConvertFromX509Name(&(pCrl->tbsCertList.issuer), &pIssuer, &nIssuerLen);
    if (ret == CVB_SUCCESS) {
        ret = (CMSCBB_ERROR_CODE)strcpy_s(pCrlInfo->issuer, MAX_ISSUER_NAME_LENGTH, pIssuer);
        if (CVB_FAILED(ret)) {
            CVB_LOG_WARNING(ret, CVB_NULL);
        }
    }
    if (pIssuer != CVB_NULL) {
        CmscbbFree(pIssuer);
    }
}

/* get update time */
CVB_STATIC CMSCBB_ERROR_CODE InternalGetCrlUpdateTime(CmscbbCrlInfo* pCrlInfo, const CmscbbX509Crl* pCrl)
{
    CMSCBB_ERROR_CODE ret;

    CVB_TIME_T updateTime = 0;
    ret = CmscbbConvertDatetimeToTime(&(pCrl->tbsCertList.thisUpdateTime), &updateTime);
    if (ret == CVB_SUCCESS) {
        pCrlInfo->updateTime = (CVB_INT64)updateTime;
    }
    return ret;
}

/*
 * Prototype    : InternalGetCrlValidUntil
 * Description  : Get the valid X509 crl 
 * Params
 *   [IN] pRevokeList: crl information
 *   [OUT] pCrl: X509 crl 
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2016/05/19 16:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalGetCrlValidUntil(CmscbbCrlInfo* pCrlInfo, const CmscbbX509Crl* pCrl)
{
    CMSCBB_ERROR_CODE ret;

    CVB_TIME_T validUntil = 0;
    ret = CmscbbConvertDatetimeToTime(&(pCrl->tbsCertList.nextUpdateTime), &validUntil);
    if (ret == CVB_SUCCESS) {
        pCrlInfo->validUntil = (CVB_INT64)validUntil;
    }
    return ret;
}

/*
 * Prototype    : InternalGetCrlIsAuthored
 * Description  : Get the crl which is authorized
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pRevokeList: crl information
 *   [OUT] pCrl: X509 crl
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2016/05/19 16:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalGetCrlIsAuthored(CMSCBB_VRF* pVrf, CmscbbCrlInfo* pCrlInfo, const CmscbbX509Crl* pCrl)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbX509Cert* pAuthorCert;
    CVB_BOOL result = CVB_FALSE;

    pAuthorCert = CmscbbPkiFindCrlIssuer(pVrf, pCrl);
    if (pAuthorCert != CVB_NULL) {
        CVB_BOOL isSelfSigned = 0;

        pVrf->base_time = (CVB_TIME_T)pCrlInfo->updateTime;
        ret = CmscbbPkiVerifyCert(pVrf, pAuthorCert, CVB_TRUE, CVB_TRUE, &result);
        if (ret == CVB_SUCCESS && result == CVB_TRUE) {
            pCrlInfo->valid = CVB_TRUE;
        }

        ret = CmscbbX509IsSelfSigned(pAuthorCert, &isSelfSigned);
        if (CVB_FAILED(ret)) {
            return ret;
        }
        if (isSelfSigned && pCrl->tbsCertList.revokedCerts.revoked_list.num != 0) {
            ret = InternalGetRevokeList(&pCrlInfo->revokeList, &(pCrl->tbsCertList.revokedCerts));
            if (CVB_FAILED(ret)) {
                return ret;
            }
        }
        if (pAuthorCert->toBeSigned.serialNumber.len <= CMSCBB_MAX_SN_LEN) {
            ret = (CMSCBB_ERROR_CODE)memcpy_s(pCrlInfo->issuerSn.sn, CMSCBB_MAX_SN_LEN, pAuthorCert->toBeSigned.serialNumber.octs, pAuthorCert->toBeSigned.serialNumber.len);
            if (CVB_FAILED(ret)) {
                return ret;
            }
            pCrlInfo->issuerSn.snLenth = pAuthorCert->toBeSigned.serialNumber.len;

        }
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalGetCrlInfo
 * Description  : get information from CRL
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pCrl: X509 crl
 *   [OUT] ppCrlInfo: crl information
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 14:53  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalGetCrlInfo(CMSCBB_VRF* pVrf, const CmscbbX509Crl* pCrl, CmscbbCrlInfo** ppCrlInfo)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbCrlInfo* pCrlInfo = CVB_NULL;

    *ppCrlInfo = CVB_NULL;
    ret = CmscbbMallocWith0((CVB_VOID**)&pCrlInfo, sizeof(CmscbbCrlInfo));
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return ret;
    }

    pCrlInfo->valid = CVB_FALSE;
    InternalGetCrlIssuerName(pCrlInfo, pCrl);

    ret = InternalGetCrlUpdateTime(pCrlInfo, pCrl);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = InternalGetCrlValidUntil(pCrlInfo, pCrl);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    /* get verify info */
    ret = InternalGetCrlIsAuthored(pVrf, pCrlInfo, pCrl);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    *ppCrlInfo = pCrlInfo;
    return CVB_SUCCESS;

CVB_ERR:
    CmscbbFree(pCrlInfo);
    return ret;
}

/*
 * Prototype    : InternalCheckParamDecodeCrl
 * Description  : check paramter when decode crl 
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] pbCrl: CRL data address
 *   [IN] nCrlLength: CRL data length
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:45  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamDecodeCrl(const CMSCBB_VRF* pVrf, const CVB_BYTE* pbCrl, CVB_UINT32 nCrlLength)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (pbCrl == CVB_NULL || nCrlLength == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbDecodeCrl(CMSCBB_VRF_CTX ctx, const CVB_BYTE* pbCrl, CVB_UINT32 nCrlLength, CmscbbCrlBundleInfo** ppResult)
{
    CMSCBB_ERROR_CODE ret;
    LIST_OF(CmscbbX509Cert) certList = {0};
    LIST_OF(CmscbbX509Crl) crlList = {0};
    CVB_INT iter = 0;
    CmscbbCrlBundleInfo* pResult = CVB_NULL;
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;

    ret = InternalCheckParamDecodeCrl(pVrf, pbCrl, nCrlLength);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    if (ppResult == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

#if CMSCBB_SUPPORT_PEM
    ret = InternalDecodeCertCrl(pVrf, pbCrl, nCrlLength, &certList, &crlList);
#else
    ret = InternalDecodeStreamCertCrl(pVrf, pbCrl, nCrlLength, &certList, &crlList);
#endif
    CVB_GOTO_ERR_WITH_LOG_IF(ret != CVB_SUCCESS || 0 == crlList.num, CMSCBB_ERR_PKI_CRL_DECODE);

    if (MAX_CRL_SUPPORT < crlList.num) {
        ret = CMSCBB_ERR_PKI_CRL_TOO_MUCH;
        CMSCBB_LIST_FREE(&certList, CmscbbX509FreeCert);
        CMSCBB_LIST_FREE(&crlList, CmscbbX509FreeCrl);
        CVB_LOG_ERROR(ret, "Decode CRL failed.");
        return ret;
    }

    ret = InternalAddCrlToStore(pVrf, &crlList);
    CVB_GOTO_ERR_WITH_LOG_IF(ret != CVB_SUCCESS, CMSCBB_ERR_PKI_CRL_DECODE);

    ret = InternalAddCertToStore(pVrf, &certList, CVB_FALSE);
    CVB_GOTO_ERR_WITH_LOG_IF(ret != CVB_SUCCESS, CMSCBB_ERR_PKI_CRL_DECODE);

    ret = CmscbbMallocWith0((CVB_VOID**)&pResult, sizeof(CmscbbCrlBundleInfo));
    CVB_GOTO_ERR_WITH_LOG_IF(ret != CVB_SUCCESS, CMSCBB_ERR_PKI_CRL_DECODE);

    pResult->st_size = sizeof(CmscbbCrlBundleInfo);

    for (; iter < (CVB_INT)crlList.num && iter < MAX_CRL_SUPPORT; ++iter) {
        CmscbbCrlInfo* pCrlInfo = CVB_NULL;
        CmscbbX509Crl* pCrl = crlList.data[iter];
        if (pCrl == CVB_NULL) {
            continue;
        }
        ret = InternalGetCrlInfo(pVrf, pCrl, &pCrlInfo);
        if (CVB_FAILED(ret)) {
            continue;
        }
        if (pCrlInfo != CVB_NULL) {
            pResult->crlInfoList[iter] = pCrlInfo;
            ++pResult->crlCount;
        }
    }

    *ppResult = pResult;

    CMSCBB_LIST_FREE(&certList, CmscbbX509FreeCert);
    CMSCBB_LIST_FREE(&crlList, CmscbbX509FreeCrl);
    return CVB_SUCCESS;

CVB_ERR:
    if (pResult != CVB_NULL) {
        CmscbbFree(pResult);
    }
    *ppResult = CVB_NULL;
    CMSCBB_LIST_FREE(&certList, CmscbbX509FreeCert);
    CMSCBB_LIST_FREE(&crlList, CmscbbX509FreeCrl);
    return ret;
}

/*
 * Prototype    : InternalIsCrlIssuerRevoked
 * Description  : check if the missing crl's issuer is revoked
 * Params
 *   [IN] pVrf: verify context
 *   [IN] pciRoot: crl issued by root
 *   [IN] pciMissing: crl which can't found in old crl list.
 * Return Value : TRUE: the missing crl's issuer sn found in revoke list from new root crl;
 *                FALSE: not found
 *   Date              Author     Modification
 *   2016/06/01 10:17  t00307193  Create
 */
CVB_STATIC CVB_BOOL InternalIsCrlIssuerRevoked(const CmscbbCrlInfo* pciRoot, const CmscbbCrlInfo* pciMissing)
{
    CVB_INT iter;

    /* find missing issuer sn from root crl's revoke list */
    for (iter = 0; iter < (CVB_INT)pciRoot->revokeList.revokeCount; ++iter) {
        CmscbbSerialNum* pRevokedSn = pciRoot->revokeList.snList + iter;
        if (pRevokedSn->snLenth == pciMissing->issuerSn.snLenth &&
            CmscbbMemCmp(pRevokedSn->sn, pciMissing->issuerSn.sn, pciMissing->issuerSn.snLenth) == 0) {
            return CVB_TRUE;
        }
    }

    /* not found */
    return CVB_FALSE;
}

/*
 * Prototype    : InternalCheckNewCrl
 * Description  : check if the new CRL contains all corresponding CRL in old.
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] newCrlBi: new crl bundle information which contains all in old
 *   [IN] oldCrlBi: old crl bundle information
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 14:54  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckNewCrl(const CmscbbCrlBundleInfo* newCrlBi, const CmscbbCrlBundleInfo* oldCrlBi)
{
    CVB_INT iNew;
    CVB_INT iOld;
    const CmscbbCrlInfo* pciRoot = CVB_NULL;

    /* new CRL bundle should contains all in old */
    for (iOld = 0; iOld < oldCrlBi->crlCount; ++iOld) {
        CVB_BOOL found = CVB_FALSE;
        const CmscbbCrlInfo* psiOld = oldCrlBi->crlInfoList[iOld];
        if (psiOld == CVB_NULL) {
            return CMSCBB_ERR_UNDEFINED;
        }

        for (iNew = 0; iNew < (CVB_INT)newCrlBi->crlCount; ++iNew) {
            const CmscbbCrlInfo* psiNew = newCrlBi->crlInfoList[iNew];
            if (psiNew == CVB_NULL) {
                return CMSCBB_ERR_UNDEFINED;
            }

            /* Finds the CRL issued by the root certificate, which has revocation information for level two CAs */
            if (pciRoot == CVB_NULL && psiNew->revokeList.revokeCount != 0) {
                pciRoot = psiNew;
            }

            if (CmscbbStrCmp(psiNew->issuer, psiOld->issuer) == 0) {
                found = CVB_TRUE;
                break;
            }
        }
        if (found == CVB_FALSE) {
            /* check root CRL's revoke list for missing issuer */
            if (pciRoot != CVB_NULL && InternalIsCrlIssuerRevoked(pciRoot, psiOld) == CVB_TRUE) {
                continue;
            }
            return CMSCBB_ERR_UNDEFINED;
        }
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCompareCrlInfo
 * Description  : compare two CRL info to get which is newer
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] psi1: crl info 1
 *   [IN] psi2: crl info 2
 *   [OUT] curState: Results of comparisons,
 *           SCPS_NEW: S1 all CRLs are newer than S2.
 *           SCPS_OLD: S1 all CRLs are older than S2.
 *           SCPS_MIX: Cannot be compared, S1 has a new CRL than S2, and there are older CRLs than S2
 * Return Value : CVB_STATIC CVB_INT32
 *   Date              Author     Modification
 *   2015/11/10 14:56  t00307193  Create
 */
CVB_STATIC CVB_INT32 InternalCompareCrlInfo(const CMSCBB_VRF* pVrf, const CmscbbCrlInfo* psi1, const CmscbbCrlInfo* psi2, CmscbbCrlPeriodStat* curState)
{
    (CVB_VOID)pVrf;
    if (CmscbbStrCmp(psi1->issuer, psi2->issuer) == 0) {
        CmscbbCrlPeriodStat newState = SCPS_SAME;
        if (psi1->updateTime > psi2->updateTime) {
            newState = SCPS_NEW;
        } else if (psi1->updateTime < psi2->updateTime) {
            newState = SCPS_OLD;
        } else { /* same */
            return 0;
        }

        /* state changed */
        if (*curState != newState) {
            if (*curState == SCPS_SAME) {
                *curState = newState;
            } else {
                *curState = SCPS_MIX;
            }
        }
        return 0;
    }
    return -1;
}

/*
 * Prototype    : InternalCompareIntercrossCrl
 * Description  : Compare two crl bundle, which contains inter-crossed crl list.
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] s1: crl bundle info 1
 *   [IN] s2: crl bundle info 2
 *   [OUT] curState: Results of comparisons,
 *           SCPS_NEW: S1 all CRLs are newer than S2.
 *           SCPS_OLD: S1 all CRLs are older than S2.
 *           SCPS_MIX: Cannot be compared, S1 has a new CRL than S2, and there are older CRLs than S2
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 14:56  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCompareIntercrossCrl(const CMSCBB_VRF* pVrf, const CmscbbCrlBundleInfo* s1, const CmscbbCrlBundleInfo* s2, CmscbbCrlPeriodStat* curState)
{
    CMSCBB_ERROR_CODE ret = CVB_SUCCESS;
    CVB_INT iS1;
    CVB_INT iS2;

    for (iS1 = 0; iS1 < s1->crlCount; ++iS1) {
        const CmscbbCrlInfo* psi1 = s1->crlInfoList[iS1];
        if (psi1 == CVB_NULL || psi1->valid != 1) {
            *curState = SCPS_MIX;
            return CMSCBB_ERR_PKI_CRL_INVALID;
        }
    }

    for (iS2 = 0; iS2 < s2->crlCount; ++iS2) {
        const CmscbbCrlInfo* psi2 = s2->crlInfoList[iS2];
        if (psi2 == CVB_NULL || psi2->valid != 1) {
            *curState = SCPS_MIX;
            return CMSCBB_ERR_PKI_CRL_INVALID;
        }
    }

    for (iS1 = 0; iS1 < s1->crlCount; ++iS1) {
        const CmscbbCrlInfo* psi1 = s1->crlInfoList[iS1];

        for (iS2 = 0; iS2 < s2->crlCount; ++iS2) {
            const CmscbbCrlInfo* psi2 = s2->crlInfoList[iS2];

            /* find the CRL which have same issuer with psi1 */
            if (InternalCompareCrlInfo(pVrf, psi1, psi2, curState) == 0) {
                break;
            }
        }

        if (*curState == SCPS_MIX) {
            break;
        }
    }

    return ret;
}

/*
 * Prototype    : InternalFindDuplicateCrlIssuer
 * Description  : To troubleshoot duplicate publishers in the same CRL package
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] crlToUpdate: CRLs to be updated
 * Return Value : Cvb_true There is a duplicate publisher; Cvb_false No duplicate publisher
 * Remarks      : Repeat the name of the publisher in the CRL, as suggested by Xiao Hui
 *   Date              Author     Modification
 *   2016/04/28 10:11  t00307193  Create
 */
CVB_STATIC CVB_BOOL InternalFindDuplicateCrlIssuer(const CmscbbCrlBundleInfo* crlToUpdate)
{
    CVB_INT iter;
    /* Traversing CRLs from 0 to N-2 */
    for (iter = 0; iter < crlToUpdate->crlCount - 1; ++iter) {
        CmscbbCrlInfo* pCrl = crlToUpdate->crlInfoList[iter];
        CVB_INT iNext;
        /* Traversing CRLs from iter+1 to N-1 */
        for (iNext = iter + 1; iNext < crlToUpdate->crlCount; ++iNext) {
            CmscbbCrlInfo* pCrlNext = crlToUpdate->crlInfoList[iNext];
            /* Name of the CRL publisher before and after the check */
            if (CmscbbStrCmp(pCrl->issuer, pCrlNext->issuer) == 0) {
                return CVB_TRUE;
            }
        }
    }
    return CVB_FALSE;
}
/*
 * Prototype    : InternalCheckCompareResult
 * Description  : Compare two CRL file information which update
 * Params
 *   [IN] crlToUpdate: The object to compare
 *   [IN] crlOnDevice: The object to compare
 *   [OUT] stat: Results of comparisons,
 *           SCPS_NEW: S1 all CRLs are newer than S2.
 *           SCPS_OLD: S1 all CRLs are older than S2.
 *           SCPS_MIX: Cannot be compared, S1 has a new CRL than S2, and there are older CRLs than S2
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:49  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckCompareResult(const CmscbbCrlBundleInfo *crlToUpdate, const CmscbbCrlBundleInfo *crlOnDevice, CmscbbCrlPeriodStat curState)
{
    if (curState == SCPS_NEW) { /* crlToUpdate contains all crlOnDevice */
        if (InternalCheckNewCrl(crlToUpdate, crlOnDevice) != CVB_SUCCESS) {
            return CMSCBB_ERR_PKI_CRL_FAILED_MAPPING;
        }
    } else {
        if (InternalCheckNewCrl(crlOnDevice, crlToUpdate) != CVB_SUCCESS) {
            return CMSCBB_ERR_PKI_CRL_FAILED_MAPPING;
        }
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalCheckParamCrlCompare
 * Description  : check two CRL file information which update
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] crlToUpdate: The object to compare
 *   [IN] crlOnDevice: The object to compare
 *   [IN] stat: Results of comparisons,
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:49  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParamCrlCompare(const CMSCBB_VRF *pVrf, const CmscbbCrlBundleInfo *crlToUpdate, const CmscbbCrlBundleInfo *crlOnDevice, const CmscbbCrlPeriodStat *stat)
{
    CMSCBB_ERROR_CODE ret = InternalCheckVerifyOjbect(pVrf);
    if (CVB_FAILED(ret)) {
        return ret;
    }
    if (crlToUpdate == CVB_NULL || crlOnDevice == CVB_NULL || stat == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    if (crlToUpdate->crlCount == 0 || crlOnDevice->crlCount == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CRL_EMPTY, CVB_NULL);
        return CMSCBB_ERR_PKI_CRL_EMPTY;
    }
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbCrlCompare(CMSCBB_VRF_CTX ctx, const CmscbbCrlBundleInfo *crlToUpdate, const CmscbbCrlBundleInfo *crlOnDevice, CmscbbCrlPeriodStat *stat)
{
    CMSCBB_VRF *pVrf = (CMSCBB_VRF *)ctx;
    CMSCBB_ERROR_CODE ret;
    CmscbbCrlPeriodStat curState = SCPS_SAME;

    ret = InternalCheckParamCrlCompare(pVrf, crlToUpdate, crlOnDevice, stat);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    ret = InternalCompareIntercrossCrl(pVrf, crlToUpdate, crlOnDevice, &curState);
    if (CVB_FAILED(ret)) {
        *stat = SCPS_MIX;
        return ret;
    }

    if (InternalFindDuplicateCrlIssuer(crlToUpdate) == CVB_TRUE ||
        InternalFindDuplicateCrlIssuer(crlOnDevice) == CVB_TRUE) {
        *stat = SCPS_MIX;
        return CMSCBB_ERR_PKI_CRL_DUPLICATE_ISSUER;
    }

    /* change state to "new" if crlToUpdate contains more item than crlOnDevice */
    if (curState == SCPS_SAME) {
        if (crlToUpdate->crlCount > crlOnDevice->crlCount) {
            curState = SCPS_NEW;
        } else if (crlToUpdate->crlCount < crlOnDevice->crlCount) {
            curState = SCPS_OLD;
        }
    }

    ret = InternalCheckCompareResult(crlToUpdate, crlOnDevice, curState);
    if (CVB_FAILED(ret)) {
        *stat = SCPS_MIX;
        return ret;
    }

    *stat = curState;
    return ret;
}

CMSCBB_ERROR_CODE CmscbbCrlFree(CMSCBB_VRF_CTX ctx, CmscbbCrlBundleInfo* pCrlBundle)
{
    CMSCBB_VRF* pVrf = (CMSCBB_VRF*)ctx;
    CVB_INT iter = 0;

    if (pVrf == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    if (pCrlBundle == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    for (; iter < pCrlBundle->crlCount; ++iter) {
        CmscbbCrlInfo* pCrlInfo = pCrlBundle->crlInfoList[iter];
        InternalDestoryRevokeList(&pCrlInfo->revokeList);
        CmscbbFree((CVB_VOID*)pCrlInfo);
    }

    CmscbbFree(pCrlBundle);
    return CVB_SUCCESS;
}

#endif /* CMSCBB_SUPPORT_CRL_COMPARE */

#if CMSCBB_SUPPORT_FILE
#define MAX_PKI_FILE_LEN (2 * 1000000)

/*
 * Prototype    : InternalReadFile
 * Description  : read file's content into memory
 * Params
 *   [IN] pszFilePath: file path
 *   [OUT] data: file data object
 *   [OUT] size: the size of file 
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 14:59  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalReadFile(const CVB_CHAR* pszFilePath, CVB_BYTE** data, CVB_INT32* size)
{
    CVB_BYTE* pbData = CVB_NULL;
    CVB_UINT32 nFileSize;
    CMSCBB_ERROR_CODE ret;
    CVB_FILE_HANDLE hFile;

    if (*pszFilePath == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_SYS_FILE_OPEN, "Empty file path.");
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    hFile = CmscbbFileOpen(pszFilePath, (const CVB_CHAR*)"rb");
    if (hFile == CVB_NULL) {
        CVB_LOG_ERROR1(CMSCBB_ERR_SYS_FILE_OPEN, "Can not open file '%s'.", pszFilePath);
        return CMSCBB_ERR_SYS_FILE_OPEN;
    }

    nFileSize = (CVB_UINT32)CmscbbFileGetSize(hFile);
    CVB_GOTO_ERR_WITH_LOG_IF(0 == nFileSize, CMSCBB_ERR_SYS_FILE_GET_SIZE);
    CVB_GOTO_ERR_WITH_LOG_IF(MAX_PKI_FILE_LEN < nFileSize, CMSCBB_ERR_SYS_FILE_TOO_LARGE);

    ret = CmscbbMalloc((CVB_VOID**)&pbData, nFileSize);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    CVB_GOTO_ERR_WITH_LOG_IF(nFileSize != CmscbbFileRead(pbData, nFileSize, hFile), CMSCBB_ERR_SYS_FILE_READ);

    *size = (CVB_INT32)nFileSize;
    *data = pbData;
    goto CVB_FINAL;
CVB_ERR:
    CmscbbFree(pbData);
CVB_FINAL:
    InternalCloseFile(hFile);
    return ret;
}
#endif

#if CMSCBB_SUPPORT_PEM
/*
 * Prototype    : InternalDecodeCertCrl
 * Description  : decode crl-bundle, which contains both crl list and cert list
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbContent: The data for the signature content
 *   [IN] nContentLength: length of the signature content
 *   [IN,OUT] pCertList: list of X509 certificate
 *   [IN,OUT] pCrlList: list of X509 crl
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 14:59  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodeCertCrl(CMSCBB_VRF* pVrf, const CVB_BYTE* pbContent,
    CVB_UINT32 nContentLength, LIST_OF(CmscbbX509Cert)* pCertList, LIST_OF(CmscbbX509Crl)* pCrlList)
{
#if CMSCBB_SUPPORT_PEM
    CVB_BOOL is_pem = CVB_FALSE;

    if (nContentLength < CVB_MIN_PEM_LEN) {
        return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
    }

    if (CmscbbStrNCmp((const CVB_CHAR*)pbContent, (const CVB_CHAR*)CVB_PEM_SYMBOL,
        (CVB_SIZE_T)CmscbbStrlen((const CVB_CHAR*)CVB_PEM_SYMBOL)) == 0) {
        is_pem = CVB_TRUE;
    }

    if (is_pem) {
        CMSCBB_ERROR_CODE ret;
        CVB_BYTE* pbPemContent = CVB_NULL;
        /* The string must end with 0 to ensure Strstr is not crossed */
        ret = CmscbbMallocWith0((CVB_VOID**)&pbPemContent, nContentLength + 1);
        if (CVB_FAILED(ret)) {
            CVB_LOG_DEBUG(ret, CVB_NULL);
            return ret;
        }

        ret = (CMSCBB_ERROR_CODE)memcpy_s((CVB_VOID*)pbPemContent, nContentLength, (const CVB_VOID*)pbContent, nContentLength);
        if (CVB_FAILED(ret)) {
            CmscbbFree((CVB_VOID*)pbPemContent);
            return ret;
        }

        ret = InternalDecodePemCertCrl(pVrf, pbPemContent, nContentLength, pCertList, pCrlList);
        CmscbbFree((CVB_VOID*)pbPemContent);
        return ret;
    } else
#endif
    {
        pVrf->resv[0] = 0;  /* Avoid lint alarms */
        return InternalDecodeStreamCertCrl(pVrf, pbContent, nContentLength, pCertList, pCrlList);
    }
}

/*
 * Prototype    : InternalPemDecodeCert
 * Description  : decode cert with PEM format
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbBegin: the certificate base64 begin location
 *   [IN] nEncoded: length of encode 
 *   [OUT] pCert: X509 Certificate
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 15:00  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalPemDecodeCert(CMSCBB_VRF* pVrf, const CVB_CHAR* pbBegin, CVB_UINT32 nEncoded, CmscbbX509Cert** pCert)
{
    CMSCBB_ERROR_CODE ret;
    const CVB_CHAR* pszCerB64Begin = CVB_NULL;
    const CVB_CHAR* pszCerB64End = CVB_NULL;
    CVB_BYTE* pbDer = CVB_NULL;
    CVB_UINT32 nDer = 0;
    CVB_UINT32 nDecoded = 0;

    if (CmscbbStrNCmp(pbBegin, (const CVB_CHAR*)CVB_PEM_SYMBOL_CERT, CVB_PEM_SYMBOL_CERT_LEN) != 0) {
        return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
    }
    pszCerB64Begin = pbBegin + CVB_PEM_SYMBOL_CERT_LEN + 1;

    pszCerB64End = CmscbbStrStr(pbBegin, (const CVB_CHAR*)CVB_PEM_SYMBOL_CERT_END);
    if (pszCerB64End == CVB_NULL || (CVB_UINT32)(pszCerB64End - pszCerB64Begin) > nEncoded) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_INVALID_PEM, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_INVALID_PEM);
    }

    ret = InternalBase64Decode(pszCerB64Begin, pszCerB64End, &pbDer, &nDer);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
    }

    ret = CmscbbX509DecodeCert(pbDer, nDer, pCert, &nDecoded);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CMSCBB_LIST_ADD(&pVrf->raw_set, pbDer);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    return CVB_SUCCESS;
CVB_ERR:
    CmscbbFree(pbDer);
    if (pCert != CVB_NULL) {
        CmscbbX509FreeCert(*pCert);
        *pCert = CVB_NULL;
    }
    return ret;
}

/*
 * Prototype    : InternalPemDecodeCrl
 * Description  : decode crl with PEM format
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbBegin: the certificate base64 begin location
 *   [IN] nEncoded: length of encode 
 *   [OUT] pCrl: X509 Certificate
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 15:01  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalPemDecodeCrl(CMSCBB_VRF* pVrf, const CVB_CHAR* pbBegin, CVB_UINT32 nEncoded, CmscbbX509Crl** pCrl)
{
    CMSCBB_ERROR_CODE ret;
    const CVB_CHAR* pszB64Begin = CVB_NULL;
    const CVB_CHAR* pszB64End = CVB_NULL;
    CVB_BYTE* pbDer = CVB_NULL;
    CVB_UINT32 nDer = 0;
    CVB_UINT32 nDecoded = 0;

    if (CmscbbStrNCmp(pbBegin, (const CVB_CHAR*)CVB_PEM_SYMBOL_CRL, CVB_PEM_SYMBOL_CRL_LEN) != 0) {
        return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
    }
    pszB64Begin = pbBegin + CVB_PEM_SYMBOL_CRL_LEN;

    pszB64End = CmscbbStrStr(pbBegin, (const CVB_CHAR*)CVB_PEM_SYMBOL_CRL_END);
    if (pszB64End == CVB_NULL || (CVB_UINT32)(pszB64End - pszB64Begin) > nEncoded) {
        CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_INVALID_PEM, CVB_NULL);
        return (CMSCBB_ERR_PKI_CMS_INVALID_PEM);
    }

    ret = InternalBase64Decode(pszB64Begin, pszB64End, &pbDer, &nDer);
    if (CVB_FAILED(ret)) {
        CVB_LOG_ERROR(ret, CVB_NULL);
        return CMSCBB_ERR_PKI_CMS_INVALID_PEM;
    }

    ret = CmscbbX509DecodeCrl(pbDer, nDer, pCrl, &nDecoded);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    ret = CMSCBB_LIST_ADD(&pVrf->raw_set, pbDer);
    CVB_GOTO_ERR_IF_FAIL_LOG(ret);

    return CVB_SUCCESS;
CVB_ERR:
    CmscbbFree(pbDer);
    if (pCrl != CVB_NULL) {
        CmscbbX509FreeCrl(*pCrl);
        *pCrl = CVB_NULL;
    }
    return ret;
}

/*
 * Prototype    : InternalAddPemCertToList
 * Description  : Add cert with PEM format into list
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbBegin: the certificate base64 begin location
 *   [IN] pbEnd: the certificate base64 end location
 *   [IN,OUT] pCertList: a list of X509 certificate
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 15:02  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalAddPemCertToList(CMSCBB_VRF* pVrf, const CVB_CHAR* pbBegin, const CVB_CHAR* pbEnd, LIST_OF(CmscbbX509Cert)* pCertList)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbX509Cert* pCert = CVB_NULL;
    ret = InternalPemDecodeCert(pVrf, pbBegin, (CVB_UINT32)(pbEnd - pbBegin), &pCert);
    if (ret == CVB_SUCCESS && pCert != CVB_NULL) {
        if (pCertList == CVB_NULL) {
            /* ignore cert when the input list is NULL */
            CmscbbX509FreeCert(pCert);
        } else {
            ret = CMSCBB_LIST_ADD(pCertList, pCert);
            if (ret != CVB_SUCCESS) {
                CmscbbX509FreeCert(pCert);
            }
        }
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalAddPemCrlToList
 * Description  : Add crl with PEM format into list.
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbBegin: the certificate base64 begin location
 *   [IN] pbEnd: the certificate base64 end location
 *   [IN,OUT] pCertList: a list of X509 certificate
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 15:03  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalAddPemCrlToList(CMSCBB_VRF* pVrf, const CVB_CHAR* pbBegin, const CVB_CHAR* pbEnd, LIST_OF(CmscbbX509Crl)* pCrlList)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbX509Crl* pCrl = CVB_NULL;
    ret = InternalPemDecodeCrl(pVrf, pbBegin, (CVB_UINT32)(pbEnd - pbBegin), &pCrl);
    if (ret == CVB_SUCCESS && pCrl != CVB_NULL) {
        if (pCrlList == CVB_NULL) {
            /* ignore crl when the input list is NULL */
            CmscbbX509FreeCrl(pCrl);
        } else {
            ret = CMSCBB_LIST_ADD(pCrlList, pCrl);
            if (ret != CVB_SUCCESS) {
                CmscbbX509FreeCrl(pCrl);
            }
        }
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalDecodePemCertCrl
 * Description  : decode crl-bundle with PEM format, which contains both crl list and cert list
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbContent: The data for the signature content
 *   [IN] nContentLength: the length of signature content
 *   [IN,OUT] pCertList: a list of X509 certificate
 *   [IN,OUT] pCrlList: a list of X509 crl
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 15:03  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodePemCertCrl(CMSCBB_VRF* pVrf, const CVB_BYTE* pbContent, CVB_UINT32 nContentLength, LIST_OF(CmscbbX509Cert)* pCertList, LIST_OF(CmscbbX509Crl)* pCrlList)
{
    CMSCBB_ERROR_CODE ret;
    const CVB_CHAR* pbBegin = (const CVB_CHAR*)pbContent;
    const CVB_CHAR* pbEnd = CVB_NULL;

    if (pbContent == CVB_NULL || nContentLength == 0) {
        CVB_LOG_ERROR(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pbBegin = CmscbbStrStr(pbBegin, (const CVB_CHAR*)CVB_PEM_SYMBOL);
    while (pbBegin != CVB_NULL) {
        const CVB_CHAR* szType = pbBegin + 11;
        pbEnd = CmscbbStrStr(pbBegin, (const CVB_CHAR*)CVB_PEM_SYMBOL_END);
        if (pbEnd == CVB_NULL) {
            CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_INVALID_PEM, CVB_NULL);
            return (CMSCBB_ERR_PKI_CMS_INVALID_PEM);
        }

        pbEnd += 8;
        pbEnd = CmscbbStrStr(pbEnd, (const CVB_CHAR*)CVB_PEM_SPLIT);
        if (pbEnd == CVB_NULL) {
            CVB_LOG_ERROR(CMSCBB_ERR_PKI_CMS_INVALID_PEM, CVB_NULL);
            return (CMSCBB_ERR_PKI_CMS_INVALID_PEM);
        }

        pbEnd += 5;
        if (CmscbbStrNCmp(szType, (const CVB_CHAR*)"CERTIFICATE", 11) == 0) {
            ret = InternalAddPemCertToList(pVrf, pbBegin, pbEnd, pCertList);
            if (CVB_FAILED(ret)) {
                CVB_LOG_ERROR(ret, CVB_NULL);
                return ret;
            }
        }
        if (CmscbbStrNCmp(szType, (const CVB_CHAR*)"X509 CRL", 8) == 0) {
            ret = InternalAddPemCrlToList(pVrf, pbBegin, pbEnd, pCrlList);
            if (CVB_FAILED(ret)) {
                CVB_LOG_ERROR(ret, CVB_NULL);
                return ret;
            }
        }
        pbBegin = CmscbbStrStr(pbEnd, (const CVB_CHAR*)CVB_PEM_SYMBOL);
    }

    return CVB_SUCCESS;
}
#endif

/*
 * Prototype    : InternalDecodeStreamCertCrl
 * Description  : decode crl-bundle, which contains both crl list and cert list
 * Params
 *   [IN] pVrf: data for verify context
 *   [IN] pbContent: The data for the signature content
 *   [IN] nContentLength: the length of signature content
 *   [IN,OUT] pCertList: a list of X509 certificate
 *   [IN,OUT] pCrlList: a list of X509 crl
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 15:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodeStreamCertCrl(CMSCBB_VRF* pVrf, const CVB_BYTE* pbContent, CVB_UINT32 nContentLength, LIST_OF(CmscbbX509Cert)* pCertList, LIST_OF(CmscbbX509Crl)* pCrlList)
{
    CMSCBB_ERROR_CODE ret;
    const CVB_BYTE* pbEncoded = pbContent;
    CVB_UINT32 nDecodedLength = 0;
    CmscbbX509Cert* pCert = CVB_NULL;
    CmscbbX509Crl* pCrl = CVB_NULL;
    CVB_UINT32 nRemainLength = nContentLength;

#if CMSCBB_CACHE_ASN_DATA
    {
        CVB_BYTE* pbCopy = CVB_NULL;
        ret = CmscbbMalloc((CVB_VOID**)&pbCopy, nContentLength);
        CVB_GOTO_ERR_IF_FAIL(ret);

        ret = (CMSCBB_ERROR_CODE)memcpy_s(pbCopy, nContentLength, pbContent, nContentLength);
        if (CVB_FAILED(ret)) {
            CmscbbFree(pbCopy);
            CVB_LOG_ERROR(ret, NULL);
            return ret;
        }

        ret = CMSCBB_LIST_ADD(&pVrf->raw_set, pbCopy);
        if (CVB_FAILED(ret)) {
            CmscbbFree(pbCopy);
            return ret;
        }
        pbEncoded = pbCopy;
    }
#else
    ret = 0;
    pVrf->resv[0] = 0;
#endif

    while (nRemainLength > 0) {
        ret = CmscbbX509DecodeCert(pbEncoded, nRemainLength, &pCert, &nDecodedLength);
        if (pCert != CVB_NULL) {
            if (pCertList != CVB_NULL) {
                ret = CMSCBB_LIST_ADD(pCertList, pCert);
                CVB_GOTO_ERR_IF_FAIL_LOG(ret);
            } else {
                CmscbbX509FreeCert(pCert);
            }
            pbEncoded += nDecodedLength;
            nRemainLength -= nDecodedLength;
            pCert = CVB_NULL;
            continue;
        }

        ret = CmscbbX509DecodeCrl(pbEncoded, nRemainLength, &pCrl, &nDecodedLength);
        if (pCrl != CVB_NULL) {
            if (pCrlList != CVB_NULL) {
                ret = CMSCBB_LIST_ADD(pCrlList, pCrl);
                CVB_GOTO_ERR_IF_FAIL_LOG(ret);
            } else {
                CmscbbX509FreeCrl(pCrl);
            }
            pbEncoded += nDecodedLength;
            nRemainLength -= nDecodedLength;
            pCrl = CVB_NULL;
            continue;
        }

        break;
    }

    /* Provides limited fault tolerance, allowing for a certain amount of redundant data */
    if (ret != CVB_SUCCESS && nRemainLength <= 32) {
        ret = CVB_SUCCESS;
    }
    goto CVB_FINAL;
CVB_ERR:
    CmscbbX509FreeCert(pCert);
    CmscbbX509FreeCrl(pCrl);
CVB_FINAL:
    return ret;
}
