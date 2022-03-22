/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */

/*
 * File Name          : cmscbb_cms_vrf.h
 * Brief              : <TODO>
 * Author             : t00307193
 * Creation Date      : 2015/05/28 11:20
 * Detail Description : cmscbb  Interface Definition header File
 * History            : t00307193   2015/05/28 11:20     new
 */
#ifndef H_CMSCBB_CMS_VRF_H
#define H_CMSCBB_CMS_VRF_H
#include "cmscbb_config.h"
#include "cmscbb_plt_def.h"
#include "cmscbb_err_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef CVB_VOID* CMSCBB_VRF_CTX;

#define MAX_ISSUER_NAME_LENGTH 256
#if CMSCBB_SUPPORT_CRL_COMPARE

#define CMSCBB_MAX_SN_LEN 32
/* define serials number type */
typedef struct cmscbb_serial_num_st {
    CVB_BYTE sn[CMSCBB_MAX_SN_LEN];
    CVB_UINT32 snLenth;
} CmscbbSerialNum;

/* list of serials number of revoked certs */
typedef struct cmscbb_revoke_list_st {
    CmscbbSerialNum* snList;
    CVB_UINT32 revokeCount;
} CmscbbRevokeList;

/* Keep informations for CRL parse result */
#define MAX_CRL_SUPPORT 16
typedef struct cmscbb_crl_info_st {
#if CMSCBB_STRICT_CHECK
    CVB_SIZE_T st_size;
#endif
    int valid;		/* is valid */
#if CMSCBB_BYTE_ALIGN
    CVB_BYTE resv0[4];
#endif
    CVB_INT64 updateTime;	/* Date of issue, number of seconds from 1970-1-1 0 */
    CVB_INT64 validUntil;  /* Next issue date, number of seconds from 1970-1-1 0. */
    CVB_CHAR issuer[MAX_ISSUER_NAME_LENGTH];	/* Publishing person Information */
    CmscbbSerialNum issuerSn;    /* Issue Certificate serial number */
    CmscbbRevokeList revokeList; /* Root certificate Revocation List */
    CVB_CHAR resv[60];
} CmscbbCrlInfo;

/* CRL result bundle/set */
typedef struct cmscbb_crl_bundle_info_st {
    CVB_SIZE_T st_size;
    CmscbbCrlInfo* crlInfoList[MAX_CRL_SUPPORT];	/* CRL Information list, maximum can save 16 */
    CVB_INT crlCount;	/* Number of true information of CRLs */
    CVB_CHAR resv[64];
} CmscbbCrlBundleInfo;

/* CRL bundle/set issue time compare options */
typedef enum cmscbb_crl_period_stat {
    SCPS_SAME = 0,
    SCPS_NEW = 1,
    SCPS_OLD = 2,
    SCPS_MIX = 3,
} CmscbbCrlPeriodStat;
#endif /* CMSCBB_SUPPORT_CRL_COMPARE */

/*
 * Keep informations for creating verify context
 * callback_funcs: platform related functions, which implemented by caller
 */
typedef struct cmscbb_ctx_create_params_st {
    CVB_SIZE_T st_size;	/* size of this struct */

#if CMSCBB_NEED_RELOCATE
    CVB_ULONG relocBase;	/* system base address to relocate compiled address */
#endif
    CVB_CHAR resv[64];
} CmscbbCtxCreateParams;

/*
 * Prototype    : CmscbbVerifyCreateCtx
 * Description  : Create verify context
 * Params
 *   [IN] pCtx: Verify that the above
 *   [IN] pParams: Verify that the above build param
 * Return Value : return cvb_success correctly, error return error code
 * Remarks      : Params must be set correctly when initializing st_size = sizeof(CmscbbCtxCreateParams)
 *   Date              Author     Modification
 *   2015/11/09 15:52  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyCreateCtx(CMSCBB_VRF_CTX* pCtx,
    const CmscbbCtxCreateParams* pParams);

#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : CmscbbVerifyAddCertFile
 * Description  : Add a CA certificate as a file and a signing certificate
 * Params
 *   [IN] ctx: Signature context
 *   [IN] pszCertFile: Certificate file path
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 15:55  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyAddCertFile(CMSCBB_VRF_CTX ctx,
    const CVB_CHAR* pszCertFile);
#endif

/*
 * Prototype    : CmscbbVerifyAddCert
 * Description  : Adding CA certificates and signing certificates as data
 * Params
 *   [IN] ctx: Signature context
 *   [IN] pbCert: X509Certificate data
 *   [IN] nCertLength: X509Certificate data length
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 15:57  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyAddCert(CMSCBB_VRF_CTX ctx,
    const CVB_BYTE* pbCert, CVB_UINT32 nCertLength);

#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : CmscbbVerifyAddCrlFile
 * Description  : Add a CRL list as a file
 * Params
 *   [IN] ctx: Signature context
 *   [IN] pszCrlFile: CRL file path
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 15:58  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyAddCrlFile(CMSCBB_VRF_CTX ctx, const CVB_CHAR* pszCrlFile);
#endif

/*
 * Prototype    : CmscbbVerifyAddCrl
 * Description  : Add a list of CRLs in data form
 * Params
 *   [IN] ctx: Signature context
 *   [IN] pbCrl: CRL list
 *   [IN] nCrlLength: CRL data length
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:27  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyAddCrl(CMSCBB_VRF_CTX ctx,
    const CVB_BYTE* pbCrl, CVB_UINT32 nCrlLength);

#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : CmscbbVerifyDetachSignatureQuick
 * Description  : Verifying a separate signature
 * Params
 *   [IN] ctx: Validation context
 *   [IN] srcfile: Verify the source file path of the signature file
 *   [IN] sigfile: CMS-formatted signature file path
 *   [OUT] result: Return validation result, 1 is passed, 0 is not passed
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:28  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureQuick(CMSCBB_VRF_CTX ctx,
    const CVB_CHAR* srcfile, const CVB_CHAR* sigfile, CVB_INT32* result);
#endif

/*
 * Prototype    : CmscbbVerifyDetachSignatureBegin
 * Description  : Preparing verification signatures
 * Params
 *   [IN] ctx: Signature context
 *   [IN] pbSignature: Signature data in CMS format
 *   [IN] nSigLength: The length of the signature data
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:29  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureBegin(CMSCBB_VRF_CTX ctx,
    const CVB_BYTE* pbSignature, CVB_UINT32 nSigLength);

/*
 * Prototype    : CmscbbVerifyDetachSignatureUpdate
 * Description  : Enter the contents of the signature
 * Params
 *   [IN] ctx: Signature context
 *   [IN] pbContent: The data for the signature content, if the signature data is too large, 
 *        you can call the update function multiple times, * Must ensure that the segmented data sequence is unchanged
 *   [IN] nContentLength: The length of the signed content fragment data
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:31  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureUpdate(CMSCBB_VRF_CTX ctx,
    const CVB_BYTE* pbContent, CVB_INT32 nContentLength);

/*
 * Prototype    : CmscbbVerifyDetachSignatureFinal
 * Description  : Verifying signatures
 * Params
 *   [IN] ctx: Signature context
 *   [IN] result: Validation results, 1 means pass, 0 means no.
 * Return Value : return cvb_success correctly, error return error code
 * Remarks      : <TODO>
 *   Date              Author     Modification
 *   2015/11/09 18:35  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyDetachSignatureFinal(CMSCBB_VRF_CTX ctx, CVB_INT32* result);

/*
 * Prototype    : CmscbbVrfCtxFree
 * Description  : revoked Validation context
 * Params
 *   [IN] ctx: A CMSCBB_VERIFY_CTX structure that needs to be released
 * Return Value : return cvb_success correctly, error return error code
 * Remarks      : <TODO>
 *   Date              Author     Modification
 *   2015/11/09 18:41  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVrfCtxFree(CMSCBB_VRF_CTX ctx);

#if CMSCBB_ALLOW_NO_CHECK_TSA_CRL
/*
 * Prototype    : CmscbbVerifyGetTsaCertSn
 * Description  : return the tsa cert's sn of cms
 * Params
 *   [IN] ctx: verify context
 *   [OUT] sn: serials number of tsa cert
 * Return Value : CMSCBB_ERROR_CODE
 * Remarks      : the sn will return correctly only when the cms verify passed
 *   Date              Author     Modification
 *   2016/07/14 10:37  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbVerifyGetTsaCertSn(CMSCBB_VRF_CTX ctx, CmscbbSerialNum* sn);
#endif

/*
 * Prototype    : CmscbbGetVersion
 * Description  : Get version number
 * Params
 *   [IN] :NA
 * Return Value : Return version Information
 *   Date              Author     Modification
 *   2015/11/09 18:42  t00307193  Create
 */
const CVB_CHAR* CmscbbGetVersion(CVB_VOID);

#if CMSCBB_SUPPORT_CRL_COMPARE
#if CMSCBB_SUPPORT_FILE
/*
 * Prototype    : CmscbbDecodeCrlFile
 * Description  : Get CRL File Information
 * Params
 *   [IN] ctx: Validation context
 *   [IN] crlFile: CRL file path
 *   [OUT] pResult:  Parse the result, including all CRL information in the file
 * Return Value : return cvb_success correctly, error return error code
 * Remarks      :The CRL file may have merged a CRL published by multiple root CAs, so the return result is a list of CRL information
 *   Date              Author     Modification
 *   2015/11/09 18:42  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbDecodeCrlFile(CMSCBB_VRF_CTX ctx,
    const CVB_CHAR* crlFile, CmscbbCrlBundleInfo** pResult);
#endif

/*
 * Prototype    : CmscbbDecodeCrl
 * Description  : Resolving CRL Data
 * Params
 *   [IN] ctx: Validation context
 *   [IN] pbCrl: CRL data address
 *   [IN] nCrlLength: CRL data length
 *   [OUT] pResult: CRL resolution results, containing all CRL information
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:45  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbDecodeCrl(CMSCBB_VRF_CTX ctx,
    const CVB_BYTE* pbCrl, CVB_UINT32 nCrlLength, CmscbbCrlBundleInfo** pResult);

/*
 * Prototype    : CmscbbCrlFree
 * Description  : <TODO>
 * Params
 *   [IN] ctx: Validation context
 *   [IN] pCrlBundle: CRL resolution Results
 * Return Value : return cvb_success correctly, error return error code
 *   Date              Author     Modification
 *   2015/11/09 18:48  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbCrlFree(CMSCBB_VRF_CTX ctx, CmscbbCrlBundleInfo* pCrlBundle);

/*
 * Prototype    : CmscbbCrlCompare
 * Description  : Compare two CRL file information which update
 * Params
 *   [IN] ctx: Validation context
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
CMSCBB_ERROR_CODE CmscbbCrlCompare(CMSCBB_VRF_CTX ctx, const CmscbbCrlBundleInfo* crlToUpdate, const CmscbbCrlBundleInfo* crlOnDevice,
    CmscbbCrlPeriodStat* stat);
#endif /* CMSCBB_SUPPORT_CRL_COMPARE */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* H_CMSCBB_CMS_VRF_H */
