/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: y00309840
 * Create: 2018/12/12
 * History: 2018/12/12 new
 */
#ifndef H_CMS_VERIFY_H
#define H_CMS_VERIFY_H
#include "../cmscbb_common/cmscbb_common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodeStreamCertCrl(CMSCBB_VRF* pVrf, const CVB_BYTE* pbContent,
    CVB_UINT32 nContentLength, LIST_OF(CmscbbX509Cert)* pCertList, LIST_OF(CmscbbX509Crl)* pCrlList);

/*
 * Prototype    : InternalFreeMdInfo
 * Description  : free CMSCBB_VERIFY_DIGEST_INFO
 * Params
 *   [IN] pDigestInfo: verify digest info
 * Return Value : CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 14:52  t00307193  Create
 */
CVB_STATIC CVB_VOID InternalFreeMdInfo(CMSCBB_VERIFY_DIGEST_INFO* pDigestInfo);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* H_CMS_VERIFY_H */
