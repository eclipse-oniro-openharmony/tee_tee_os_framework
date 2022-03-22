/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: y00309840
 * Create: 2018/12/12
 * History: 2018/12/12 new
 */
#ifndef H_CMSCBB_CMS_PARSE_H
#define H_CMSCBB_CMS_PARSE_H
#include "cmscbb_cms_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Prototype    : CmscbbPkcs7DecodeSigned
 * Description  : Decode CMS, which is encoded by DER
 * Params
 *   [IN] pbEncodedP7: bytes encoded by pkcs7
 *   [IN] nEncodedLength: the length of pkcs7 content 
 *   [OUT] ppSigned: pkcs7 signed content
 *   [OUT] bytesDecoded: decoded result
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 20:17  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbPkcs7DecodeSigned(const CVB_BYTE* pbEncodedP7, CVB_UINT32 nEncodedLength, CmscbbPkcs7Content** ppSigned, CVB_UINT32* bytesDecoded);

/*
 * Prototype    : CmscbbPkcs7FreeSigned
 * Description  : Free CMS
 * Params
 *   [IN] pSigned: pkcs7 signed content
 * Return Value : CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 20:18  t00307193  Create
 */
CVB_VOID CmscbbPkcs7FreeSigned(CmscbbPkcs7Content* pSigned);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* H_CMSCBB_CMS_PARSE_H */
