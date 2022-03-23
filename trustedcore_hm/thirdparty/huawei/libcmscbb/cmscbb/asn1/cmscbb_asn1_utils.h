/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_ASN1_UTILS_H
#define H_CMSCBB_ASN1_UTILS_H
#include "../cmscbb_common/cmscbb_common.h"

/*
 * Prototype    : CmscbbCompareAsnOcts
 * Description  : compare two CmscbbAsnOcts
 * Return Value :
 *   if pAsnOctsExpect > pAsnOctsActual return >0
 *   else if pAsnOctsExpect == pAsnOctsActual return ==0
 *   else return <0
 *   Date              Author     Modification
 *   2015/08/03 9:35  t00307193  Create
 */
CVB_INT32 CmscbbCompareAsnOcts(const CmscbbAsnOcts* pAsnOctsExpect, const CmscbbAsnOcts* pAsnOctsActual);

#define CMSCBB_COMPARE_ASN_BITS CmscbbCompareAsnOcts
#define CMSCBB_COMPARE_ASN_OID CmscbbCompareAsnOcts

/*
 * Prototype    : CmscbbFindOid
 * Description  : Find object id by id index.
 * Params
 *   [IN] aoid: id index
 * Return Value : matched object id, or CVB_NULL if not found.
 *   Date              Author     Modification
 *   2015/07/17 11:39  t00307193  Create
 */
const CmscbbAsnOid* CmscbbFindOid(CMSCBB_AOIDS aoid);

/*
 * Prototype    : CmscbbFindAoid
 * Description  : find id index by object id
 * Params
 *   [IN] pOid: object id
 * Return Value : matched id index, or AOID_UNKNOWN if not found.
 *   Date              Author     Modification
 *   2015/07/29 17:20  t00307193  Create
 */
CMSCBB_AOIDS CmscbbFindAoid(const CmscbbAsnOid* pOid);

/* create tag from class, form and code */
#define CMSCBB_MAKE_TAG(tag, _cls, _form, _code) do { \
    (tag).cls = (CMSCBB_BER_CLASS)(_cls); \
    (tag).form = (CMSCBB_BER_FORM)(_form); \
    (tag).code = (CMSCBB_BER_TAG_CODE)(_code); \
} while (0)

/*
 * Prototype    : CmscbbConvertFromTime
 * Description  : Convert time object into time structure.
 * Params
 *   [IN] pAsnTime: a string of time in  pAsnTime->octs
 *   [OUT] pDateTime: timestamp
 *   Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/08/17 14:30  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbConvertFromTime(const CmscbbAsnOcts* pAsnTime, CmscbbDatetime* pDateTime);

/*
 * Prototype    : CmscbbConvertDatetimeToTime
 * Description  : Convert time object to time_t value
 * Params
 *   [IN] pAsnTime: a string of time in  pAsnTime->octs
 *   [OUT] r_tm: a timestamp
 * Return Value : CMSCBB_ERROR_CODE
 *
 *   Date              Author     Modification
 *   2015/08/17 14:41  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbConvertDatetimeToTime(const CmscbbAsnOcts* pAsnTime, CVB_TIME_T* r_tm);

/*
 * Prototype    : CmscbbGetHashAoidFromSign
 * Description  : return associated hash algorithm from signature algorithm
 * Params
 *   [IN] signId: object id
 * Return Value : CMSCBB_AOIDS
 * Remarks      : Associated hash algorithm, or AOIDS_UNKNOW if not found.
 *   Date              Author     Modification
 *   2015/11/11 9:47  t00307193  Create
 */
CMSCBB_AOIDS CmscbbGetHashAoidFromSign(const CmscbbAsnOid* pSignId);
#endif  /* H_CMSCBB_ASN1_UTILS_H */

