/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../asn1/cmscbb_asn1_utils.h"

/*
 * Prototype    : CmscbbFindOid
 * Description  : Find object id by id index.
 * Params
 *   [IN] aoid: id index
 * Return Value : matched object id, or CVB_NULL if not found.
 *   Date              Author     Modification
 *   2015/07/17 11:39  t00307193  Create
 */
const CmscbbAsnOid* CmscbbFindOid(CMSCBB_AOIDS aoid)
{
    CVB_INT i;

    for (i = 0; i < (CVB_INT)g_cvbOidCount; ++i) {
        if (g_cvbOIDTable[i].aoid == aoid) {
            return &g_cvbOIDTable[i].stAsnOid;
        }
    }

    return CVB_NULL;
}

/*
 * Prototype    : CmscbbFindAoid
 * Description  : find id index by object id
 * Params
 *   [IN] pOid: object id
 * Return Value : matched id index, or AOID_UNKNOWN if not found.
 *   Date              Author     Modification
 *   2015/07/29 17:20  t00307193  Create
 */
CMSCBB_AOIDS CmscbbFindAoid(const CmscbbAsnOid* pOid)
{
    CVB_INT iter;
    if (pOid == CVB_NULL) {
        return AOID_UNKNOWN;
    }

    for (iter = 0; iter < (CVB_INT)g_cvbOidCount; ++iter) {
        if (CMSCBB_COMPARE_ASN_OID(pOid, &(g_cvbOIDTable[iter].stAsnOid)) == 0) {
            return g_cvbOIDTable[iter].aoid;
        }
    }

    return AOID_UNKNOWN;
}

/*
 * Prototype    : CmscbbCompareAsnOcts
 * Description  : compare two CmscbbAsnOcts with octs
 *   Return Value : CVB_INT32 
 *   if pAsnOctsExpect > pAsnOctsActual return >0 
 *   else if pAsnOctsExpect == pAsnOctsActual return ==0 
 *   else return <0
 *   Date              Author     Modification
 *   2015/08/03 9:35  t00307193  Create
 */
#define CVB_OCTS_COMPARE_FAILED (-1)
#define CVB_OCTS_COMPARE_EQUAL 0
CVB_INT32 CmscbbCompareAsnOcts(const CmscbbAsnOcts* pAsnOctsExpect, const CmscbbAsnOcts* pAsnOctsActual)
{
    if (pAsnOctsExpect == CVB_NULL || pAsnOctsActual == CVB_NULL) {
        return CVB_OCTS_COMPARE_FAILED;
    }

    if (pAsnOctsExpect == pAsnOctsActual) {
        return CVB_OCTS_COMPARE_EQUAL;
    }

    if (pAsnOctsExpect->len != pAsnOctsActual->len) {
        return CVB_OCTS_COMPARE_FAILED;
    }

    if (pAsnOctsExpect->octs == pAsnOctsActual->octs) {
        return CVB_OCTS_COMPARE_EQUAL;
    }

    return CmscbbMemCmp(pAsnOctsExpect->octs, pAsnOctsActual->octs, pAsnOctsActual->len);
}

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
#define CVB_DECIMAL_BASE 10
#define GTC_YEAR_LENGTH 4
#define UTC_YEAR_LENGTH 2
#define GTC_YEAR_DECADE 2
#define GTC_YEAR_UNIT 3
#define YEAR_2000 2000
#define YEAR_1900 1900
#define MAX_UTC_YEAR 50
#define UTC_TIME_LENGTH 13
#define GTC_TIME_LENGTH 15
#define CVB_MONTH_HIGH 0
#define CVB_MONTH_LOW 1
#define CVB_DAY_HIGH 2
#define CVB_DAY_LOW 3
#define CVB_HOUR_HIGH 4
#define CVB_HOUR_LOW 5
#define CVB_MINU_HIGH 6
#define CVB_MINU_LOW 7
#define CVB_SECO_HIGH 8
#define CVB_SECO_LOW 9
#define CVB_THOUSAND 1000
#define CVB_HUNDRED 100
#define CVB_TEN 10
CMSCBB_ERROR_CODE CmscbbConvertFromTime(const CmscbbAsnOcts* pAsnTime, CmscbbDatetime* pDateTime)
{
    const CVB_BYTE* pbTime = CVB_NULL;

    if (pAsnTime == CVB_NULL || pDateTime == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pbTime = pAsnTime->octs;
    if (pAsnTime->tag.code == CBT_UTCTIME) {
        if (pAsnTime->len != UTC_TIME_LENGTH) {
            return CMSCBB_ERR_SYS_UTIL_CONVERT;
        }
        pDateTime->uYear = (CVB_UINT16)((*pbTime - '0') * CVB_DECIMAL_BASE + (*(pbTime + 1) - '0'));
        pDateTime->uYear = (CVB_UINT16)((CVB_INT)pDateTime->uYear + (pDateTime->uYear < MAX_UTC_YEAR ? YEAR_2000 : YEAR_1900));

        pbTime += UTC_YEAR_LENGTH;
    } else if (pAsnTime->tag.code == CBT_GENERALIZEDTIME) {
        if (pAsnTime->len != GTC_TIME_LENGTH) {
            return CMSCBB_ERR_SYS_UTIL_CONVERT;
        }
        pDateTime->uYear = (CVB_UINT16)((*pbTime - '0') * CVB_THOUSAND + (*(pbTime + 1) - '0') * CVB_HUNDRED + (*(pbTime + GTC_YEAR_DECADE) - '0') * CVB_TEN + (*(pbTime + GTC_YEAR_UNIT) - '0'));
        pbTime += GTC_YEAR_LENGTH;
    } else {
        return CMSCBB_ERR_SYS_UTIL_CONVERT;
    }

    pDateTime->uMonth = (CVB_UINT8)((pbTime[CVB_MONTH_HIGH] - '0') * CVB_DECIMAL_BASE + (pbTime[CVB_MONTH_LOW] - '0'));
    pDateTime->uDay = (CVB_UINT8)((pbTime[CVB_DAY_HIGH] - '0') * CVB_DECIMAL_BASE + (pbTime[CVB_DAY_LOW] - '0'));
    pDateTime->uHour = (CVB_UINT8)((pbTime[CVB_HOUR_HIGH] - '0') * CVB_DECIMAL_BASE + (pbTime[CVB_HOUR_LOW] - '0'));
    pDateTime->uMinute = (CVB_UINT8)((pbTime[CVB_MINU_HIGH] - '0') * CVB_DECIMAL_BASE + (pbTime[CVB_MINU_LOW] - '0'));
    pDateTime->uSecond = (CVB_UINT8)((pbTime[CVB_SECO_HIGH] - '0') * CVB_DECIMAL_BASE + (pbTime[CVB_SECO_LOW] - '0'));

    return CVB_SUCCESS;
}

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
CMSCBB_ERROR_CODE CmscbbConvertDatetimeToTime(const CmscbbAsnOcts* pAsnTime, CVB_TIME_T* r_tm)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbDatetime dt = {0};

    if (pAsnTime == CVB_NULL || r_tm == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = CmscbbConvertFromTime(pAsnTime, &dt);
    if (CVB_FAILED(ret)) {
        return ret;
    }

    *r_tm = CmscbbMktime(&dt);
    return CVB_SUCCESS;
}
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
CMSCBB_AOIDS CmscbbGetHashAoidFromSign(const CmscbbAsnOid* pSignId)
{
    CMSCBB_AOIDS hashAlgo = CmscbbFindAoid(pSignId);

    if (hashAlgo == AOID_SHA256 || hashAlgo == AOID_SHA256WITHRSAENCRYPTION) {
        return AOID_SHA256;
    }
#if CMSCBB_SUPPORT_SHA384
    if (hashAlgo == AOID_SHA384 || hashAlgo == AOID_SHA384WITHRSAENCRYPTION) {
        return AOID_SHA384;
    }
#endif
#if CMSCBB_SUPPORT_SHA512
    if (hashAlgo == AOID_SHA512 || hashAlgo == AOID_SHA512WITHRSAENCRYPTION) {
        return AOID_SHA512;
    }
#endif

    return AOID_UNKNOWN;
}
