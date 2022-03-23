/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_ASN1_DEF_H
#define H_CMSCBB_ASN1_DEF_H
#include "../asn1/cmscbb_asn1_tag.h"
#include "../cmscbb_common/cmscbb_list_def.h"
#include "cmscbb_config.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct cmscbb_asn_octs_st {
    CVB_UINT32 len;
    CMSCBB_BER_TAG tag;
    const CVB_BYTE* octs;
} CmscbbAsnOcts;
DECLARE_SET_OF(CmscbbAsnOcts, 10);

typedef struct cmscbb_asn_octs_bundle_st {
    SET_OF(CmscbbAsnOcts) bundle;
} CmscbbAsnOctsBundle;

typedef CmscbbAsnOcts CmscbbAsnBits;
typedef CVB_UINT32 CMSCBB_ASN_LEN;
typedef CVB_INT32  CmscbbAsnInt;
typedef CmscbbAsnInt   CmscbbAsnBool;
typedef CVB_INT32  CmscbbAsnEnum;
typedef CVB_CHAR   CMSCBB_ASN_NULL;
typedef CmscbbAsnOcts CmscbbAsnOid;
typedef CmscbbAsnOcts CMSCBB_ASN_RELATIVE_OID;
typedef CmscbbAsnOcts CmscbbAsnBigint;

typedef CmscbbAsnOcts CMSCBB_VISIBLE_STR;
typedef CmscbbAsnOcts CMSCBB_TELETEX_STR;
typedef CmscbbAsnOcts CMSCBB_UTF8_STR;
typedef CmscbbAsnOcts CMSCBB_UNIVERSAL_STR;
typedef CmscbbAsnOcts CMSCBB_PRINTABLE_STR;
typedef CmscbbAsnOcts CMSCBB_NUMERIC_STR;
typedef CmscbbAsnOcts CMSCBB_IA5_STR;
typedef CmscbbAsnOcts CMSCBB_BMP_STR;
typedef CmscbbAsnOcts CMSCBB_UTCTIME;
typedef CmscbbAsnOcts CMSCBB_GENERALIZEDTIME;

DECLARE_SET_OF(CmscbbAsnOid, 10);

#define CVB_ASN_INDEFINITE_LEN ((CVB_UINT32)~0L)

/* common ASN object id */
typedef enum CmscbbAoidsEm {
    AOID_UNKNOWN = 0,
    AOID_SHA256 = 43,
#if CMSCBB_SUPPORT_SHA384
    AOID_SHA384 = 44,
#endif
#if CMSCBB_SUPPORT_SHA512
    AOID_SHA512 = 45,
#endif
    AOID_SHA256WITHRSAENCRYPTION = 63,
#if CMSCBB_SUPPORT_SHA384
    AOID_SHA384WITHRSAENCRYPTION = 64,
#endif
#if CMSCBB_SUPPORT_SHA512
    AOID_SHA512WITHRSAENCRYPTION = 65,
#endif
    AOID_AT_COMMONNAME = 161,
    AOID_AT_LOCALITYNAME = 162,
    AOID_AT_STATEORPROVINCENAME = 163,
    AOID_AT_ORGANIZATIONNAME = 164,
    AOID_AT_ORGANIZATIONALUNITNAME = 165,
    AOID_AT_COUNTRYNAME = 168,
    AOID_PKCS9_AT_EMAILADDRESS = 172,
    AOID_CE_KEYUSAGE = 176,
    AOID_CE_BASICCONSTRAINTS = 184,
    AOID_CE_EXTKEYUSAGE = 188,
    AOID_KP_CODESIGNING = 192,
    AOID_KP_TIMESTAMPING = 193,
#if CMSCBB_SUPPORT_INDIRECT_CRL
    AOID_CE_ISSUINGDISTRIBUTIONPOINT = 202,
#endif
    AOID_CE_CRLREASONS = 204,
    AOID_PKCS7_SIGNEDDATA = 264,
    AOID_PKCS9_AT_MESSAGEDIGEST = 271,
    AOID_PKCS9_AT_TIMESTAMP_TOKEN = 307
} CMSCBB_AOIDS;

typedef struct cmscbb_oid_info_st {
    CMSCBB_AOIDS aoid;
    CmscbbAsnOcts stAsnOid;
    const CVB_CHAR* pucName;
} CmscbbOidInfo;

typedef struct CmscbbAsnOidBundle_st {
    SET_OF(CmscbbAsnOid) oid_bundle;
} CmscbbAsnOidBundle;

extern CmscbbOidInfo g_cvbOIDTable[];
extern CVB_UINT32 g_cvbOidCount;
#if CMSCBB_NEED_RELOCATE
extern CVB_BOOL g_cvbOidReloced;
#endif

#define CMSCBB_BUF_INVALID_POS CMSCBB_MAX_INT

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* H_CMSCBB_ASN1_DEF_H */
