/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_CMS_DEF_H
#define H_CMSCBB_CMS_DEF_H
#include "../asn1/cmscbb_asn1_def.h"
#include "../cmscbb_common/cmscbb_def.h"
#include "../cmscbb_common/cmscbb_common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* TS INFO */
typedef struct cmscbb_ts_msg_imprint_st {
    CmscbbX509AlgoIdentifier hash_algo;
    CmscbbAsnOcts hash_value;
} CmscbbTsMsgImprint;


typedef struct cmscbb_tst_info_st {
    CmscbbTsMsgImprint msg_imprint;
    CmscbbAsnOcts time;
} CmscbbTimestampInfo;

typedef struct cmscbb_pkcs7_content_info_st {
    CmscbbAsnOid type;
    CmscbbAsnOcts content;
} CmscbbPkcs7ContentInfo;

typedef struct cmscbb_pkcs7_issuer_and_serial_st {
    CmscbbX509Name issuer;
    CmscbbAsnBigint sn;
} CmscbbPkcs7IssuerAndSerial;

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
typedef struct cmscbb_x509_signed_attrs_st {
    CmscbbAsnOcts hash_value;
} CmscbbX509SignedAttrs;
#endif

typedef struct cmscbb_x509_unsigned_attrs_st {
    CmscbbAsnOcts timestamp;
} CmscbbX509UnsignedAttrs;

typedef struct cmscbb_pkcs7_signer_info_st {
    CmscbbAsnInt version;
    CmscbbPkcs7IssuerAndSerial issuerSn;
#ifdef CVB_DEBUG
    CVB_CHAR* _Issuer;
#endif /* CVB_DEBUG */
    CmscbbX509AlgoIdentifier digest_algo;
#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
    CmscbbAsnOcts rawSigned;
    CmscbbX509SignedAttrs auth_attrs;
#endif
    CmscbbAsnOcts encrypted_digest;
    CmscbbX509UnsignedAttrs unauth_attrs;
} CmscbbPkcs7SignedInfo;
DECLARE_SET_OF(CmscbbPkcs7SignedInfo, 1);

typedef struct cmscbb_pkcs7_signer_info_bundle_st {
    SET_OF(CmscbbPkcs7SignedInfo) infos;
} CmscbbPkcs7SignedInfoBundle;

typedef struct cmscbb_pkcs7_signed_data_st {
    CmscbbAsnInt version;
    CmscbbPkcs7ContentInfo content;
    CmscbbX509CertRawBundle raw_certs;
    CmscbbX509CertBundle certificates;
    CmscbbPkcs7SignedInfoBundle signer_infos;
} CmscbbPkcs7SignedData;

typedef struct cmscbb_contentinfo_st {
    CmscbbAsnOid content_type;
    CmscbbPkcs7SignedData signed_data;
} CmscbbPkcs7Content;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* H_CMSCBB_CMS_DEF_H */
