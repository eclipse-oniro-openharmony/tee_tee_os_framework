/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_X509_DEF_H
#define H_CMSCBB_X509_DEF_H
#include "../asn1/cmscbb_asn1_def.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* X509 Extensions */
typedef struct cmscbb_x509_basic_constraints_st {
    CmscbbAsnBool isCa;
} CmscbbX509BasicConstraints;

typedef CmscbbAsnOcts CMSCBB_X509_SUBJECT_KID;

typedef struct cmscbb_x509_attr_entry_st {
    CmscbbAsnOid id;
    CmscbbAsnOcts value;
} CmscbbX509AttrEntry;
DECLARE_SET_OF(CmscbbX509AttrEntry, CMSCBB_X509_ATTR_ENTRY_COUNT);

typedef struct cmscbb_x509_attr_bundle_st {
    SET_OF(CmscbbX509AttrEntry) attrs;
} CmscbbX509AttrBundle;
DECLARE_SET_OF(CmscbbX509AttrBundle, CMSCBB_X509_ATTR_COUNT);

typedef struct CmscbbX509Name_st {
    SET_OF(CmscbbX509AttrBundle) names;
} CmscbbX509Name;

typedef struct cmscbb_x509_algo_identifier_st {
    CmscbbAsnOid algorithm;
    CmscbbAsnOcts parameters;
} CmscbbX509AlgoIdentifier;
DECLARE_SET_OF(CmscbbX509AlgoIdentifier, 1);

typedef struct cmscbb_rsa_pubkey_st {
    CmscbbAsnBigint modules;  /* value n */
    CmscbbAsnBigint publicExponent;  /* value e */
} CmscbbRsaPublicKey;

typedef struct cmscbb_x509_pubkey_st {
    CmscbbRsaPublicKey rsaPubKey;
} CmscbbX509PublicKey;

typedef struct cmscbb_x509_subject_pubkey_info_st {
    CmscbbX509AlgoIdentifier algorithm;
    CmscbbX509PublicKey subjectPublicKey;
} CmscbbX509PubkeyInfo;

typedef struct cmscbb_x509_extension_entry_st {
    CmscbbAsnOid extnId;
    CmscbbAsnBool critical;
    CmscbbAsnOcts extnValue;
} CmscbbX509ExtensionEntry;
DECLARE_SET_OF(CmscbbX509ExtensionEntry, 10);
DECLARE_LIST_OF(CmscbbX509ExtensionEntry);

typedef struct cmscbb_x509_validity_st {
    CmscbbAsnOcts notBefore;
    CmscbbAsnOcts notAfter;
} CmscbbX509Validity;

typedef struct cmscbb_x509_cert_exts_st {
    CmscbbX509BasicConstraints ca_info;
    CmscbbAsnInt ku;
    CmscbbAsnInt exku;
} CmscbbX509CertExts;

/* X509 CERT */
typedef struct cmscbb_x509_cert_info_st {
    CmscbbAsnBigint serialNumber;
    CmscbbX509Name issuer;
#ifdef CVB_DEBUG
    CVB_CHAR* _Issuer;
#endif /* CVB_DEBUG */
    CmscbbX509Validity validity;
    CmscbbX509Name subject;
#ifdef CVB_DEBUG
    CVB_CHAR* _Subject;
#endif /* CVB_DEBUG */
    CmscbbX509PubkeyInfo subjectPubKey;

    CmscbbX509CertExts extensions;
} CmscbbX509CertInfo;

typedef struct cmscbb_x509_cert_st {
    CmscbbAsnOcts rawSigned;
    CmscbbX509CertInfo toBeSigned;
    CmscbbX509AlgoIdentifier algorithm;
    CmscbbAsnBits signature;
    const struct cmscbb_x509_cert_st* pIssuer;  /* it should point to its issuer in verify session after the certificate verified */
    CVB_INT32 iRef;
} CmscbbX509Cert;
DECLARE_LIST_OF(CmscbbX509Cert);

typedef struct cmscbb_x509_cert_bundle_st {
    LIST_OF(CmscbbX509Cert) certs;
} CmscbbX509CertBundle;

typedef struct cmscbb_x509_cert_raw_bundle_st {
    SET_OF(CmscbbAsnOcts) bundle;
} CmscbbX509CertRawBundle;

/* X509 CRL */
typedef struct cmscbb_x509_revoke_attrs_st {
    CmscbbAsnInt reason;
} CmscbbX509RevokeAttrs;

typedef struct cmscb_x509_revoked_entry_st {
    CmscbbAsnBigint userCert;
    CmscbbAsnOcts revocationDate;
    CmscbbX509RevokeAttrs attrs;
} CmscbbX509RevokeEntry;
DECLARE_SET_OF(CmscbbX509RevokeEntry, 20);

typedef struct cmscbb_x509_revoked_st {
    SET_OF(CmscbbX509RevokeEntry) revoked_list;
} CmscbbX509Revoked;

#if CMSCBB_SUPPORT_INDIRECT_CRL
typedef struct cmscbb_x509_issuing_dist_point_st {
    CmscbbAsnOcts distpoint;
    CmscbbAsnBool onlyuser;
    CmscbbAsnBool onlyCA;
    CmscbbAsnBits onlysomereasons;
    CmscbbAsnBool indirectCRL;
    CmscbbAsnBool onlyattr;
} CmscbbX509IssuingDistPoint;

typedef struct cmscbb_x509_crl_attrs_st {
    CmscbbX509IssuingDistPoint idp;
} CmscbbX509CrlAttrs;
#endif

typedef struct cmscbb_x509_crlinfo_st {
    CmscbbAsnInt version;
    CmscbbX509AlgoIdentifier signatureAlgo;
    CmscbbX509Name issuer;
#ifdef CVB_DEBUG
    CVB_CHAR* _Issuer;
#endif /* CVB_DEBUG */
    CmscbbAsnOcts thisUpdateTime;
    CmscbbAsnOcts nextUpdateTime;
    CmscbbX509Revoked revokedCerts;
#if CMSCBB_SUPPORT_INDIRECT_CRL
    CmscbbX509CrlAttrs extensions;
#endif
} CmscbbX509CrlInfo;

typedef struct cmscbb_x509_crl_st {
    CmscbbAsnOcts rawSigned;
    CmscbbX509CrlInfo tbsCertList;
    CmscbbX509AlgoIdentifier algorithm;
    CmscbbAsnBits signature;
    CVB_INT iRef;
} CmscbbX509Crl;
DECLARE_SET_OF(CmscbbX509Crl, 3);
DECLARE_LIST_OF(CmscbbX509Crl);

typedef enum cmscbb_x509_revoke_reason_em {
    RVRS_NONE = -1,
    RVRS_UNUSED = 0,
    RVRS_KEYCOMPROMISE = 1,
    RVRS_CACOMPROMISE = 2,
    RVRS_AFFILIATIONCHANGED = 3,
    RVRS_SUPERSEDED = 4,
    RVRS_CESSATIONOFOPERATION = 5,
    RVRS_CERTIFICATEHOLD = 6,
    RVRS_PRIVILEGEWITHDRAWN = 7,
    RVRS_AACOMPROMISE = 8,
} CmscbbX509RevokeReason;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !H_CMSCBB_X509_DEF_H */

