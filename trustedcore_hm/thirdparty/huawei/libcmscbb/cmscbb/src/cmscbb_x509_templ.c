/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../x509/cmscbb_x509_templ.h"
#include "../asn1/cmscbb_asn1_decode.h"

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509AlgoIdentifier) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509AlgoIdentifier, CmscbbAsnOcts, algorithm),
    CMSCBB_ASN_OPTIONAL_ITEM(CmscbbX509AlgoIdentifier, CmscbbAsnOcts, parameters),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509AlgoIdentifier, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509AttrEntry) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509AttrEntry, CmscbbAsnOcts, id),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509AttrEntry, CmscbbAsnOcts, value),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509AttrEntry, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509AttrBundle) = {
    CMSCBB_ASN_SET_ITEM(CmscbbX509AttrBundle, CmscbbX509AttrEntry, attrs, (CVB_ULONG)CMSCBB_X509_ATTR_ENTRY_COUNT),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509AttrBundle, g_cvbAsnFuncSetOf, CBT_SETS);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509Name) = {
    CMSCBB_ASN_SET_ITEM(CmscbbX509Name, CmscbbX509AttrBundle, names, (CVB_ULONG)CMSCBB_X509_ATTR_COUNT),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509Name, g_cvbAsnFuncSetOf, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509Validity) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Validity, CmscbbAsnOcts, notBefore),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Validity, CmscbbAsnOcts, notAfter),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509Validity, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbRsaPublicKey) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbRsaPublicKey, CmscbbAsnBigint, modules),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbRsaPublicKey, CmscbbAsnBigint, publicExponent),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbRsaPublicKey, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509PublicKey) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509PublicKey, CmscbbRsaPublicKey, rsaPubKey),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509PublicKey, g_cvbAsnFuncSeq, CBT_BITSTRING);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509PubkeyInfo) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509PubkeyInfo, CmscbbX509AlgoIdentifier, algorithm),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509PubkeyInfo, CmscbbX509PublicKey, subjectPublicKey)
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509PubkeyInfo, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509ExtensionEntry) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509ExtensionEntry, CmscbbAsnOcts, extnId),
    CMSCBB_ASN_DEFAULT_ITEM(CmscbbX509ExtensionEntry, CmscbbAsnBool, critical, 0),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509ExtensionEntry, CmscbbAsnOcts, extnValue),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509ExtensionEntry, g_cvbAsnFuncSeq, CBT_SEQUENCES);

#if CMSCBB_RELOC_STRICT_CHECK
CVB_STATIC CmscbbAsn1Item g_itemCmscbbAsnBitsToInt = {
    CVB_NULL, &g_cvbAsnFuncBitsToInt, CVB_FALSE, CBC_UNIV,
    CBF_PRIM, CBT_BITSTRING, 0, sizeof(CmscbbAsnInt)
};
CVB_STATIC CmscbbAsn1Item g_itemCmscbbAsnExku = {
    CVB_NULL, &g_cvbAsnFuncExku, CVB_FALSE, CBC_UNIV, CBF_PRIM,
    CBT_OID, 0, sizeof(CmscbbAsnInt)
};
#else
CVB_STATIC CmscbbAsn1Item g_itemCmscbbAsnBitsToInt = {
    CVB_NULL, &g_cvbAsnFuncBitsToInt, CBC_UNIV, CBF_PRIM,
    CBT_BITSTRING, 0, sizeof(CmscbbAsnInt)
};
CVB_STATIC CmscbbAsn1Item g_itemCmscbbAsnExku = {
    CVB_NULL, &g_cvbAsnFuncExku, CBC_UNIV, CBF_PRIM, CBT_OID, 0, sizeof(CmscbbAsnInt)
};
#endif

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509BasicConstraints) = {
    CMSCBB_ASN_DEFAULT_ITEM(CmscbbX509BasicConstraints, CmscbbAsnBool, isCa, CVB_FALSE),
    CMSCBB_ASN_IGNORE_ITEM(CmscbbX509BasicConstraints, CmscbbAsnOcts, CVB_ASN_OPTIONAL),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509BasicConstraints, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509CertExts) = {
    CMSCBB_ASN_MAP_ITEM(CmscbbX509CertExts, CmscbbX509BasicConstraints, ca_info, AOID_CE_BASICCONSTRAINTS),
    CMSCBB_ASN_MAP_ITEM(CmscbbX509CertExts, CmscbbAsnBitsToInt, ku, AOID_CE_KEYUSAGE),
    CMSCBB_ASN_MAP_ITEM(CmscbbX509CertExts, CmscbbAsnExku, exku, AOID_CE_EXTKEYUSAGE),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509CertExts, g_cvbAsnFuncMap, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509CertInfo) = {
    CMSCBB_ASN_IGNORE_EX_ITEM(CmscbbX509CertInfo, CmscbbAsnInt, CVB_ASN_IGNORE, CVB_ASN_EXPLICIT, 0),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CertInfo, CmscbbAsnBigint, serialNumber),
    CMSCBB_ASN_IGNORE_NORMAL_ITEM(CmscbbX509CertInfo, CmscbbAsnSeq),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CertInfo, CmscbbX509Name, issuer),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CertInfo, CmscbbX509Validity, validity),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CertInfo, CmscbbX509Name, subject),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CertInfo, CmscbbX509PubkeyInfo, subjectPubKey),
    CMSCBB_ASN_IGNORE_EX_ITEM(CmscbbX509CertInfo, CmscbbAsnBits, CVB_ASN_OPTIONAL, CVB_ASN_IMPLICIT, TAG_NUM_1),    /* issuerUID */
    CMSCBB_ASN_IGNORE_EX_ITEM(CmscbbX509CertInfo, CmscbbAsnBits, CVB_ASN_OPTIONAL, CVB_ASN_IMPLICIT, TAG_NUM_2),    /* subjectUID */
    CMSCBB_ASN_EXPLICIT_ITEM(CmscbbX509CertInfo, CmscbbX509CertExts, extensions, CVB_ASN_OPTIONAL, TAG_NUM_3), /* extensions */
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509CertInfo, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509Cert) = {
    CMSCBB_ASN_PEEK_ITEM(CmscbbX509Cert, rawSigned),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Cert, CmscbbX509CertInfo, toBeSigned),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Cert, CmscbbX509AlgoIdentifier, algorithm),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Cert, CmscbbAsnBits, signature),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509Cert, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509RevokeAttrs) = {
    CMSCBB_ASN_MAP_ITEM(CmscbbX509RevokeAttrs, CmscbbAsnEnum, reason, AOID_CE_CRLREASONS),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509RevokeAttrs, g_cvbAsnFuncMap, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509RevokeEntry) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509RevokeEntry, CmscbbAsnBigint, userCert),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509RevokeEntry, CmscbbAsnOcts, revocationDate),
    CMSCBB_ASN_OPTIONAL_ITEM(CmscbbX509RevokeEntry, CmscbbX509RevokeAttrs, attrs),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509RevokeEntry, g_cvbAsnFuncSeq, CBT_SEQUENCES);

#define MAX_REVOKE_COUNT 20
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509Revoked) = {
    CMSCBB_ASN_SET_ITEM(CmscbbX509Revoked, CmscbbX509RevokeEntry, revoked_list, (CVB_ULONG)MAX_REVOKE_COUNT),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509Revoked, g_cvbAsnFuncSetOf, CBT_SEQUENCES);

#if CMSCBB_SUPPORT_INDIRECT_CRL
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509IssuingDistPoint) = {
    CMSCBB_ASN_IMPLICIT_ITEM(CmscbbX509IssuingDistPoint, CmscbbAsnOcts, distpoint, 0),
    CMSCBB_ASN_NORMAL_IMP_ITEM(CmscbbX509IssuingDistPoint, CmscbbAsnBool, onlyuser, TAG_NUM_1),
    CMSCBB_ASN_NORMAL_IMP_ITEM(CmscbbX509IssuingDistPoint, CmscbbAsnBool, onlyCA, TAG_NUM_2),
    CMSCBB_ASN_IMPLICIT_ITEM(CmscbbX509IssuingDistPoint, CmscbbAsnBits, onlysomereasons, TAG_NUM_3),
    CMSCBB_ASN_NORMAL_IMP_ITEM(CmscbbX509IssuingDistPoint, CmscbbAsnBool, indirectCRL, TAG_NUM_4),
    CMSCBB_ASN_NORMAL_IMP_ITEM(CmscbbX509IssuingDistPoint, CmscbbAsnBool, onlyattr, TAG_NUM_5),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509IssuingDistPoint, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509CrlAttrs) = {
    CMSCBB_ASN_MAP_ITEM(CmscbbX509CrlAttrs, CmscbbX509IssuingDistPoint, idp, AOID_CE_ISSUINGDISTRIBUTIONPOINT),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509CrlAttrs, g_cvbAsnFuncMap, CBT_SEQUENCES);
#endif

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509CrlInfo) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CrlInfo, CmscbbAsnInt, version),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CrlInfo, CmscbbX509AlgoIdentifier, signatureAlgo),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CrlInfo, CmscbbX509Name, issuer),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CrlInfo, CmscbbAsnOcts, thisUpdateTime),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509CrlInfo, CmscbbAsnOcts, nextUpdateTime),
    CMSCBB_ASN_OPTIONAL_ITEM(CmscbbX509CrlInfo, CmscbbX509Revoked, revokedCerts),
#if CMSCBB_SUPPORT_INDIRECT_CRL
    CMSCBB_ASN_EXPLICIT_ITEM(CmscbbX509CrlInfo, CmscbbX509CrlAttrs, extensions, CVB_ASN_OPTIONAL, 0),
#else
    CMSCBB_ASN_IGNORE_EX_ITEM(CmscbbX509CrlInfo, CmscbbAsnSeq, CVB_ASN_OPTIONAL, CVB_ASN_EXPLICIT, 0),
#endif
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509CrlInfo, g_cvbAsnFuncSeq, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509Crl) = {
    CMSCBB_ASN_PEEK_ITEM(CmscbbX509Crl, rawSigned),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Crl, CmscbbX509CrlInfo, tbsCertList),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Crl, CmscbbX509AlgoIdentifier, algorithm),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbX509Crl, CmscbbAsnBits, signature),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509Crl, g_cvbAsnFuncSeq, CBT_SEQUENCES);

#if CMSCBB_DELAY_ADDRESS_SET
#define CVB_ITEM_IDX0 0
#define CVB_ITEM_IDX1 1
#define CVB_ITEM_IDX2 2
#define CVB_ITEM_IDX3 3
#define CVB_ITEM_IDX4 4
#define CVB_ITEM_IDX5 5
#define CVB_ITEM_IDX6 6
#define CVB_ITEM_IDX7 7
#define CVB_ITEM_IDX8 8
#define CVB_ITEM_IDX9 9
CVB_STATIC CVB_VOID InternalCmscbbX509TemplInit1(CVB_VOID)
{
    /* CmscbbX509AlgoIdentifier */
    g_templCmscbbX509AlgoIdentifier[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509AlgoIdentifier[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbX509AttrEntry */
    g_templCmscbbX509AttrEntry[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509AttrEntry[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbX509AttrBundle */
    g_templCmscbbX509AttrBundle[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbX509AttrEntry;

    /* CmscbbX509Name */
    g_templCmscbbX509Name[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbX509AttrBundle;

    /* CmscbbX509Validity */
    g_templCmscbbX509Validity[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509Validity[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbRsaPublicKey */
    g_templCmscbbRsaPublicKey[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnBigint;
    g_templCmscbbRsaPublicKey[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnBigint;

    /* CmscbbX509PublicKey */
    g_templCmscbbX509PublicKey[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbRsaPublicKey;

    /* CmscbbX509PubkeyInfo */
    g_templCmscbbX509PubkeyInfo[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbX509AlgoIdentifier;
    g_templCmscbbX509PubkeyInfo[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbX509PublicKey;
}

CVB_STATIC CVB_VOID InternalCmscbbX509TemplInit2(CVB_VOID)
{
    /* CmscbbX509ExtensionEntry */
    g_templCmscbbX509ExtensionEntry[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509ExtensionEntry[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnBool;
    g_templCmscbbX509ExtensionEntry[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbX509BasicConstraints */
    g_templCmscbbX509BasicConstraints[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnBool;
    g_templCmscbbX509BasicConstraints[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbX509CertExts */
    g_templCmscbbX509CertExts[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbX509BasicConstraints;
    g_templCmscbbX509CertExts[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnBitsToInt;
    g_templCmscbbX509CertExts[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbAsnExku;

    /* CmscbbX509CertInfo */
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnInt;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnBigint;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbAsnSeq;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX3].asn1Item = &g_itemCmscbbX509Name;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX4].asn1Item = &g_itemCmscbbX509Validity;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX5].asn1Item = &g_itemCmscbbX509Name;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX6].asn1Item = &g_itemCmscbbX509PubkeyInfo;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX7].asn1Item = &g_itemCmscbbAsnBits;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX8].asn1Item = &g_itemCmscbbAsnBits;
    g_templCmscbbX509CertInfo[CVB_ITEM_IDX9].asn1Item = &g_itemCmscbbX509CertExts;

    /* CMSCBB_X509_CERT */
    g_templCmscbbX509Cert[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509Cert[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbX509CertInfo;
    g_templCmscbbX509Cert[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbX509AlgoIdentifier;
    g_templCmscbbX509Cert[CVB_ITEM_IDX3].asn1Item = &g_itemCmscbbAsnBits;
}

CVB_STATIC CVB_VOID InternalCmscbbX509TemplInit3(CVB_VOID)
{
    /* CmscbbX509RevokeAttrs */
    g_templCmscbbX509RevokeAttrs[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnEnum;

    /* CmscbbX509RevokeEntry */
    g_templCmscbbX509RevokeEntry[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnBigint;
    g_templCmscbbX509RevokeEntry[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509RevokeEntry[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbX509RevokeAttrs;

    /* CmscbbX509Revoked */
    g_templCmscbbX509Revoked[0].asn1Item = &g_itemCmscbbX509RevokeEntry;

#if CMSCBB_SUPPORT_INDIRECT_CRL
    /* CmscbbX509IssuingDistPoint */
    g_templCmscbbX509IssuingDistPoint[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509IssuingDistPoint[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbAsnBool;
    g_templCmscbbX509IssuingDistPoint[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbAsnBool;
    g_templCmscbbX509IssuingDistPoint[CVB_ITEM_IDX3].asn1Item = &g_itemCmscbbAsnBits;
    g_templCmscbbX509IssuingDistPoint[CVB_ITEM_IDX4].asn1Item = &g_itemCmscbbAsnBool;
    g_templCmscbbX509IssuingDistPoint[CVB_ITEM_IDX5].asn1Item = &g_itemCmscbbAsnBool;

    /* CmscbbX509CrlAttrs */
    g_templCmscbbX509CrlAttrs[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbX509IssuingDistPoint;
#endif

    /* CmscbbX509CrlInfo */
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnInt;
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbX509AlgoIdentifier;
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbX509Name;
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX3].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX4].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX5].asn1Item = &g_itemCmscbbX509Revoked;
#if CMSCBB_SUPPORT_INDIRECT_CRL
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX6].asn1Item = &g_itemCmscbbX509CrlAttrs;
#else
    g_templCmscbbX509CrlInfo[CVB_ITEM_IDX6].asn1Item = &g_itemCmscbbAsnSeq;
#endif

    /* CmscbbX509Crl */
    g_templCmscbbX509Crl[CVB_ITEM_IDX0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbX509Crl[CVB_ITEM_IDX1].asn1Item = &g_itemCmscbbX509CrlInfo;
    g_templCmscbbX509Crl[CVB_ITEM_IDX2].asn1Item = &g_itemCmscbbX509AlgoIdentifier;
    g_templCmscbbX509Crl[CVB_ITEM_IDX3].asn1Item = &g_itemCmscbbAsnBits;
}

CVB_VOID CmscbbX509TemplInit(CVB_VOID)
{
    InternalCmscbbX509TemplInit1();
    InternalCmscbbX509TemplInit2();
    InternalCmscbbX509TemplInit3();
}
#endif
