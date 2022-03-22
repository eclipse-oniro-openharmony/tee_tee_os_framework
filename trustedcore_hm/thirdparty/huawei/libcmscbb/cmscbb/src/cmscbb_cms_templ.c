/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../cms/cmscbb_cms_templ.h"
#include "cmscbb_cms_def.h"
#include "../asn1/cmscbb_asn1_templ.h"

/* template for CmscbbPkcs7IssuerAndSerial */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbPkcs7IssuerAndSerial) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7IssuerAndSerial, CmscbbX509Name, issuer),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7IssuerAndSerial, CmscbbAsnBigint, sn),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbPkcs7IssuerAndSerial, g_cvbAsnFuncSeq, CBT_SEQUENCES);

#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
CVB_STATIC CmscbbAsn1Item g_itemCmscbbAttrBundleRaw = { CVB_NULL, &g_cvbAsnFuncOct, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_CONS, CBT_SETS, 0, sizeof(CmscbbAsnOcts) };

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509SignedAttrs) = {
    CMSCBB_ASN_MAP_ITEM(CmscbbX509SignedAttrs, CmscbbAsnOcts, hash_value, AOID_PKCS9_AT_MESSAGEDIGEST),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509SignedAttrs, g_cvbAsnFuncMap, CBT_SETS);
#endif

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509UnsignedAttrs) = {
    CMSCBB_ASN_MAP_FLAG_ITEM(CmscbbX509UnsignedAttrs, CmscbbAsnOcts, timestamp, CVB_ASN_RAW_DER, AOID_PKCS9_AT_TIMESTAMP_TOKEN),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbX509UnsignedAttrs, g_cvbAsnFuncMap, CBT_SETS);

/* template for CmscbbPkcs7SignedInfo */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbPkcs7SignedInfo) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7SignedInfo, CmscbbAsnInt, version),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7SignedInfo, CmscbbPkcs7IssuerAndSerial, issuerSn),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7SignedInfo, CmscbbX509AlgoIdentifier, digest_algo),
#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
    CMSCBB_ASN_IMPLICIT_PEEK_ITEM(CmscbbPkcs7SignedInfo, CmscbbAttrBundleRaw, rawSigned, 0),
    CMSCBB_ASN_IMPLICIT_ITEM(CmscbbPkcs7SignedInfo, CmscbbX509SignedAttrs, auth_attrs, 0),
#else
    CMSCBB_ASN_IGNORE_ITEM(CmscbbPkcs7SignedInfo, CmscbbAsnSet, CVB_ASN_OPTIONAL),
#endif
    CMSCBB_ASN_IGNORE_NORMAL_ITEM(CmscbbPkcs7SignedInfo, CmscbbAsnSeq),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7SignedInfo, CmscbbAsnOcts, encrypted_digest),
    CMSCBB_ASN_IMPLICIT_ITEM(CmscbbPkcs7SignedInfo, CmscbbX509UnsignedAttrs, unauth_attrs, 1),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbPkcs7SignedInfo, g_cvbAsnFuncSeq, CBT_SEQUENCES);

/* template for CmscbbPkcs7SignedInfoBundle */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbPkcs7SignedInfoBundle) = {
    CMSCBB_ASN_SET_ITEM(CmscbbPkcs7SignedInfoBundle, CmscbbPkcs7SignedInfo, infos, (CVB_VOID*)(CVB_ULONG)1),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbPkcs7SignedInfoBundle, g_cvbAsnFuncSetOf, CBT_SETS);

/* template for CmscbbPkcs7ContentInfo */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbPkcs7ContentInfo) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7ContentInfo, CmscbbAsnOcts, type),
    CMSCBB_ASN_OPTIONAL_ITEM(CmscbbPkcs7ContentInfo, CmscbbAsnOcts, content),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbPkcs7ContentInfo, g_cvbAsnFuncSeq, CBT_SEQUENCES);

#define MAX_SIGNED_DATA_COUNT 2
/* template for CmscbbPkcs7SignedData */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbX509CertRawBundle) = {
    CMSCBB_ASN_SET_ITEM_WITH_FLAG(CmscbbX509CertRawBundle, CVB_ASN_RAW_DER, CmscbbAsnOcts, bundle, (CVB_ULONG)MAX_SIGNED_DATA_COUNT),
}
CMSCBB_ASN_TEMPLATE_END_STATIC(CmscbbX509CertRawBundle, g_cvbAsnFuncSetOf, CBT_SEQUENCES);

CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbPkcs7SignedData) = {
    CMSCBB_ASN_OPTIONAL_ITEM(CmscbbPkcs7SignedData, CmscbbAsnInt, version),
    CMSCBB_ASN_IGNORE_NORMAL_ITEM(CmscbbPkcs7SignedData, CmscbbAsnSet),   /* digest_algo */
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7SignedData, CmscbbPkcs7ContentInfo, content),
    CMSCBB_ASN_IMPLICIT_ITEM(CmscbbPkcs7SignedData, CmscbbX509CertRawBundle, raw_certs, FIRST_TAG_NUM),
    CMSCBB_ASN_IGNORE_EX_ITEM(CmscbbTimestampInfo, CmscbbAsnSeq, CVB_ASN_OPTIONAL, CVB_ASN_IMPLICIT, SECOND_TAG_NUM),  /* crl */
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7SignedData, CmscbbPkcs7SignedInfoBundle, signer_infos),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbPkcs7SignedData, g_cvbAsnFuncSeq, CBT_SEQUENCES);

/* template for CmscbbPkcs7Content */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbPkcs7Content) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbPkcs7Content, CmscbbAsnOcts, content_type),
    CMSCBB_ASN_EXPLICIT_ITEM(CmscbbPkcs7Content, CmscbbPkcs7SignedData, signed_data, CVB_ASN_NORMAL, 0),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbPkcs7Content, g_cvbAsnFuncSeq, CBT_SEQUENCES);

/* template for CmscbbTsMsgImprint */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbTsMsgImprint) = {
    CMSCBB_ASN_NORMAL_ITEM(CmscbbTsMsgImprint, CmscbbX509AlgoIdentifier, hash_algo),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbTsMsgImprint, CmscbbAsnOcts, hash_value),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbTsMsgImprint, g_cvbAsnFuncSeq, CBT_SEQUENCES);

/* template for CmscbbTimestampInfo */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbTimestampInfo) = {
    CMSCBB_ASN_IGNORE_NORMAL_ITEM(CmscbbTimestampInfo, CmscbbAsnInt),
    CMSCBB_ASN_IGNORE_NORMAL_ITEM(CmscbbTimestampInfo, CmscbbAsnOcts),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbTimestampInfo, CmscbbTsMsgImprint, msg_imprint),
    CMSCBB_ASN_IGNORE_NORMAL_ITEM(CmscbbTimestampInfo, CmscbbAsnBigint),
    CMSCBB_ASN_NORMAL_ITEM(CmscbbTimestampInfo, CmscbbAsnOcts, time),
    CMSCBB_ASN_IGNORE_ITEM(CmscbbTimestampInfo, CmscbbAsnSeq, CVB_ASN_OPTIONAL), /* accuracy */
    CMSCBB_ASN_IGNORE_ITEM(CmscbbTimestampInfo, CmscbbAsnBool, CVB_ASN_OPTIONAL), /* ordering */
    CMSCBB_ASN_IGNORE_ITEM(CmscbbTimestampInfo, CmscbbAsnBigint, CVB_ASN_OPTIONAL), /* nonce */
    CMSCBB_ASN_IGNORE_EX_ITEM(CmscbbTimestampInfo, CmscbbAsnSeq, CVB_ASN_OPTIONAL, CVB_ASN_IMPLICIT, FIRST_TAG_NUM), /* issuer */
    CMSCBB_ASN_IGNORE_EX_ITEM(CmscbbTimestampInfo, CmscbbAsnSeq, CVB_ASN_OPTIONAL, CVB_ASN_IMPLICIT, SECOND_TAG_NUM), /* extensions */
}
CMSCBB_ASN_TEMPLATE_END(CmscbbTimestampInfo, g_cvbAsnFuncSeq, CBT_SEQUENCES);

#if CMSCBB_DELAY_ADDRESS_SET
CVB_VOID CmscbbCmsTemplInit(CVB_VOID)
{
    int i;
    /* CmscbbPkcs7IssuerAndSerial */
    g_templCmscbbPkcs7IssuerAndSerial[0].asn1Item = &g_itemCmscbbX509Name;
    g_templCmscbbPkcs7IssuerAndSerial[1].asn1Item = &g_itemCmscbbAsnBigint;

    /* CmscbbX509SignedAttrs */
    g_templCmscbbX509SignedAttrs[0].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbX509UnsignedAttrs */
    g_templCmscbbX509UnsignedAttrs[0].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbPkcs7SignedInfo */
    i = 0;
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbAsnInt;
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbPkcs7IssuerAndSerial;
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbX509AlgoIdentifier;
#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbAttrBundleRaw;
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbX509SignedAttrs;
#else
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbAsnSet;
#endif
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbAsnSeq;
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbPkcs7SignedInfo[i++].asn1Item = &g_itemCmscbbX509UnsignedAttrs;

    /* CmscbbPkcs7SignedInfoBundle */
    g_templCmscbbPkcs7SignedInfoBundle[0].asn1Item = &g_itemCmscbbPkcs7SignedInfo;

    /* CmscbbPkcs7ContentInfo */
    g_templCmscbbPkcs7ContentInfo[0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbPkcs7ContentInfo[1].asn1Item = &g_itemCmscbbAsnOcts;

    /* CmscbbX509CertRawBundle */
    g_templCmscbbX509CertRawBundle[0].asn1Item = &g_itemCmscbbAsnOcts;

    /* CMSCBB_PKCS7_SIGNED_DATA */
    i = 0;
    g_templCmscbbPkcs7SignedData[i++].asn1Item = &g_itemCmscbbAsnInt;
    g_templCmscbbPkcs7SignedData[i++].asn1Item = &g_itemCmscbbAsnSet;
    g_templCmscbbPkcs7SignedData[i++].asn1Item = &g_itemCmscbbPkcs7ContentInfo;
    g_templCmscbbPkcs7SignedData[i++].asn1Item = &g_itemCmscbbX509CertRawBundle;
    g_templCmscbbPkcs7SignedData[i++].asn1Item = &g_itemCmscbbAsnSeq;
    g_templCmscbbPkcs7SignedData[i++].asn1Item = &g_itemCmscbbPkcs7SignedInfoBundle;

    /* CmscbbPkcs7Content */
    g_templCmscbbPkcs7Content[0].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbPkcs7Content[1].asn1Item = &g_itemCmscbbPkcs7SignedData;

    /* CmscbbTsMsgImprint */
    g_templCmscbbTsMsgImprint[0].asn1Item = &g_itemCmscbbX509AlgoIdentifier;
    g_templCmscbbTsMsgImprint[1].asn1Item = &g_itemCmscbbAsnOcts;

    /* CMSCBB_TST_INFO */
    i = 0;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnInt;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbTsMsgImprint;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnBigint;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnOcts;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnSeq;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnBool;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnBigint;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnSeq;
    g_templCmscbbTimestampInfo[i++].asn1Item = &g_itemCmscbbAsnSeq;
}
#endif
