/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_ASN1_TEMPL_H
#define H_CMSCBB_ASN1_TEMPL_H
#include "../cmscbb_common/cmscbb_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CVB_ASN_NORMAL      0
#define CVB_ASN_OPTIONAL    1
#define CVB_ASN_PEEK        2
#define CVB_ASN_RAW_DER     4
#define CVB_ASN_SINK        8
#define CVB_ASN_DEFAULT     16
#define CVB_ASN_IGNORE      32


#define CVB_ASN_NO_TAGGING 0
#define CVB_ASN_EXPLICIT   1
#define CVB_ASN_IMPLICIT   2


struct cmscbb_asn1_template_st;
struct cmscbb_asn1Item_st;

typedef CVB_UINT32(*CVB_ASN_DECODE_ITEM)(CMSCBB_BUF* buf, CVB_VOID* result, CVB_UINT32* nDecoded, const struct cmscbb_asn1_template_st* pstTempl);

typedef struct cmscbb_asn1_template_st {
    struct cmscbb_asn1Item_st* asn1Item;
#if CMSCBB_RELOC_STRICT_CHECK
    CVB_UINT32 relocted;
#endif
    CVB_UINT32 tagCode;  /* only the code part of the tag */
    CVB_UINT16 tagType;  /* SEC_ASN_NO_TAGGING or SEC_ASN_EXPLICIT or SEC_ASN_IMPLICIT */
    CVB_UINT16 flag;     /* Normal | Optional | Default | ASN ANY | Pointer */
    CVB_UINT32 offset_val;  /* Pointer to the field that will be encoded / decoded */
#ifdef CVB_DEBUG
    const CVB_CHAR* name_val;
#endif
    /* CVB_UINT32 offset_type; */ /* OID or Int offset for ASN ANY templates */
    CVB_VOID* pDefaultVal;  /* To store the default values */
} CMSCBB_ASN1_TEMPLATE;

typedef struct cmscbb_asn1_any_map_st {
    CmscbbAsnInt iAnyId;
    CMSCBB_ASN1_TEMPLATE *pstAnyTempl;
} CMSCBB_ASN1_ANY_MAP;

typedef struct cmscbb_asn1_functions_st {
    CVB_ASN_DECODE_ITEM pDecode;
#if CMSCBB_RELOC_STRICT_CHECK
    CVB_UINT32 relocted;
#endif
} CMSCBB_ASN1_FUNCTIONS;

typedef struct cmscbb_asn1Item_st {
    struct cmscbb_asn1_template_st* asnTempl;
    CMSCBB_ASN1_FUNCTIONS* asn_func;
#if CMSCBB_RELOC_STRICT_CHECK
    CVB_UINT32 relocted;
#endif
    CMSCBB_BER_CLASS ber_class;
    CMSCBB_BER_FORM ber_form;
    CMSCBB_BER_TAG_CODE ber_code;
    CVB_UINT32 templ_count;
    CVB_UINT32 item_szie; /* if parent item is "sequence of", then this is for elements' size, not the list structure */
} CmscbbAsn1Item;

#ifdef __64BIT
#define STRUCT_OFFSET(structure, field) ((CVB_UINT32)(CVB_PTR)(&((structure*)(CVB_ULONG)0)->field))
#else
#define STRUCT_OFFSET(structure, field) ((CVB_UINT32)(CVB_PTR)(&((structure*)(CVB_ULONG)1)->field) - 1)
#endif


extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncOct;
extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncBits;
extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncSeq;
extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncInt;
extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncSetOf;
extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncMap;
extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncBitsToInt;
extern CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncExku;

extern CmscbbAsn1Item g_itemCmscbbAsnOcts;
extern CmscbbAsn1Item g_itemCmscbbAsnBits;
extern CmscbbAsn1Item g_itemCmscbbAsnInt;
extern CmscbbAsn1Item g_itemCmscbbAsnEnum;
extern CmscbbAsn1Item g_itemCmscbbAsnBigint;
extern CmscbbAsn1Item g_itemCmscbbAsnBool;
extern CmscbbAsn1Item g_itemCmscbbAsnSeq;
extern CmscbbAsn1Item g_itemCmscbbAsnSet;
extern CmscbbAsn1Item g_itemCmscbbAsnOidBundle;
extern CmscbbAsn1Item g_itemCmscbbAsnOctsBundle;

/* X509 templates */
extern CmscbbAsn1Item g_itemCmscbbX509AlgoIdentifier;
extern CmscbbAsn1Item g_itemCmscbbX509Name;
extern CmscbbAsn1Item g_itemCmscbbX509ExtensionEntry;
extern CmscbbAsn1Item g_itemCmscbbX509Cert;
extern CmscbbAsn1Item g_itemCmscbbX509Crl;
extern CmscbbAsn1Item g_itemCmscbbX509BasicConstraints;
#if CMSCBB_SUPPORT_INDIRECT_CRL
extern CmscbbAsn1Item g_itemCmscbbX509IssuingDistPoint;
#endif

#define CMSCBB_ASN_TEMPLATE_BEGIN(tname) CVB_STATIC CMSCBB_ASN1_TEMPLATE g_templ##tname[]
#define CMSCBB_ASN_ANY_MAP_BEGIN(tname) CVB_STATIC CMSCBB_ASN1_ANY_MAP g_anyMap##tname[]
#define CMSCBB_ASN_TEMPLATE_MAP_BEGIN(tname) CVB_STATIC CMSCBB_ASN1_ANY_MAP g_map##tname[]

#if CMSCBB_RELOC_STRICT_CHECK
#define CMSCBB_RELOC_INIT_VAL CVB_FALSE,
#else
#define CMSCBB_RELOC_INIT_VAL
#endif

#if CMSCBB_DELAY_ADDRESS_SET
#define CVB_NAME2ITEM(name) CVB_NULL
#else
#define CVB_NAME2ITEM(name) (&(g_item##name))
#endif

#ifdef CVB_DEBUG
#define CMSCBB_ASN_NORMAL_ITEM(tname, subtname, field) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_NORMAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_IMPLICIT_PEEK_ITEM(tname, subtname, field, tagCode) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagCode, CVB_ASN_IMPLICIT, CVB_ASN_PEEK | CVB_ASN_RAW_DER | CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_PEEK_ITEM(tname, field) { CVB_NAME2ITEM(CmscbbAsnOcts), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_PEEK | CVB_ASN_RAW_DER, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_SET_ITEM(tname, subtname, field, count) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_NORMAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, (CVB_VOID*)(count) }
#define CMSCBB_ASN_SET_ITEM_WITH_FLAG(tname, flag, subtname, field, count) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, flag, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, (CVB_VOID*)(count) }
#define CMSCBB_ASN_ITEM_WITH_FLAG(tname, flag, subtname, field) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, flag, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_OPTIONAL_ITEM(tname, subtname, field) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_IGNORE_ITEM(tname, subtname, flag) { CVB_NAME2ITEM(subtname), 0, CMSCBB_RELOC_INIT_VAL CVB_ASN_NO_TAGGING, CVB_ASN_IGNORE | (flag), CVB_NULL, "ignored", CVB_NULL }
#define CMSCBB_ASN_IGNORE_NORMAL_ITEM(tname, subtname) { CVB_NAME2ITEM(subtname), 0, CMSCBB_RELOC_INIT_VAL CVB_ASN_NO_TAGGING, CVB_ASN_IGNORE, CVB_NULL, "ignored", CVB_NULL }
#define CMSCBB_ASN_IGNORE_EX_ITEM(tname, subtname, flag, tag, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, tag, CVB_ASN_IGNORE | (flag), CVB_NULL, "ignored", CVB_NULL }
#define CMSCBB_ASN_DEFAULT_ITEM(tname, subtname, field, defaultvalue) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_DEFAULT, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, (CVB_VOID*)(defaultvalue) }
#define CMSCBB_ASN_IMPLICIT_ITEM(tname, subtname, field, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, CVB_ASN_IMPLICIT, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_IMPLICIT_ITEM_WITH_FLAG(tname, subtname, field, flag, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, CVB_ASN_IMPLICIT, flag, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_EXPLICIT_ITEM(tname, subtname, field, flag, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, CVB_ASN_EXPLICIT, flag, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_NORMAL_IMP_ITEM(tname, subtname, field, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, CVB_ASN_IMPLICIT, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_MAP_ITEM(tname, subtname, field, id) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL id, CVB_ASN_NO_TAGGING, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_MAP_FLAG_ITEM(tname, subtname, field, flag, id) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL id, CVB_ASN_NO_TAGGING, (flag) | CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field, CVB_NULL }
#define CMSCBB_ASN_MAP_KEY_ITEM() { CVB_NAME2ITEM(CmscbbAsnOid), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_MAP_KEY, CVB_NULL, "map key", CVB_NULL }
#define CMSCBB_ASN_MAP_VALUE_ITEM(tname, field) { CVB_NULL, CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_MAP_VALUE, (CVB_UINT32)STRUCT_OFFSET(tname, field), #field (CVB_VOID*)&(tname##_map) }
#else
#define CMSCBB_ASN_NORMAL_ITEM(tname, subtname, field) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_NORMAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_IMPLICIT_PEEK_ITEM(tname, subtname, field, tagCode) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagCode, CVB_ASN_IMPLICIT, CVB_ASN_PEEK | CVB_ASN_RAW_DER | CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_PEEK_ITEM(tname, field) { CVB_NAME2ITEM(CmscbbAsnOcts), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_PEEK | CVB_ASN_RAW_DER, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_SET_ITEM(tname, subtname, field, count) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_NORMAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), (CVB_VOID*)(count) }
#define CMSCBB_ASN_SET_ITEM_WITH_FLAG(tname, flag, subtname, field, count) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, flag, (CVB_UINT32)STRUCT_OFFSET(tname, field), (CVB_VOID*)(count) }
#define CMSCBB_ASN_ITEM_WITH_FLAG(tname, flag, subtname, field) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, flag, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_OPTIONAL_ITEM(tname, subtname, field) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_IGNORE_ITEM(tname, subtname, flag) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_IGNORE | (flag), CVB_NULL, CVB_NULL }
#define CMSCBB_ASN_IGNORE_NORMAL_ITEM(tname, subtname) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_IGNORE, CVB_NULL, CVB_NULL }
#define CMSCBB_ASN_IGNORE_EX_ITEM(tname, subtname, flag, tag, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, tag, CVB_ASN_IGNORE | (flag), CVB_NULL, CVB_NULL }
#define CMSCBB_ASN_DEFAULT_ITEM(tname, subtname, field, defaultvalue) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_DEFAULT, (CVB_UINT32)STRUCT_OFFSET(tname, field), (CVB_VOID*)(defaultvalue) }
#define CMSCBB_ASN_IMPLICIT_ITEM(tname, subtname, field, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, CVB_ASN_IMPLICIT, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_EXPLICIT_ITEM(tname, subtname, field, flag, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, CVB_ASN_EXPLICIT, flag, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_NORMAL_IMP_ITEM(tname, subtname, field, tagnum) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL tagnum, CVB_ASN_IMPLICIT, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_MAP_ITEM(tname, subtname, field, id) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL id, CVB_ASN_NO_TAGGING, CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_MAP_FLAG_ITEM(tname, subtname, field, flag, id) { CVB_NAME2ITEM(subtname), CMSCBB_RELOC_INIT_VAL id, CVB_ASN_NO_TAGGING, (flag) | CVB_ASN_OPTIONAL, (CVB_UINT32)STRUCT_OFFSET(tname, field), CVB_NULL }
#define CMSCBB_ASN_MAP_KEY_ITEM() { CVB_NAME2ITEM(CmscbbAsnOid), CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_MAP_KEY, CVB_NULL, CVB_NULL }
#define CMSCBB_ASN_MAP_VALUE_ITEM(tname, field) { CVB_NULL, CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_MAP_VALUE, (CVB_UINT32)STRUCT_OFFSET(tname, field), (CVB_VOID*)&(tname##_map) }
#endif

#define CMSCBB_ASN_TEMPLATE_END(tname, cb, tagcode) ;\
    CmscbbAsn1Item g_item##tname = { g_templ##tname, &(cb), CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_CONS, tagcode, sizeof(g_templ##tname) / sizeof(CMSCBB_ASN1_TEMPLATE), sizeof(tname) }

#define CMSCBB_ASN_TEMPLATE_END_STATIC(tname, cb, tagcode) ;\
    CVB_STATIC CmscbbAsn1Item g_item##tname = { g_templ##tname, &(cb), CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_CONS, tagcode, sizeof(g_templ##tname) / sizeof(CMSCBB_ASN1_TEMPLATE), sizeof(tname) }

/* Implemented in CMSCBB_CMS_TEMPL.C */
extern CmscbbAsn1Item g_itemCmscbbPkcs7Content;
extern CmscbbAsn1Item g_itemCmscbbTimestampInfo;

#if CMSCBB_DELAY_ADDRESS_SET
CVB_VOID CmscbbAsn1TemplInit(CVB_VOID);
CVB_VOID CmscbbCmsTemplInit(CVB_VOID);
CVB_VOID CmscbbX509TemplInit(CVB_VOID);
#endif

#ifdef __cplusplus
}
#endif


#endif /* H_CMSCBB_ASN1_TEMPL_H */
