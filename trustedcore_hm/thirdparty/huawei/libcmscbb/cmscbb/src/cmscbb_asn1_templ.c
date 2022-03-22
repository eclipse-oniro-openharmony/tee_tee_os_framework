/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../asn1/cmscbb_asn1_templ.h"

/* defined CmscbbAsnOcts decode template */
CmscbbAsn1Item g_itemCmscbbAsnOcts = { CVB_NULL, &g_cvbAsnFuncOct, CMSCBB_RELOC_INIT_VAL CBC_ANY_CLASS, CBF_ANY_FORM, CBT_ANY_CODE, 0, sizeof(CmscbbAsnOcts) };

/* defined CmscbbAsnBigint decode template */
CmscbbAsn1Item g_itemCmscbbAsnBigint = { CVB_NULL, &g_cvbAsnFuncOct, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_PRIM, CBT_INTEGER, 0, sizeof(CmscbbAsnOcts) };

/* defined CmscbbAsnSeq decode template */
CmscbbAsn1Item g_itemCmscbbAsnSeq = { CVB_NULL, &g_cvbAsnFuncOct, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_CONS, CBT_SEQUENCES, 0, sizeof(CmscbbAsnOcts) };

/* defined CmscbbAsnSet decode template */
CmscbbAsn1Item g_itemCmscbbAsnSet = { CVB_NULL, &g_cvbAsnFuncOct, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_CONS, CBT_SETS, 0, sizeof(CmscbbAsnOcts) };

/* defined CmscbbAsnBits decode template */
CmscbbAsn1Item g_itemCmscbbAsnBits = { CVB_NULL, &g_cvbAsnFuncBits, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_PRIM, CBT_BITSTRING, 0, sizeof(CmscbbAsnBits) };

/* defined CmscbbAsnInt decode template */
CmscbbAsn1Item g_itemCmscbbAsnInt = { CVB_NULL, &g_cvbAsnFuncInt, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_PRIM, CBT_INTEGER, 0, sizeof(CmscbbAsnInt) };

/* defined CmscbbAsnEnum decode template */
CmscbbAsn1Item g_itemCmscbbAsnEnum = { CVB_NULL, &g_cvbAsnFuncInt, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_PRIM, CBT_ENUM, 0, sizeof(CmscbbAsnEnum) };

/* defined MSCBB_ASN_BOOL decode template */
CmscbbAsn1Item g_itemCmscbbAsnBool = { CVB_NULL, &g_cvbAsnFuncInt, CMSCBB_RELOC_INIT_VAL CBC_UNIV, CBF_PRIM, CBT_BOOLEAN, 0, sizeof(CmscbbAsnBool) };

#define MAX_OID_COUNT_IN_BUNDLE 10
/* template for CmscbbAsnOidBundle */
CMSCBB_ASN_TEMPLATE_BEGIN(CmscbbAsnOidBundle) = {
    CMSCBB_ASN_SET_ITEM(CmscbbAsnOidBundle, CmscbbAsnOcts, oid_bundle, (CVB_ULONG)MAX_OID_COUNT_IN_BUNDLE),
}
CMSCBB_ASN_TEMPLATE_END(CmscbbAsnOidBundle, g_cvbAsnFuncSetOf, CBT_SEQUENCES);

#if CMSCBB_DELAY_ADDRESS_SET
CVB_VOID CmscbbAsn1TemplInit(CVB_VOID)
{
    g_templCmscbbAsnOidBundle[0].asn1Item = &g_itemCmscbbAsnOcts;
    return;
}
#endif
