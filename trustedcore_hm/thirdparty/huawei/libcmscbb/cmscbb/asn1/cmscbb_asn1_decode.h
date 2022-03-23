/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_ASN1_DECODE_H
#define H_CMSCBB_ASN1_DECODE_H
#include "../asn1/cmscbb_asn1_templ.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Prototype    : RelocateTemplate
 * Description  : Address of static pointer in redirect template
 * Params
 *   [IN] asn1Item: asn1 object
 *   [IN] reloc_off: reset loaction offset
 * Return Value : None
 *   Date              Author     Modification
 *   2016/08/03 13:36  t00307193  Create
 */
CVB_VOID RelocateTemplate(CmscbbAsn1Item* asn1Item, CVB_ULONG reloc_off);

/*
 * Prototype    : CmscbbAsnDecode
 * Description  : decode a DER encoded asn item
 * Return Value : CMSCBB_ERROR_CODE 
 *   Date              Author     Modification
 *   2015/11/11 9:55  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbAsnDecode(const CVB_BYTE* pbBuf, CVB_UINT32 nBufLen, struct cmscbb_asn1Item_st* pAsnItem, CVB_BYTE flag, CVB_VOID** ppResult, CVB_UINT32* nDecoded);

/*
 * Prototype    : CmscbbAsnFree
 * Description  : free asn item
 * Return Value : None
 *   Date              Author     Modification
 *   2015/11/11 9:55  t00307193  Create
 */
CVB_VOID CmscbbAsnFree(CVB_VOID* pObj, const struct cmscbb_asn1Item_st* pAsnItem, CVB_BYTE flag);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* H_CMSCBB_ASN1_DECODE_H */
