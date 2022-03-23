/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../asn1/cmscbb_asn1_decode.h"
#include "../asn1/cmscbb_asn1_utils.h"

#define CMSCBB_ASN_XKU_CODE_SIGN  0x08  /* same as CMSCBB_PKI_XKU_CODE_SIGN */
#define CMSCBB_ASN_XKU_TIMESTAMP  0x40  /* same as CMSCBB_PKI_XKU_TIMESTAMP */

CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeOctet(CMSCBB_BUF *b, CVB_VOID *v,
    CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE *pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeBits(CMSCBB_BUF *b, CVB_VOID *v,
    CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE CmscbbBitsToInt(CMSCBB_BUF *b, CVB_VOID *v,
    CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE CmscbbOidToExku(CMSCBB_BUF *b, CVB_VOID *v,
    CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeSeq(CMSCBB_BUF* b, CVB_VOID* v,
    CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeInt(CMSCBB_BUF* b, CVB_VOID* v,
    CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeSetof(CMSCBB_BUF* b, CVB_VOID* v,
    CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeMap(CMSCBB_BUF* b, CVB_VOID* v,
    CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl);
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckTag(
    const CMSCBB_ASN1_TEMPLATE* pAsnTempl, const CMSCBB_BER_TAG* pTag);

#if CMSCBB_RELOC_STRICT_CHECK
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncOct = { CmscbbDecodeOctet, CVB_FALSE };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncBits = { CmscbbDecodeBits, CVB_FALSE };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncSeq = { CmscbbDecodeSeq, CVB_FALSE };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncInt = { CmscbbDecodeInt, CVB_FALSE };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncSetOf = { CmscbbDecodeSetof, CVB_FALSE };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncMap = { CmscbbDecodeMap, CVB_FALSE };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncBitsToInt = { CmscbbBitsToInt, CVB_FALSE };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncExku = { CmscbbOidToExku, CVB_FALSE };
#else
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncOct = { CmscbbDecodeOctet };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncBits = { CmscbbDecodeBits };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncSeq = { CmscbbDecodeSeq };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncInt = { CmscbbDecodeInt };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncSetOf = { CmscbbDecodeSetof };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncMap = { CmscbbDecodeMap };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncBitsToInt = { CmscbbBitsToInt };
CMSCBB_ASN1_FUNCTIONS g_cvbAsnFuncExku = { CmscbbOidToExku };
#endif


#define CVB_BUF_REVERT_CURSOR(buf, cur) ((buf)->iCursor = (cur))
#define CVB_BUF_GET_CURSOR(buf, cur) ((cur) = (buf)->iCursor)
#define CVB_BUF_GET_OFFSET(buf, cur) ((buf)->iCursor - (cur))
#define CVB_BUF_GET_POINT(buf) (const CVB_BYTE*)((buf)->pVal + (buf)->iCursor)

#define CVB_IS_IGNORE_TEMPL(tmpl) (((tmpl) != CVB_NULL) && (CVB_ASN_IGNORE & (tmpl)->flag))

#define ASN_LONG_LENTH_COUNT 2
#define SIGN_BIT_MASK 0x80

#if CMSCBB_NEED_RELOCATE
#if CMSCBB_RELOC_STRICT_CHECK
CVB_VOID RelocateTemplate(CmscbbAsn1Item* asn1Item, CVB_ULONG reloc_off)
{
    int iter;

    if (reloc_off == 0) {
        return;
    }

    if (asn1Item == CVB_NULL) {
        return;
    }

    /* Check if the address has been converted */
    if (asn1Item->relocted == CVB_TRUE) {
        return;
    }

    /* Convert analytic function address */
    if (asn1Item->asn_func != CVB_NULL) {
        asn1Item->asn_func = (CMSCBB_ASN1_FUNCTIONS*)((CVB_ULONG)(asn1Item->asn_func) + reloc_off);
        if (asn1Item->asn_func->pDecode != CVB_NULL && asn1Item->asn_func->relocted == CVB_FALSE) {
            asn1Item->asn_func->pDecode = (CVB_ASN_DECODE_ITEM)(
                (CVB_ULONG)(asn1Item->asn_func->pDecode) + reloc_off);
            asn1Item->asn_func->relocted = CVB_TRUE;
        }
    }

    if (asn1Item->asnTempl != CVB_NULL) {
        /* Convert template Address */
        asn1Item->asnTempl = (CMSCBB_ASN1_TEMPLATE*)((CVB_ULONG)(asn1Item->asnTempl) + reloc_off);

        /* Recursive call to address translation functions to transform the domain of a child template */
        for (iter = 0; iter < (int)asn1Item->templ_count; ++iter) {
            CMSCBB_ASN1_TEMPLATE* pTempl = asn1Item->asnTempl + iter;
            if (pTempl == CVB_NULL) {
                continue;
            }

            if (pTempl->asn1Item && CVB_FALSE == (pTempl->relocted != CVB_NULL)) {
                pTempl->asn1Item = (CmscbbAsn1Item*)((CVB_ULONG)(pTempl->asn1Item) + reloc_off);
                pTempl->relocted = CVB_TRUE;
            }
            /* The template that pTempl->asn1Item points to is not necessarily redirected even if pTempl->asn1Item has been redirected */
            RelocateTemplate(pTempl->asn1Item, reloc_off);
        }
    }
    asn1Item->relocted = CVB_TRUE;
}
#else
CVB_VOID RelocateTemplate(CmscbbAsn1Item* asn1Item, CVB_ULONG reloc_off)
{
    int iter;
    CMSCBB_ASN1_TEMPLATE* pTempl = CVB_NULL;

    if (asn1Item == CVB_NULL) {
        return;
    }

    if (reloc_off == 0) {
        return;
    }

    /* Check if the address has been converted */
    if ((CVB_ULONG)asn1Item->asn_func > reloc_off) {
        return;
    }

    /* Convert analytic function address */
    if (asn1Item->asn_func != CVB_NULL) {
        asn1Item->asn_func = (CMSCBB_ASN1_FUNCTIONS*)((CVB_ULONG)(asn1Item->asn_func) + reloc_off);
        if (asn1Item->asn_func->pDecode != CVB_NULL && (CVB_ULONG)(asn1Item->asn_func->pDecode) < reloc_off) {
            asn1Item->asn_func->pDecode = (CVB_ASN_DECODE_ITEM)((CVB_ULONG)(asn1Item->asn_func->pDecode) + reloc_off);
        }
    }

    if (asn1Item->asnTempl != CVB_NULL) {
        /* Convert template Address */
        asn1Item->asnTempl = (CMSCBB_ASN1_TEMPLATE*)((CVB_ULONG)(asn1Item->asnTempl) + reloc_off);

        /* Recursive call to address translation functions to transform the domain of a child template */
        for (iter = 0; iter < asn1Item->templ_count; ++iter) {
            pTempl = asn1Item->asnTempl + iter;
            if (pTempl == CVB_NULL) {
                continue;
            }

            if (pTempl->asn1Item != CVB_NULL && (CVB_ULONG)(pTempl->asn1Item) < reloc_off) {
                pTempl->asn1Item = (CmscbbAsn1Item*)((CVB_ULONG)(pTempl->asn1Item) + reloc_off);
            }
            /* The template that Ptempl->asn1Item points to is not necessarily redirected even if Ptempl->asn1Item has been redirected */
            RelocateTemplate(pTempl->asn1Item, reloc_off);
        }
    }
}
#endif
#endif

/*
 * Prototype    : cmscbb_dec_tag
 * Description  : decode asn1 element tag
 * Params
 *   [IN] b: DER data stream
 *   [OUT] pTag: tag
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:02  t00307193  Create
 */
#define CLASS_BIT_POS 6
CVB_STATIC CMSCBB_ERROR_CODE InternalDecTag(CMSCBB_BUF* b, CMSCBB_BER_TAG* pTag)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BYTE szTag = 0;

    ret = CmscbbBufGet(b, &szTag);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    CMSCBB_MAKE_TAG(*pTag, (szTag & CMSCBB_TAG_CLASS_MASK) >> CLASS_BIT_POS, (szTag & CMSCBB_TAG_PC_MASK) != 0 ? CBF_CONS : CBF_PRIM,
                    szTag & CMSCBB_TAG_CODE_MASK);

    /* long form tag, not supported */
    if ((CVB_INT)pTag->code == CMSCBB_TAG_CODE_MASK) {
        CVB_LOG_DEBUG(CMSCBB_ERR_ASN1_TAG_DEC, CVB_NULL);
        return (CMSCBB_ERR_ASN1_TAG_DEC);
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalDecLen
 * Description  : decode asn1 element length
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DER data stream
 *   [OUT] nLength: length
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecLen(CMSCBB_BUF* b, CVB_UINT32* nLength)
{
    CMSCBB_ERROR_CODE ret;
    CVB_BYTE szLen = 0;
    CVB_UINT32 nLen;
    CVB_UINT32 lenTemp = 0;

    ret = CmscbbBufGet(b, &szLen);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* Check length type */
    nLen = (CVB_UINT32)(szLen & CMSCBB_LEN_MASK);

    /* Short length, less than 128 bytes */
    if (nLen == (CVB_UINT32)szLen) {
        lenTemp = (CVB_UINT32)nLen;
    } else if (nLen == 0 /* indefinite length */
        || nLen > sizeof(CVB_UINT)) {
        CVB_LOG_WARNING(0, "indefinit length not supported.");
        return CMSCBB_ERR_ASN1_LEN_DEC;
    } else {
        /* Long length, greater than 128 bytes */
        CVB_UINT i;
        for (i = 0; i < nLen; ++i) {
            ret = CmscbbBufGet(b, &szLen);
            if (CVB_FAILED(ret)) {
                CVB_LOG_DEBUG(ret, CVB_NULL);
                return ret;
            }
            lenTemp = (lenTemp << BIT_COUNT_OF_BYTE) + szLen;
        }
    }

    /* check if length overflow */
    if (lenTemp > (b->nBufLen - b->iCursor)) {
        CVB_LOG_ERROR(0, "overflow length.");
        return CMSCBB_ERR_ASN1_LEN_DEC;
    }

    *nLength = lenTemp;
    return CVB_SUCCESS;
}

/*
 * Prototype    : _cvb_check_tag
 * Description  : Check DER tag
 * Params
 *   [IN] pAsnTempl: ASN1 parsing Template
 *   [IN] tagReal: tag
 * Return Value : CVB_SUCCESS if match
 *   Date              Author     Modification
 *   2015/11/11 12:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalCheckTag(const CMSCBB_ASN1_TEMPLATE* pAsnTempl, const CMSCBB_BER_TAG* tagReal)
{
    CmscbbAsn1Item* pAsnItem;
    CMSCBB_BER_TAG tagExp = CVB_BER_TAG_INIT;

    pAsnItem = pAsnTempl->asn1Item;
    if (pAsnTempl->tagType == CVB_ASN_IMPLICIT) {
        CMSCBB_MAKE_TAG(tagExp, CBC_CNTX, pAsnItem->ber_form, pAsnTempl->tagCode);
    } else {
        CMSCBB_MAKE_TAG(tagExp, pAsnItem->ber_class, pAsnItem->ber_form, pAsnItem->ber_code);
    }

    if ((tagExp.cls != CBC_ANY_CLASS && tagExp.cls != tagReal->cls)
            || (tagExp.form != CBF_ANY_FORM && tagExp.form != tagReal->form)
            || (tagExp.code != CBT_ANY_CODE && tagExp.code != tagReal->code)) {
        CVB_LOG_INFO(CMSCBB_ERR_ASN1_TAG_CHECK, "tag not match");
        return CMSCBB_ERR_ASN1_TAG_CHECK;
    }
    return CVB_SUCCESS;
}

CVB_STATIC CVB_BOOL InternalHasOct(CVB_UINT32 berLen, const CmscbbAsnOcts* pAsnOcts)
{
    if (berLen == 0 && pAsnOcts != CVB_NULL) {
        return CVB_TRUE;
    }
    return CVB_FALSE;
}

CVB_STATIC CVB_BOOL InternalIsDerRawTemplFlag(const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    if (pstTempl != CVB_NULL && (CVB_ASN_RAW_DER & pstTempl->flag)) {
        return CVB_TRUE;
    }
    return CVB_FALSE;
}

/*
 * Prototype    : InternalDecodeOctet
 * Description  : Gets the length and content of the Octet element
 * Params
 *   [IN] b: buffer
 *   [IN] pstTempl:  Templates for parsing 
 *   [IN] cur0: buffer cursor
 *   [IN] tag: tag
 *   [IN] pAsnOcts: asn object
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2016/08/10 11:50  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecodeOctet(CMSCBB_BUF* b, CVB_UINT32 cur0, const CMSCBB_ASN1_TEMPLATE* pstTempl, CMSCBB_BER_TAG tag, CmscbbAsnOcts* pAsnOcts)
{
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 berLen = 0;

    ret = InternalDecLen(b, &berLen);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    if (InternalHasOct(berLen, pAsnOcts)) {
        /* cp-if the pasnocts has been initialized, you don't have to call it. */
        if (pAsnOcts != NULL) {
            pAsnOcts->octs = CVB_NULL;
        }
        return CVB_SUCCESS;
    }

    /* The cvb_asn_raw_der identifier means that the full ASN1 encoding data is saved and the data is deferred for resolution, so tag and length are required */
    if (InternalIsDerRawTemplFlag(pstTempl)) {
        CVB_UINT32 tagLen = CVB_BUF_GET_OFFSET(b, cur0);

        berLen += tagLen;
        CVB_BUF_REVERT_CURSOR(b, cur0);
    } else {
        if (tag.code == CBT_INTEGER) {
            /* Remove first sign bit */
            if (berLen > 0 && 0 == b->pVal[b->iCursor]) {
                berLen -= 1;
                ++(b->iCursor);
            }
        }
    }

    if (pAsnOcts != NULL) {
        pAsnOcts->octs = CVB_BUF_GET_POINT(b);
        pAsnOcts->len = berLen;
        pAsnOcts->tag.cls = tag.cls;
        pAsnOcts->tag.code = tag.code;
        pAsnOcts->tag.form = tag.form;
    }
    ret = CmscbbBufSeek(b, (CVB_INT32)berLen, CBSW_CURRENT);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : CmscbbDecodeOctet
 * Description  : decode DER to CmscbbAsnOcts
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN, OUT] v: Memory address to receive cmscbb_asn_octs data
 *   [IN] bytesDecoded: Parse the number of bytes consumed
 *   [IN] pstTempl: Parse the template used
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:04  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeOctet(CMSCBB_BUF *b, CVB_VOID *v, CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE *pstTempl)
{
    CVB_UINT32 cur0;
    CMSCBB_BER_TAG tag = CVB_BER_TAG_INIT;
    CmscbbAsnOcts* pAsnOcts = CVB_NULL;
    CMSCBB_ERROR_CODE ret;

    /* Parameter check */
    if (bytesDecoded == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    if (!CVB_IS_IGNORE_TEMPL(pstTempl)) {
        if (v == CVB_NULL) {
            CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
            return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
        }
        pAsnOcts = (CmscbbAsnOcts*)v;
    }

    /* Locate the current data flow read pointer */
    CVB_BUF_GET_CURSOR(b, cur0);

    ret = InternalDecTag(b, &tag);
    CVB_GOTO_ERR_IF_FAIL(ret);

    /* Incoming templates are not empty and will continue to be parsed according to the template, and if empty, the bare data will be saved directly */
    if ((pstTempl != CVB_NULL) && (pstTempl->asn1Item != CVB_NULL)) {
        ret = InternalCheckTag(pstTempl, &tag);
        CVB_GOTO_ERR_IF_FAIL(ret);
    }

    ret = InternalDecodeOctet(b, cur0, pstTempl, tag, pAsnOcts);
    CVB_GOTO_ERR_IF_FAIL(ret);

    /* A fallback read pointer is required if the template's identifier contains Cvb_asn_peek */
    if ((pstTempl != CVB_NULL) && (CVB_ASN_PEEK & pstTempl->flag)) {
        CVB_BUF_REVERT_CURSOR(b, cur0);
        *bytesDecoded = 0;
#if CMSCBB_SUPPORT_SIGNED_ATTRIBUTE
        CVB_GOTO_ERR_IF(CVB_NULL == pAsnOcts, CMSCBB_ERR_ASN1_OCT_PEEK);
        /* The tag type of the cvb_asn_implicit needs to modify its own tag value to the value specified by the child template */
        if (CVB_ASN_IMPLICIT & pstTempl->tagType) {
            CmscbbAsn1Item* pAsnRefItem = pstTempl->asn1Item;
            CVB_GOTO_ERR_IF(CVB_NULL == pAsnRefItem, CMSCBB_ERR_ASN1_OCT_PEEK);

            CMSCBB_MAKE_TAG(pAsnOcts->tag, pAsnRefItem->ber_class, pAsnRefItem->ber_form, pAsnRefItem->ber_code);
        }
#endif
    } else {
        *bytesDecoded = CVB_BUF_GET_OFFSET(b, cur0);
    }

    goto CVB_FINAL;
CVB_ERR:
    CVB_BUF_REVERT_CURSOR(b, cur0);
CVB_FINAL:
    return ret;
}

/*
 * Prototype    : InternalDecSeqValue
 * Description  : decode asn1 sequence item
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN, OUT] v: Save the memory address of the resolved result
 *   [IN] pstInternalTempl: Templates for parsing
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalDecSeqValue(CMSCBB_BUF* b, const CVB_VOID* v, const CMSCBB_ASN1_TEMPLATE* pstInternalTempl)
{
    CMSCBB_ERROR_CODE ret = 0;
    CVB_UINT32 nDecoded = 0;
    CVB_VOID* pFieldValue = CVB_NULL;
    CVB_UINT32 cur0;

    CVB_BUF_GET_CURSOR(b, cur0);

    /* If the tag type is cvb_asn_explicit, you need to peel a layer of tag and length and check the tag value */
    if (pstInternalTempl->tagType == CVB_ASN_EXPLICIT) {
        CVB_UINT32 nElementLen = 0;
        CMSCBB_BER_TAG tagReal = CVB_BER_TAG_INIT;
        CMSCBB_BER_TAG tagInternal = { CBC_CNTX, CBF_CONS, CBT_EOC };

        tagInternal.code = (CMSCBB_BER_TAG_CODE)pstInternalTempl->tagCode;

        ret = InternalDecTag(b, &tagReal);
        CVB_GOTO_ERR_IF_FAIL(ret);

        CVB_GOTO_ERR_IF(CmscbbMemCmp(&tagReal, &tagInternal, sizeof(CMSCBB_BER_TAG)) != 0, CMSCBB_ERR_ASN1_SEQ_DEC);

        ret = InternalDecLen(b, &nElementLen);
        CVB_GOTO_ERR_IF_FAIL(ret);
    }

    CVB_GOTO_ERR_IF(CVB_NULL == pstInternalTempl->asn1Item->asn_func->pDecode, CMSCBB_ERR_ASN1_SEQ_DEC);

    /* Find the memory address of the resolved result by offset */
    pFieldValue = (CVB_NULL == v) ? CVB_NULL : (CVB_VOID*)((CVB_PTR)v + pstInternalTempl->offset_val);
    ret = pstInternalTempl->asn1Item->asn_func->pDecode(b, pFieldValue, &nDecoded, pstInternalTempl);
    CVB_GOTO_ERR_IF_FAIL(ret);

    goto CVB_FINAL;
CVB_ERR:
    /* Ignore error if flag indicates this field is optional */
    if (pstInternalTempl->flag & (CVB_ASN_OPTIONAL | CVB_ASN_DEFAULT)) {
        CVB_BUF_REVERT_CURSOR(b, cur0);
        ret = CVB_SUCCESS;
    }
CVB_FINAL:
    return ret;
}

/*
 * Prototype    : InternalSeqCheckRemainOptional
 * Description  : check if there's any unfinished item, which is not optional
 * Params
 *   [IN] pstCheckTempl: The current template
 *   [IN] remainTempl: Remaining templates
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalSeqCheckRemainOptional(const CMSCBB_ASN1_TEMPLATE* pstCheckTempl, CVB_UINT32 remainTempl)
{
    CVB_UINT32 remainNum = remainTempl;

    while (remainNum > 0) {
        if ((pstCheckTempl->flag & (CVB_ASN_OPTIONAL | CVB_ASN_DEFAULT)) == 0) {
            return CMSCBB_ERR_ASN1_SEQ_DEC;
        }
        ++pstCheckTempl;
        --remainNum;
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : InternalAsn1ParseContent
 * Description  : decode DER tag, length and value
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN] pstTempl: Templates for parsing
 *   [IN] tagForm: Target form Value
 *   [IN] tagCode: Target Code value
 *   [OUT] nElemLen: Returns the length of the ASN1 element
 *   [OUT] tagReal: Returns the TAG of the ASN1 element
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE InternalAsn1ParseContent(CMSCBB_BUF *b, const CMSCBB_ASN1_TEMPLATE* pstTempl, CMSCBB_BER_FORM tagForm, CMSCBB_BER_TAG_CODE tagCode, CVB_UINT32 *nElemLen, CMSCBB_BER_TAG* tagReal)
{
    CMSCBB_ERROR_CODE ret;

    CMSCBB_BER_TAG tagExp = CVB_BER_TAG_INIT;
    if (pstTempl->tagType & CVB_ASN_IMPLICIT) {
        CMSCBB_MAKE_TAG(tagExp, CBC_CNTX, tagForm, pstTempl->tagCode);
    } else {
        CMSCBB_MAKE_TAG(tagExp, CBC_UNIV, tagForm, tagCode);
    }

    ret = InternalDecTag(b, tagReal);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* Check that the parsed tag value matches the expected */
    if (CmscbbMemCmp(&tagExp, tagReal, sizeof(CMSCBB_BER_TAG)) != 0) {
        return CMSCBB_ERR_ASN1_TAG_DEC;
    }

    ret = InternalDecLen(b, nElemLen);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    return CVB_SUCCESS;
}

CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParmDecSeq(CMSCBB_BUF* b, CVB_VOID* v, CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    if (!b || !v || !bytesDecoded || !pstTempl) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : CmscbbDecodeSeq
 * Description  : decode DER sequence
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN, OUT] v: Memory address that holds the result of the resolution
 *   [OUT] bytesDecoded: Parse the number of bytes consumed
 *   [IN] pstTempl: Templates for parsing
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeSeq(CMSCBB_BUF* b, CVB_VOID* v, CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 cur0;
    CVB_UINT32 curContent = 0;
    CmscbbAsn1Item* pAsnItem = CVB_NULL;
    CVB_UINT32 nContentLen = 0;
    CVB_UINT32 nTotalElementLen = 0;
    CMSCBB_ASN1_TEMPLATE* pstInternalTempl = CVB_NULL;
    CVB_UINT32 iter;
    CMSCBB_BER_TAG tagReal = CVB_BER_TAG_INIT;

    ret = InternalCheckParmDecSeq(b, v, bytesDecoded, pstTempl);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* Save the initial buffer read pointer */
    CVB_BUF_GET_CURSOR(b, cur0);

    pAsnItem = pstTempl->asn1Item;

    ret = InternalAsn1ParseContent(b, pstTempl, pAsnItem->ber_code == CBT_BITSTRING ? CBF_PRIM : CBF_CONS, (CMSCBB_BER_TAG_CODE)pAsnItem->ber_code, &nContentLen, &tagReal);
    CVB_GOTO_ERR_IF_FAIL(ret);

    /* Bit string type skips a unused bits byte */
    if (pAsnItem->ber_code == CBT_BITSTRING) {
        (CVB_VOID)CmscbbBufSeek(b, 1, CBSW_CURRENT);
        --nContentLen;
    }

    CVB_BUF_GET_CURSOR(b, curContent);

    for (pstInternalTempl = pAsnItem->asnTempl, iter = 0; iter < pAsnItem->templ_count; ++pstInternalTempl, ++iter) {
#ifdef CVB_DEBUG
        if (pstInternalTempl->name_val) {
            CVB_LOG_DEBUG1(0, "Decode sequence field: %s", pstInternalTempl->name_val);
        }
#endif

        /* no element data left, so check the rest of template item should be optional */
        if (nTotalElementLen == nContentLen) {
            ret = InternalSeqCheckRemainOptional(pstInternalTempl, pAsnItem->templ_count - iter);
            CVB_GOTO_ERR_IF_FAIL(ret);

            break;
        } else {
            CVB_GOTO_ERR_IF(nTotalElementLen >= nContentLen, CMSCBB_ERR_ASN1_SEQ_DEC);
        }

        ret = InternalDecSeqValue(b, (CVB_ASN_IGNORE & pstInternalTempl->flag) ? CVB_NULL : v, pstInternalTempl);
        CVB_GOTO_ERR_IF_FAIL(ret);

        nTotalElementLen = CVB_BUF_GET_OFFSET(b, curContent);
    }

    /* compare parent length field with total decoded length of all elements */
    CVB_GOTO_ERR_IF(nTotalElementLen != nContentLen, CMSCBB_ERR_ASN1_SEQ_DEC);

    *bytesDecoded = CVB_BUF_GET_OFFSET(b, cur0);
    goto CVB_FINAL;

CVB_ERR:
    CVB_BUF_REVERT_CURSOR(b, cur0);
CVB_FINAL:
    return ret;
}

/*
 * Prototype    : CmscbbDecodeBits
 * Description  : decode DER bits
 * Params
 *   [IN] b: buffer
 *   [IN] v: asn bits
 *   [OUT] bytesDecoded: result of decoded
 *   [IN] pstTempl:  Templates for parsing
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE   Author     Modification
 *   2015/11/11 12:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeBits(CMSCBB_BUF *b, CVB_VOID *v, CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    CMSCBB_ERROR_CODE ret;
    CMSCBB_BER_TAG tagReal = CVB_BER_TAG_INIT;
    CVB_UINT32 cur0;
    CVB_UINT32 nElemLen = 0;
    CmscbbAsnBits* pAsnBits = CVB_NULL;
    CVB_BYTE nUnusedBits = 0;

    if (bytesDecoded == CVB_NULL || pstTempl == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    CVB_BUF_GET_CURSOR(b, cur0);

    ret = InternalAsn1ParseContent(b, pstTempl, CBF_PRIM, CBT_BITSTRING, &nElemLen, &tagReal);
    CVB_GOTO_ERR_IF_FAIL(ret);

    CVB_GOTO_ERR_IF(0 == nElemLen ||
        CBF_CONS == tagReal.form, CMSCBB_ERR_ASN1_BITS_DEC); /* constructed bit string not supported, although it's legal */
                    
    if (!(CVB_ASN_IGNORE & pstTempl->flag)) {
        pAsnBits = (CmscbbAsnBits*)v;
        CVB_GOTO_ERR_IF(pAsnBits == CVB_NULL, CMSCBB_ERR_ASN1_BITS_DEC);

        pAsnBits->tag.cls = tagReal.cls;
        pAsnBits->tag.code = tagReal.code;
        pAsnBits->tag.form = tagReal.form;

        /* get unused bits count */
        ret = CmscbbBufGet(b, &nUnusedBits);
        CVB_GOTO_ERR_IF_FAIL(ret);

        --nElemLen;

        pAsnBits->len = nElemLen;

        pAsnBits->octs = CVB_BUF_GET_POINT(b);
    }

    ret = CmscbbBufSeek(b, (CVB_INT32)nElemLen, CBSW_CURRENT);
    CVB_GOTO_ERR_IF_FAIL(ret);

    *bytesDecoded = CVB_BUF_GET_OFFSET(b, cur0);

    goto CVB_FINAL;
CVB_ERR:
    CVB_BUF_REVERT_CURSOR(b, cur0);
CVB_FINAL:
    return ret;
}

/*
 * Prototype    : CmscbbBitsToInt
 * Description  : asn1 bits to integer converter
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN, OUT] v: memory address in which the result is parsed
 *   [IN] bytesDecoded: Resolution of bytes consumed
 *   [IN] pstTempl: Parsing templates
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2016/01/08 14:14  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbBitsToInt(CMSCBB_BUF *b, CVB_VOID *v, CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbAsnBits asnBits = {0};
    CmscbbAsnInt* pAsnInt = (CmscbbAsnInt*)v;

    if (v == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    ret = CmscbbDecodeBits(b, &asnBits, bytesDecoded, pstTempl);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    if (asnBits.octs == CVB_NULL) {
        CVB_LOG_ERROR(CMSCBB_ERR_ASN1_BITS_DEC, "Decode bits to intger failed.");
        return CMSCBB_ERR_ASN1_BITS_DEC;
    }

    *pAsnInt = asnBits.octs[0];

    if (asnBits.len == ASN_LONG_LENTH_COUNT) {
        *pAsnInt = (CmscbbAsnInt)((CVB_UINT32) * pAsnInt << BIT_COUNT_OF_BYTE) | asnBits.octs[1];
    } else if (asnBits.len > ASN_LONG_LENTH_COUNT) {
        CVB_LOG_ERROR(CMSCBB_ERR_ASN1_BITS_DEC, "unsupported length count");
        return CMSCBB_ERR_ASN1_BITS_DEC;
    }

    return CVB_SUCCESS;
}

/*
 * Prototype    : CmscbbOidToExku
 * Description  : asn1 oid to extended key usage converter
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN, OUT] v: memory address in which the result is parsed
 *   [OUT] bytesDecoded: Resolution of bytes consumed
 *   [IN] pstTempl: Resolution of bytes consumed
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2016/08/06 16:16  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbOidToExku(CMSCBB_BUF *b, CVB_VOID *v, CVB_UINT32 *bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    CMSCBB_ERROR_CODE ret;
    CmscbbAsnOidBundle extKuSet = {{0}};
    CmscbbAsnInt* pAsnInt = (CmscbbAsnInt*)v;
#ifdef CVB_DEBUG
    CMSCBB_ASN1_TEMPLATE realTempl = { &g_itemCmscbbAsnOidBundle, CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_NORMAL, 0, CVB_NULL, CVB_NULL };
#else
    CMSCBB_ASN1_TEMPLATE realTempl = { &g_itemCmscbbAsnOidBundle, CMSCBB_RELOC_INIT_VAL 0, CVB_ASN_NO_TAGGING, CVB_ASN_NORMAL, 0, CVB_NULL };
#endif /* CVB_DEBUG */

    (CVB_VOID)pstTempl;
    if (v == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    realTempl.asn1Item = &g_itemCmscbbAsnOidBundle;
    ret = CmscbbDecodeSetof(b, &extKuSet, bytesDecoded, &realTempl);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    /* extract ext usage */
    if (extKuSet.oid_bundle.num > 0) {
        CmscbbAsnOid* pExtKuId = &(extKuSet.oid_bundle.data[0]);
        CMSCBB_AOIDS extKuId = CmscbbFindAoid(pExtKuId);
        if (extKuId == AOID_KP_CODESIGNING) {
            *pAsnInt |= CMSCBB_ASN_XKU_CODE_SIGN;
        } else if (extKuId == AOID_KP_TIMESTAMPING) {
            *pAsnInt |= CMSCBB_ASN_XKU_TIMESTAMP;
        }
    }

    return CVB_SUCCESS;
}

CVB_STATIC CMSCBB_ERROR_CODE InternalCheckParmDecInt(const CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    if (pstTempl == CVB_NULL || bytesDecoded == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    return CVB_SUCCESS;
}

/*
 * Prototype    : CmscbbDecodeInt
 * Description  : decode asn1 element to integer
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN] v: memory address in which the result is parsed
 *   [IN] bytesDecoded: Resolution of bytes consumed
 *   [IN] pstTempl: Resolution of bytes consumed
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/11 12:06  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeInt(CMSCBB_BUF* b, CVB_VOID* v, CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    CMSCBB_BER_TAG tagReal = CVB_BER_TAG_INIT;
    CVB_UINT32 nElemLen = 0;
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 cur0;
    CMSCBB_BER_TAG_CODE tagCode = CBT_NULL_CODE;

    ret = InternalCheckParmDecInt(bytesDecoded, pstTempl);
    if (CVB_FAILED(ret)) {
        CVB_LOG_DEBUG(ret, CVB_NULL);
        return ret;
    }

    CVB_BUF_GET_CURSOR(b, cur0);

    if (pstTempl->asn1Item != CVB_NULL) {
        tagCode = pstTempl->asn1Item->ber_code;
    }

    ret = InternalAsn1ParseContent(b, pstTempl, CBF_PRIM, tagCode, &nElemLen, &tagReal);
    CVB_GOTO_ERR_IF_FAIL(ret);

    if (!(CVB_ASN_IGNORE & pstTempl->flag)) {
        CVB_ULONG value = 0;
        CVB_BYTE byte = 0;
        CmscbbAsnInt* pAsnInt = (CmscbbAsnInt*)v;
        CVB_INT i;

        if (pAsnInt == CVB_NULL) {
            CVB_LOG_ERROR(CMSCBB_ERR_ASN1_INT_DEC, CVB_NULL);
            return CMSCBB_ERR_ASN1_INT_DEC;
        }

        /* the int data should less then 4 byte */
        CVB_GOTO_ERR_IF(nElemLen > sizeof(CmscbbAsnInt), CMSCBB_ERR_ASN1_INT_DEC);

        ret = CmscbbBufGet(b, &byte);
        CVB_GOTO_ERR_IF(CVB_FAILED(ret), CMSCBB_ERR_ASN1_INT_DEC);

        if (tagCode == CBT_BOOLEAN) {
            CVB_GOTO_ERR_IF(nElemLen != 1, CMSCBB_ERR_ASN1_BOOL_DEC);
            value = (CVB_ULONG)(byte == 0xFF);
        } else {
            if (byte & SIGN_BIT_MASK) { /* top bit of first byte is sign bit */
                value = ((CVB_ULONG) - 1 ^ 0xFF) | byte;
            } else {
                value = byte;
            }
        }

        for (i = 1; i < (CVB_INT)nElemLen; ++i) {
            ret = CmscbbBufGet(b, &byte);
            CVB_GOTO_ERR_IF(CVB_FAILED(ret), CMSCBB_ERR_ASN1_INT_DEC);

            value = (value << BIT_COUNT_OF_BYTE) | (CVB_ULONG)byte;
        }

        *pAsnInt = (CmscbbAsnInt)value;
    } else {
        (CVB_VOID)CmscbbBufSeek(b, (CVB_INT32)nElemLen, CBSW_CURRENT);
    }

    *bytesDecoded = CVB_BUF_GET_OFFSET(b, cur0);

    goto CVB_FINAL;
CVB_ERR:
    CVB_BUF_REVERT_CURSOR(b, cur0);
CVB_FINAL:
    return ret;
}

/*
 * Prototype    : CmscbbDecodeSetof
 * Description  : decode DER set/sequence of
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN] v: memory address in which the result is parsed
 *   [IN] bytesDecoded: Resolution of bytes consumed
 *   [IN] pstTempl: Resolution of bytes consumed
 * Return Value : CVB_STATIC CMSCBB_ERROR_CODE
 * Remarks      : The template for "sequence of"/"set of" is very special,
 *   it should only have one item.
 *   Date              Author     Modification
 *   2015/11/11 12:07  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeSetof(CMSCBB_BUF* b, CVB_VOID* v, CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 cur0;
    CMSCBB_BER_TAG tagReal = CVB_BER_TAG_INIT;
    CVB_UINT32 nContentLen = 0;
    CVB_UINT32 nTotalElemLen = 0;
    CVB_UINT32 nElemLen = 0;
    CMSCBB_ASN1_TEMPLATE* pInternalTempl = CVB_NULL;
    CMSCBB_LIST_DUMMY* pList = CVB_NULL;
    CVB_UINT32 itemCount = 0;
    CVB_UINT32 maxItem;

    if (v == CVB_NULL || bytesDecoded == CVB_NULL || pstTempl == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    /* the template's item should be the one! the template is special for "sequence of" */
#define ITEM_COUNT_OF_TEMPLATE_OF_SETOF 1
    if (pstTempl->asn1Item->templ_count != ITEM_COUNT_OF_TEMPLATE_OF_SETOF) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    CVB_BUF_GET_CURSOR(b, cur0);

    ret = InternalAsn1ParseContent(b, pstTempl, CBF_CONS, (CMSCBB_BER_TAG_CODE)pstTempl->asn1Item->ber_code, &nContentLen, &tagReal);
    CVB_GOTO_ERR_IF(CVB_FAILED(ret), CMSCBB_ERR_ASN1_SETOF_DEC);

    pInternalTempl = pstTempl->asn1Item->asnTempl;
    /* Gets the memory address of the array by offset */
    pList = (CMSCBB_LIST_DUMMY*)((CVB_PTR)v + pInternalTempl->offset_val);
    /* Gets the maximum number of arrays */
    maxItem = (CVB_PTR)pInternalTempl->pDefaultVal;

    CVB_GOTO_ERR_IF(CVB_NULL == pInternalTempl->asn1Item->asn_func->pDecode, CMSCBB_ERR_ASN1_SETOF_DEC);

    while (nContentLen > nTotalElemLen) {
        CVB_VOID* pItemPtr = CVB_NULL;
        CVB_GOTO_ERR_IF(itemCount >= maxItem, CMSCBB_ERR_ASN1_SETOF_DEC);

        /* The memory address where the result is stored */
        pItemPtr = (CVB_VOID*)((CVB_PTR)pList->data + pInternalTempl->asn1Item->item_szie * itemCount);
        ret = pInternalTempl->asn1Item->asn_func->pDecode(b, pItemPtr, &nElemLen, pInternalTempl);
        CVB_GOTO_ERR_IF(CVB_FAILED(ret), CMSCBB_ERR_ASN1_SETOF_DEC);

        ++itemCount;
        nTotalElemLen += nElemLen;
    }

    CVB_GOTO_ERR_IF(nContentLen != nTotalElemLen, CMSCBB_ERR_ASN1_SETOF_DEC);
    pList->num = itemCount;

    *bytesDecoded = CVB_BUF_GET_OFFSET(b, cur0);

    goto CVB_FINAL;
CVB_ERR:
    CVB_BUF_REVERT_CURSOR(b, cur0);
CVB_FINAL:
    return ret;
}

/*
 * Prototype    : CmscbbDecodeMap
 * Description  : Resolves the ASN1 element to the type specified in the map
 * Params
 *   [IN] pVrf: Validation context
 *   [IN] b: DERData flow
 *   [IN] v: memory address in which the result is parsed
 *   [IN] bytesDecoded: Resolution of bytes consumed
 *   [IN] pstTempl: Resolution of bytes consumed
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2016/08/06 16:46  t00307193  Create
 */
CVB_STATIC CMSCBB_ERROR_CODE CmscbbDecodeMap(CMSCBB_BUF* b, CVB_VOID* v, CVB_UINT32* bytesDecoded, const CMSCBB_ASN1_TEMPLATE* pstTempl)
{
    CMSCBB_ERROR_CODE ret;
    CVB_UINT32 cur0;
    CMSCBB_BER_TAG tagReal = CVB_BER_TAG_INIT;
    CVB_UINT32 nContentLen = 0;
    CVB_UINT32 nTotalElemLen = 0;
    CmscbbX509ExtensionEntry extItem = {{0}, 0, {0}};

    if (v == CVB_NULL || bytesDecoded == CVB_NULL || pstTempl == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }
    CVB_BUF_GET_CURSOR(b, cur0);

    ret = InternalAsn1ParseContent(b, pstTempl, CBF_CONS, (CMSCBB_BER_TAG_CODE)pstTempl->asn1Item->ber_code, &nContentLen, &tagReal);
    CVB_GOTO_ERR_IF(CVB_FAILED(ret), CMSCBB_ERR_ASN1_SETOF_DEC);

    while (nContentLen > nTotalElemLen) {
        CVB_UINT32 nDecoded = 0;
        CmscbbAsn1Item* pAsnItem = pstTempl->asn1Item;
        CMSCBB_ASN1_TEMPLATE* pInternalTempl = pAsnItem->asnTempl;
        CVB_UINT32 ulAoid = 0;
        CVB_INT iter = 0;
        CMSCBB_ASN1_TEMPLATE itemTempl;

        /* in case of lack of base address */
        itemTempl.asn1Item = &g_itemCmscbbX509ExtensionEntry;
#if CMSCBB_RELOC_STRICT_CHECK
        itemTempl.relocted = CVB_FALSE;
#endif
        itemTempl.tagCode = 0;
        itemTempl.tagType = CVB_ASN_NO_TAGGING;
        itemTempl.flag = CVB_ASN_NORMAL;
        itemTempl.offset_val = 0;
#ifdef CVB_DEBUG
        itemTempl.name_val = CVB_NULL;
#endif
        itemTempl.pDefaultVal = CVB_NULL;

        /* Read a Cmscbb_x509_extension_entry type object from the buffer first */
        ret = CmscbbDecodeSeq(b, &extItem, &nDecoded, &itemTempl);
        CVB_GOTO_ERR_IF_FAIL(ret);
        CVB_GOTO_ERR_IF(CVB_NULL == extItem.extnValue.octs || 0 == extItem.extnValue.len, CMSCBB_ERR_ASN1_SETOF_DEC);

        nTotalElemLen += nDecoded;

        /* Traversing the map to find the real template */
        ulAoid = (CVB_UINT32)CmscbbFindAoid(&extItem.extnId);
        for (; iter < (CVB_INT)pAsnItem->templ_count; ++iter, ++pInternalTempl) {
            if (pInternalTempl->tagCode == ulAoid) {
                CMSCBB_BUF pBufVal = {0};
                pBufVal.pVal = extItem.extnValue.octs;
                pBufVal.nBufLen = extItem.extnValue.len;

                CVB_GOTO_ERR_IF(CVB_NULL == pInternalTempl->asn1Item->asn_func->pDecode, CMSCBB_ERR_ASN1_SETOF_DEC);
                ret = pInternalTempl->asn1Item->asn_func->pDecode(&pBufVal,
                    (CVB_VOID*)((CVB_PTR)v + pInternalTempl->offset_val), &nDecoded, pInternalTempl);
                CVB_GOTO_ERR_IF_FAIL(ret);
                break;
            }
        }
    }

    CVB_GOTO_ERR_IF(nContentLen != nTotalElemLen, CMSCBB_ERR_ASN1_SETOF_DEC);

    *bytesDecoded = CVB_BUF_GET_OFFSET(b, cur0);

    goto CVB_FINAL;
CVB_ERR:
    CVB_BUF_REVERT_CURSOR(b, cur0);
CVB_FINAL:
    return ret;
}

CMSCBB_ERROR_CODE CmscbbAsnDecode(const CVB_BYTE* pbBuf, CVB_UINT32 nBufLen, CmscbbAsn1Item* pAsnItem, CVB_BYTE flag, CVB_VOID** ppResult, CVB_UINT32* nDecoded)
{
    CVB_VOID* pResult = CVB_NULL;
    CMSCBB_ERROR_CODE ret;
    CMSCBB_BUF buf = {0};

    CMSCBB_ASN1_TEMPLATE templ;
    templ.asn1Item = pAsnItem;
#if CMSCBB_RELOC_STRICT_CHECK
    templ.relocted = CVB_FALSE;
#endif
    templ.tagCode = 0;
    templ.tagType = CVB_ASN_NO_TAGGING;
    templ.flag = (CVB_UINT16)flag;
    templ.offset_val = 0;
#ifdef CVB_DEBUG
    templ.name_val = CVB_NULL;
#endif
    templ.pDefaultVal = CVB_NULL;

    if (pbBuf == CVB_NULL || nBufLen == 0 || pAsnItem == CVB_NULL || ppResult == CVB_NULL || nDecoded == CVB_NULL) {
        CVB_LOG_DEBUG(CMSCBB_ERR_CONTEXT_INVALID_PARAM, CVB_NULL);
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    CVB_GOTO_ERR_IF(pAsnItem->asn_func->pDecode == CVB_NULL, CMSCBB_ERR_ASN1_BASE);

    ret = CmscbbBufInit(&buf, pbBuf, nBufLen);
    CVB_GOTO_ERR_IF_FAIL(ret);

    ret = CmscbbMallocWith0(&pResult, pAsnItem->item_szie);
    CVB_GOTO_ERR_IF_FAIL(ret);

    ret = pAsnItem->asn_func->pDecode(&buf, pResult, nDecoded, &templ);
    CVB_GOTO_ERR_IF_FAIL(ret);

    *ppResult = pResult;
    goto CVB_FINAL;
CVB_ERR:
    CmscbbFree(pResult);
CVB_FINAL:
    return ret;
}

CVB_VOID CmscbbAsnFree(CVB_VOID* pObj, const struct cmscbb_asn1Item_st* pAsnItem, CVB_BYTE flag)
{
    (CVB_VOID)pAsnItem;
    (CVB_VOID)flag;
    CmscbbFree(pObj);
}
