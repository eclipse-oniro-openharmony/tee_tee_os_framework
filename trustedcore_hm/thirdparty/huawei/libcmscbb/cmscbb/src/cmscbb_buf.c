/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../cmscbb_common/cmscbb_buf.h"

CMSCBB_ERROR_CODE CmscbbBufInit(CMSCBB_BUF* pBuf, const CVB_BYTE* pVal, CVB_UINT32 nValLen)
{
    if (pBuf == CVB_NULL || pVal == CVB_NULL || nValLen == 0) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    pBuf->pVal = pVal;
    pBuf->nBufLen = nValLen;
    pBuf->iCursor = 0;

    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbBufGet(CMSCBB_BUF* pBuf, CVB_BYTE* pByte)
{
    if (pBuf == CVB_NULL || pByte == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    /* nBufLen < 2M , So it won't overflow. */
    if (pBuf->iCursor == pBuf->nBufLen) {
        return CMSCBB_ERR_SYS_BUF_EOF;
    }

    *pByte = pBuf->pVal[pBuf->iCursor++];
    return CVB_SUCCESS;
}

CMSCBB_ERROR_CODE CmscbbBufSeek(CMSCBB_BUF* pBuf, CVB_INT32 iPos, CMSCBB_BUF_SEEK_WAY way)
{
    CVB_INT32 iNewPos;

    if (pBuf == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    if (way != CBSW_CURRENT) {
        return CMSCBB_ERR_UNDEFINED;
    }

    iNewPos = (CVB_INT32)pBuf->iCursor + iPos;
    if (iNewPos < 0 /* Prevent overflow symbol reversal */
            || iNewPos > (CVB_INT32)pBuf->nBufLen) {
        return CMSCBB_ERR_UNDEFINED;
    }
    pBuf->iCursor = (CVB_UINT32)iNewPos;

    return CVB_SUCCESS;
}
