/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_BUF_H
#define H_CMSCBB_BUF_H
#include "../cmscbb_common/cmscbb_def.h"

#ifdef __cplusplus
extern "C" {
#endif

/* End OF Buffer */
#define CMSCBB_EOB (CVB_UINT32)(-1)

typedef enum CmscbbBufSeekWayEm {
    CBSW_SET = 0,
    CBSW_CURRENT = 1
} CMSCBB_BUF_SEEK_WAY;

typedef struct cmscbb_buf_st {
    const CVB_BYTE* pVal;
    CVB_UINT32 nBufLen;
    CVB_UINT32 iCursor;
} CMSCBB_BUF;

/*
 * Prototype    : CmscbbBufInit
 * Description  : Initialize read-only buffer with memory data.
 * Params
 *   [IN] pBuf: buffer
 *   [IN] pVal: valid
 *   [IN] nValLen: valid length
 * Return Value : CMSCBB_ERROR_CODE
 * Remarks      : extern memory data is attached into this buffer,
 *   so don't free the memory before buffer destroy.
 
 *   Date              Author     Modification
 *   2015/11/10 19:17  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbBufInit(CMSCBB_BUF* pBuf, const CVB_BYTE* pVal, CVB_UINT32 nValLen);

/*
 * Prototype    : CmscbbBufGet
 * Description  : get 1 byte from the buffer.
 * Params
 *   [IN] pBuf: buffer
 *   [IN] pByte: byte
 * Return Value : CMSCBB_ERROR_CODE
 * Remarks      : buffer's read point will increase by 1.
 *   Date              Author     Modification
 *   2015/11/10 19:19  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbBufGet(CMSCBB_BUF* pBuf, CVB_BYTE* pByte);

/*
 * Prototype    : CmscbbBufSeek
 * Description  : Change the current read point.
 * Params
 *   [IN] pBuf: buffer
 *   [IN] iPos: position
 *   [IN] way: way to seek the buffer
 * Return Value : CMSCBB_ERROR_CODE
   Author     Modification
 *   2015/11/10 19:22  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbBufSeek(CMSCBB_BUF* pBuf, CVB_INT32 iPos, CMSCBB_BUF_SEEK_WAY way);

#ifdef __cplusplus
}
#endif

#endif /* H_CMSCBB_BUF_H */
