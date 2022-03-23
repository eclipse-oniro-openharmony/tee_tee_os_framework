/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */

/*
 * File Name          : cmscbb_list.h
 * Brief              : <TODO>
 * Author             : t00307193
 * Creation Date      : 2015/07/22 15:52:05
 * Detail Description : The list is not thread safe, so the pVrf should in the same thread.
 * History            
 *      Date time           Author        Description
 *      2015/07/22 15:52    t00307193     new
 */
#ifndef H_CMSCBB_LIST_H
#define H_CMSCBB_LIST_H
#include "../cmscbb_common/cmscbb_def.h"
#include "cmscbb_sdk.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Prototype    : CmscbbListFreeCallback
 * Description  : function type of free list item callback
 * Params
 *   [IN] CVB_VOID*: function pointer
 * Return Value : CVB_VOID
 *   Date              Author     Modification
 *   2015/11/10 17:31  t00307193  Create
 */
typedef CVB_VOID(*CmscbbListFreeCallback)(CVB_VOID*);

/*
 * Prototype    : CmscbbListItemCmpCallback
 * Description  : function type of list search and sort callback
 * Params
 *   [IN] pExpect: expect function 
 *   [IN] pActual: actual 
 * Return Value : typedef CVB_INT
 *   Date              Author     Modification
 *   2015/11/10 18:05  t00307193  Create
 */
typedef CVB_INT(*CmscbbListItemCmpCallback)(const CVB_VOID* pExpect, const CVB_VOID* pActual);

/*
 * Prototype    : CmscbbListAdd
 * Description  : add item into list.
 * Params
 *   [IN] pList: cmscbb list
 *   [IN] pItem: cms item object
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 17:30  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbListAdd(CMSCBB_LIST_DUMMY* pList, CVB_VOID* pItem);

/*
 * Prototype    : CmscbbListSort
 * Description  : sort items in the list.
 * Params
 *   [IN] pList: cmscbb list
 *   [IN] cmp_cb:compare callback
 * Return Value : CMSCBB_ERROR_CODE
 *   Date              Author     Modification
 *   2015/11/10 17:30  t00307193  Create
 */
CMSCBB_ERROR_CODE CmscbbListSort(CMSCBB_LIST_DUMMY* pList, CmscbbListItemCmpCallback cmp_cb);

/*
 * Prototype    : CmscbbListFree
 * Description  : free the list.
 * Params
 *   [IN] pList: cmscbb list
 *   [IN] free_cb: free callback 
 * Return Value : CVB_VOID
 * Remarks      : all items in the list will be free through callback.
 *   Date              Author     Modification
 *   2015/11/10 17:30  t00307193  Create
 */
CVB_VOID CmscbbListFree(CMSCBB_LIST_DUMMY* pList, CmscbbListFreeCallback free_cb);

#define CMSCBB_LIST_ADD(pList, pItem) CmscbbListAdd((CMSCBB_LIST_DUMMY*)(CVB_VOID*)(pList), pItem)
#define CMSCBB_LIST_SORT(pList, cmp_cb) CmscbbListSort((CMSCBB_LIST_DUMMY*)(CVB_VOID*)(pList), (CmscbbListItemCmpCallback)(cmp_cb))
#define CMSCBB_LIST_FREE(pList, free_cb) CmscbbListFree((CMSCBB_LIST_DUMMY*)(CVB_VOID*)(pList), (CmscbbListFreeCallback)(free_cb))

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* H_CMSCBB_LIST_H */
