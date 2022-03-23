/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#include "../cmscbb_common/cmscbb_list.h"

CMSCBB_ERROR_CODE CmscbbListAdd(CMSCBB_LIST_DUMMY* pList, CVB_VOID* pItem)
{
    if (pList == CVB_NULL || pItem == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    if (pList->num >= CVB_LIST_MAX_COUNT) {
        return CMSCBB_ERR_SYS_LIST_OVERFLOW;
    }

    pList->data[pList->num] = pItem;
    ++pList->num;

    return CVB_SUCCESS;
}

CVB_VOID CmscbbListFree(CMSCBB_LIST_DUMMY* pList, CmscbbListFreeCallback free_cb)
{
    CVB_INT iter;

    if (pList == CVB_NULL || free_cb == CVB_NULL) {
        return;
    }

    for (iter = 0; iter < (CVB_INT)pList->num; ++iter) {
        free_cb(pList->data[iter]);
    }

    pList->num = 0;
}

/* use a improved bubble sort */
CMSCBB_ERROR_CODE CmscbbListSort(CMSCBB_LIST_DUMMY* pList, CmscbbListItemCmpCallback cmp_cb)
{
    CVB_INT iter1;
    CVB_INT iter2;
    /* check if last sort already done */
    CVB_INT flag;

    if (pList == CVB_NULL || cmp_cb == CVB_NULL) {
        return CMSCBB_ERR_CONTEXT_INVALID_PARAM;
    }

    flag = 1;
    for (iter1 = 0; iter1 < (CVB_INT)pList->num && flag; ++iter1) {
        const CVB_INT N_CMP = 2;
        CVB_INT beginIndex = (CVB_INT)pList->num - N_CMP;
        flag = 0;
        for (iter2 = beginIndex; iter2 >= iter1; --iter2) {
            if (cmp_cb(pList->data[iter2], pList->data[iter2 + 1]) > 0) {
                /* swap two element */
                CVB_VOID* pTemp = pList->data[iter2];
                pList->data[iter2] = pList->data[iter2 + 1];
                pList->data[iter2 + 1] = pTemp;
                flag = 1;
            }
        }
    }

    return CVB_SUCCESS;
}
