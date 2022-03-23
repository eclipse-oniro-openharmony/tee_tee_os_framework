/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2015-2018. All rights reserved.
 * Description: Signature Verify CBB Library
 * Author: t00307193
 * Create: 2015
 * History: 2018/11/23 y00309840 UK rule fixes
 */
#ifndef H_CMSCBB_LIST_DEF_H
#define H_CMSCBB_LIST_DEF_H
#include "cmscbb_types.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CVB_LIST_MAX_COUNT 16

#define LIST_OF(elem) LIST_TYPE_##elem
#define DECLARE_LIST_OF(elem) typedef struct list_type_##elem {\
    CVB_UINT32 num; \
    elem* data[CVB_LIST_MAX_COUNT]; \
} LIST_TYPE_##elem

#define SEQUENCE_OF LIST_OF

typedef struct cmscbb_list_dummy_st {
    CVB_UINT32 num;
    CVB_VOID* data[CVB_LIST_MAX_COUNT];
} CMSCBB_LIST_DUMMY;

#define SET_OF(elem) SET_TYPE_##elem
#define DECLARE_SET_OF(elem, capacity) typedef struct set_type_##elem {\
    CVB_UINT32 num; \
    elem data[(capacity)]; \
} SET_TYPE_##elem

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* H_CMSCBB_LIST_DEF_H */
