/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: table2
 * Create: 2012-01-17
 */

#ifndef TABLE2_H_
#define TABLE2_H_
#include "table2_1.h"
#include "table2_2.h"
#include "table2_3.h"
#include "table2_4.h"
#include "table2_5.h"
#include "table2_6.h"
#include "table2_7.h"

#ifndef wb_aes_bround
#define wb_aes_bround(tb, x, y, r)     \
do { \
    x##0 = table(tb, r, 0, 0, (y##0 >> 0) & 0xFF) ^ table(tb, r, 0, 1, (y##3 >> 8) & 0xFF) ^ \
        table(tb, r, 0, 2, (y##2 >> 16) & 0xFF) ^ table(tb, r, 0, 3, (y##1 >> 24) & 0xFF);   \
    x##1 = table(tb, r, 1, 0, (y##1 >> 0) & 0xFF) ^ table(tb, r, 1, 1, (y##0 >> 8) & 0xFF) ^ \
        table(tb, r, 1, 2, (y##3 >> 16) & 0xFF) ^ table(tb, r, 1, 3, (y##2 >> 24) & 0xFF);   \
    x##2 = table(tb, r, 2, 0, (y##2 >> 0) & 0xFF) ^ table(tb, r, 2, 1, (y##1 >> 8) & 0xFF) ^ \
        table(tb, r, 2, 2, (y##0 >> 16) & 0xFF) ^ table(tb, r, 2, 3, (y##3 >> 24) & 0xFF);   \
    x##3 = table(tb, r, 3, 0, (y##3 >> 0) & 0xFF) ^ table(tb, r, 3, 1, (y##2 >> 8) & 0xFF) ^ \
        table(tb, r, 3, 2, (y##1 >> 16) & 0xFF) ^ table(tb, r, 3, 3, (y##0 >> 24) & 0xFF);   \
}while (0)

#endif

#ifndef WB_EXP_SIZE2
#define WB_EXP_SIZE2 8
#endif

#ifndef WB_NR2
#define WB_NR2 14
#endif

/* table2 size is 57344 */
#define TABLE_ARRAY_SIZE 57344
const unsigned int g_table2[TABLE_ARRAY_SIZE] = {
    TABLE2_CONTENT_1,
    TABLE2_CONTENT_2,
    TABLE2_CONTENT_3,
    TABLE2_CONTENT_4,
    TABLE2_CONTENT_5,
    TABLE2_CONTENT_6,
    TABLE2_CONTENT_7
};
#endif
