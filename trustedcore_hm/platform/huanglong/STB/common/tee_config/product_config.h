/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: for product config defination
 * Create: 2020-04-23
 */
#ifndef PRODUCT_CONFIG_H
#define PRODUCT_CONFIG_H

#ifdef DEF_ENG
#define UT_MEM_LEN   (15U * 1024U * 1024U)
#endif
#define EID1_MEM_LEN (26U * 1024U * 1024U)
#define EID3_MEM_LEN (3U * 1024U * 1024U)

#define HIAI_RUNNING_MEM_BASE   0x19A00000U /* these macros should be delete when sync hisi next */
#define HIAI_RUNNING_MEM_LEN    0x1780000U
#define HIAI_PAGETABLE_MEM_BASE 0x1B180000U
#define HIAI_PAGETABLE_MEM_LEN  0x180000U

enum DYN_MEM_CONFIGID {
    CONFIGID_UT     = 1,
    CONFIGID_EID1   = 2,
    CONFIGID_EID3   = 3,
    CONFIGID_AI   = 4,
};

/* this enum is from hisi */
enum DDR_SEC_REGION {
    DDR_SEC_EID = 5,
    DDR_SEC_FACE = 0x10,
};

#endif
