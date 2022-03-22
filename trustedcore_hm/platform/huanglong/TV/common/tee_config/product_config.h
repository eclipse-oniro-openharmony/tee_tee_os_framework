/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: for product config defination
 * Create: 2020-09-01
 */
#ifndef PRODUCT_CONFIG_H
#define PRODUCT_CONFIG_H

#ifdef DEF_ENG
#define UT_MEM_LEN   (15U * 1024U * 1024U)
#endif
#define EID1_MEM_LEN (26U * 1024U * 1024U)
#define EID3_MEM_LEN (3U * 1024U * 1024U)
#define AI_TINY_MEM_SIZE (2U * 1024U * 1024U)
#define NPU_MEM_LEN (128U * 1024U * 1024U)

enum DYN_MEM_CONFIGID {
    CONFIGID_UT          = 1,
    CONFIGID_EID1        = 2,
    CONFIGID_EID3        = 3,
    CONFIGID_AI          = 4,
    CONFIGID_AI_TINY     = 5,
    CONFIGID_NPU         = 6,
};

enum DDR_SEC_REGION {
    DDR_SEC_EID = 5,
    DDR_SEC_FACE = 0x10,
};

#endif
