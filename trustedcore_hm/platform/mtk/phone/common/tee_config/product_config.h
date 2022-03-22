/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: for product config defination
 * Author: Heyanhong heyanhong2@huawei.com
 * Create: 2020-09-14
 */
#ifndef PRODUCT_CONFIG_H
#define PRODUCT_CONFIG_H

#ifdef DEF_ENG
#define UT_MEM_LEN   (15U * 1024U * 1024U)
#define TEST_DYNION_MEM_LEN (4U * 1024U * 1024U)
#endif
#define EID1_MEM_LEN (26U * 1024U * 1024U)
#define EID3_MEM_LEN (3U * 1024U * 1024U)
#define AI_TINY_MEM_SIZE (2U * 1024U * 1024U)

enum DYN_MEM_CONFIGID {
#ifdef DEF_ENG
    CONFIGID_UT          = 1,
#endif
    CONFIGID_EID1        = 2,
    CONFIGID_EID3        = 3,
    CONFIGID_AI        = 4,
    CONFIGID_AI_TINY   = 5,
#ifdef DEF_ENG
    CONFIGID_TEST_DYNION = 6,
#endif
};

/* this enum is from hisi */
enum DDR_SEC_REGION {
    DDR_SEC_EID = 5,
    DDR_SEC_FACE = 0x10,
};

#endif
