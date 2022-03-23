/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: record the register mmap information.
 * Create: 2020-03
 */
#ifndef PLATDRV_MTK_CC_ADAPT_H
#define PLATDRV_MTK_CC_ADAPT_H

#define CC_ECPKI_PUBL_KEY_VALIDATION_TAG 0xEC000001
#define CC_ECPKI_PRIV_KEY_VALIDATION_TAG 0xEC000002

typedef enum {
    UTIL_USER_KEY        = 0,
    UTIL_ROOT_KEY        = 1,
    UTIL_SESSION_KEY     = 2,
    UTIL_END_OF_KEY_TYPE = 0x7FFFFFFF
} UtilKeyType_t;

typedef enum {
    CRYS_AES_Key128BitSize = 0,
    CRYS_AES_Key192BitSize = 1,
    CRYS_AES_Key256BitSize = 2,
    CRYS_AES_Key512BitSize = 3,
    CRYS_AES_KeySizeNumOfOptions,
    CRYS_AES_KeySizeLast = 0x7FFFFFFF,
} CRYS_AES_KeySize_t;

typedef struct {
    /* ! Private Key data. */
    uint32_t PrivKey[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    CCEcpkiDomainID_t domain;
    uint32_t tmp_buf[10];
} CCEcpkiPrivKey_trans_t;

typedef struct CCEcpkiUserPrivKey_trans_t {
    uint32_t valid_tag;
    uint32_t PrivKeyDbBuff[(sizeof(CCEcpkiPrivKey_trans_t) + 3) / 4];
} CCEcpkiUserPrivKey_trans_t;

typedef struct {
    /* ! Public Key coordinates. */
    uint32_t x[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t y[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    CCEcpkiDomainID_t domain;
    uint32_t pointType;
} CCEcpkiPublKey_trans_t;

typedef struct CCEcpkiUserPublKey_trans_t {
    uint32_t valid_tag;
    uint32_t PublKeyDbBuff[(sizeof(CCEcpkiPublKey_trans_t) + 3) / 4];
} CCEcpkiUserPublKey_trans_t;
#endif
