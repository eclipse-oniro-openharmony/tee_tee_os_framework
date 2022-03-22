/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: ccdriver adapt header file
 * Author: zhanglinhao
 * Create: 2020-06-18
 */
#ifndef _CC_ADAPT_H
#define _CC_ADAPT_H

#define CC_ECPKI_PUBL_KEY_VALIDATION_TAG  0xEC000001
#define CC_ECPKI_PRIV_KEY_VALIDATION_TAG 0xEC000002

#include "cc_ecpki_types.h"
#include "cc_aes.h"
#include <cc_util_defs.h>
/* !< \internal [(CC_ECPKI_MODUL_MAX_LENGTH_IN_BITS + 31)/(sizeof(uint32_t)) + 1] */
#define CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS  18
#define BUF_LEN  10
#define WORD_LEN  4
#define WORD_ALIGNE  3
typedef enum  {
    UTIL_USER_KEY = 0,
    UTIL_ROOT_KEY = 1,
    UTIL_SESSION_KEY = 2,
    UTIL_END_OF_KEY_TYPE = 0x7FFFFFFF
} UtilKeyType_t;

typedef struct {
    /*! Private Key data. */
    uint32_t PrivKey[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    CCEcpkiDomainID_t DomainID;
    uint32_t tmp_buf[BUF_LEN];
} CCEcpkiPrivKey_trans_t;

typedef struct CCEcpkiUserPrivKey_trans_t {
    uint32_t valid_tag;
    uint32_t PrivKeyDbBuff[(sizeof(CCEcpkiPrivKey_trans_t) + WORD_ALIGNE) / WORD_LEN];
} CCEcpkiUserPrivKey_trans_t;

typedef struct {
    /*! Public Key coordinates. */
    uint32_t PublKeyX[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t PublKeyY[CC_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    CCEcpkiDomainID_t DomainID;
    uint32_t pointType;
} CCEcpkiPublKey_trans_t;

typedef struct CCEcpkiUserPublKey_trans_t {
    uint32_t valid_tag;
    uint32_t PublKeyDbBuff[(sizeof(CCEcpkiPublKey_trans_t) + WORD_ALIGNE) / WORD_LEN];
} CCEcpkiUserPublKey_trans_t;

CCUtilError_t UtilCmacDeriveKey(UtilKeyType_t keyType,
                                CCAesUserKeyData_t *pUserKey,
                                uint8_t *pDataIn,
                                size_t dataInSize,
                                CCUtilAesCmacResult_t pCmacResult);
#endif
