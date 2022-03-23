/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2012-2020. All rights reserved.
 * Description: cc driver implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
 */

#ifndef _CC_ADAPT_H
#define _CC_ADAPT_H

#include "ssi_aes.h"
#include "ssi_pal_types_plat.h"
#include "sasi_aesccm.h"
#include "sns_silib.h"
#include "sasi_des.h"
#include "sasi_hmac.h"
#include "ssi_util_oem_asset.h"
#include "sasi_ecpki_types.h"
#include "sasi_dh.h"
#include "sasi_rsa_schemes.h"
#include "sasi_rsa_build.h"
#include "sasi_ecpki_build.h"
#include "sasi_ecpki_domain.h"
#include "sasi_ecpki_kg.h"
#include "sasi_ecpki_ecdsa.h"
#include "sasi_rsa_kg.h"
#include "sasi_ecpki_dh.h"
#include "sasi_rsa_prim.h"
#include "ssi_util_key_derivation.h"
#include "sasi_ecpki_local.h"
#include "ssi_util_error.h"
#include "ssi_util_cmac.h"

#define CC_ECPKI_PUBL_KEY_VALIDATION_TAG  0xEC000001
#define CC_ECPKI_PRIV_KEY_VALIDATION_TAG 0xEC000002

#ifndef align_up_size
#define align_up_size(x, alignment)    ((sizeof(x) + ((alignment) - 1)) / (alignment))
#endif

#define TMP_BUFFER_SIZE 10

typedef enum  {
    UTIL_USER_KEY = 0,
    UTIL_ROOT_KEY = 1,
    UTIL_SESSION_KEY = 2,
    UTIL_END_OF_KEY_TYPE = 0x7FFFFFFF
} UtilKeyType_t;

typedef struct {
    /*! Private Key data. */
    uint32_t  PrivKey[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS + 1];
    SaSi_ECPKI_DomainID_t  DomainID;
    uint32_t tmp_buf[TMP_BUFFER_SIZE];
} SaSi_ECPKI_PrivKey_trans_t;

typedef struct SaSi_ECPKI_UserPrivKey_trans_t {
    uint32_t    valid_tag;
    uint32_t    PrivKeyDbBuff[align_up_size(SaSi_ECPKI_PrivKey_trans_t, 4)];
} SaSi_ECPKI_UserPrivKey_trans_t;

typedef struct {
    /*! Public Key coordinates. */
    uint32_t PublKeyX[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    uint32_t PublKeyY[SaSi_ECPKI_MODUL_MAX_LENGTH_IN_WORDS];
    SaSi_ECPKI_DomainID_t  DomainID;
    uint32_t pointType;
} SaSi_ECPKI_PublKey_trans_t;

typedef struct SaSi_ECPKI_UserPublKey_trans_t {
    uint32_t    valid_tag;
    uint32_t    PublKeyDbBuff[align_up_size(SaSi_ECPKI_PublKey_trans_t, 4)];
} SaSi_ECPKI_UserPublKey_trans_t;

void DX_Clock_Init(void);
void DX_Clock_Uninit(void);
CIMPORT_C SaSiError_t sasi_aes_mac_mode(SaSiAesUserContext_t *pContext, SaSiBool_t *mac_mode);
SaSiError_t SaSi_AESCCM_Init_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, SaSiAesEncryptMode_t EncrDecrMode,
                                 SaSi_AESCCM_Key_t CCM_Key, SaSi_AESCCM_KeySize_t KeySizeId, uint32_t AdataSize,
                                 uint32_t TextSize, uint8_t *N_ptr, uint8_t SizeOfN, uint8_t SizeOfT);
SaSiError_t SaSi_AESCCM_BlockTextData_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                          uint32_t DataInSize, uint8_t *DataOut_ptr);

CEXPORT_C SaSiError_t SaSi_AESCCM_Finish_MTK(SaSi_AESCCM_UserContext_t *ContextID_ptr, uint8_t *DataIn_ptr,
                                             uint32_t DataInSize, uint8_t *DataOut_ptr, SaSi_AESCCM_Mac_Res_t MacRes,
                                             uint8_t *SizeOfT);
#endif
