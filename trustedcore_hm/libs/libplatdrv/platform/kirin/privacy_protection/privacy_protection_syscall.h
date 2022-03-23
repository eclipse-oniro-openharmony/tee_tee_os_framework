/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TA sevice for privacydata protection
 * Create: 2020-03-10
 */
#ifndef SYSCALL_PRIVACY_PROTECTION_H
#define SYSCALL_PRIVACY_PROTECTION_H

#include "stdint.h"

enum cmd {
    PRIP_MSP_POWERON      = 0,
    PRIP_MSP_POWEROFF     = 1,
    PRIP_RNG_GEN_TRND     = 2,
    PRIP_SM2_GEN_KEY      = 3,
    PRIP_SM2_ENCRYPT      = 4,
    PRIP_SM2_DECRYPT      = 5,
    PRIP_SM3_HASH_INIT    = 6,
    PRIP_SM3_HASH_UPDATE  = 7,
    PRIP_SM3_HASH_DOFINAL = 8,
    PRIP_SM3_HASH_SIGLE   = 9,
    PRIP_SM4_SET_KEY      = 10,
    PRIP_SM4_SET_IV       = 11,
    PRIP_SM4_INIT         = 12,
    PRIP_SM4_UPDATE       = 13,
    PRIP_SM4_DOFINAL      = 14,
    PRIP_KM_DERIVE_KDR    = 15,
    PRIP_SM9_SIGN         = 16,
    PRIP_SM9_VERIFY       = 17,
    PRIP_SM9_ENCRYPT      = 18,
    PRIP_SM9_DECRYPT      = 19,
    PRIP_SM9_WRAP_KEY     = 20,
    PRIP_SM9_UNWRAP_KEY   = 21,
    PRIP_SM9_PRE_DATA     = 22,
};
#endif
