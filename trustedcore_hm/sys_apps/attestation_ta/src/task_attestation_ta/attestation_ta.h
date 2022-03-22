/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: attestation ta head file
 * Create: 2019-03-25
 * History: 2019-12-10 limingjuan@huawei.com modify csec issue
 */

#ifndef ATTEST_ATTESTATION_TA_H
#define ATTEST_ATTESTATION_TA_H

#include <tee_defines.h>

#define ATTEST_TA_CMD_ID_INIT       0x1 /* attestation ta init cmd */
#define PARAM_ZERO                  0
#define PARAM_ONE                   1
#define PARAM_TWO                   2
#define PARAM_THREE                 3
#define PARAM_NUM                   4
#define ATTEST_TA_VEISION_LEN       64
#define TA_PUBKEY_DER_LEN           294
#define ATTEST_TA_CHAIN_MAX_LEN     8192
#define PKI_KM_CMD_ID_ATTEST_TA_KEY 14
#define DEVICE_ID_LEN               32
#define API_VERSION_LEN             16
#define IMPL_VERSION_LEN            32

struct cert_extension_t {
    TEE_UUID uuid;
    uint8_t device_id[DEVICE_ID_LEN];
    uint8_t tee_api_version[API_VERSION_LEN];
    uint8_t tee_impl_version[IMPL_VERSION_LEN];
};
#endif
