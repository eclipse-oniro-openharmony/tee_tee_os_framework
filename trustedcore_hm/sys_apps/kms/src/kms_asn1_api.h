/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: KMS ASN1 function
 * Create: 2021-08-10
 */

#ifndef KMS_KMS_ANS1_API_H
#define KMS_KMS_ANS1_API_H

#include "kms_pub_def.h"

#define TAG_SEQUENCE  0x30
#define TAG_INTEGER   0x02
#define TAG_BITSTRING 0x03
#define TAG_OID       0x06
#define MAX_HEADER_LEN 0x05
#define SM2_MODE_LEN  0x20
#define ECPOINT       0x04
#define MAX_PUBKEY_LEN 256
#define RIGHT_SHIFT_ONE_BYTE 8

TEE_Result ecc_pubkey_to_asn1(struct kms_buffer_data *in_pub_key, struct kms_buffer_data *out_pub_key);
#endif
