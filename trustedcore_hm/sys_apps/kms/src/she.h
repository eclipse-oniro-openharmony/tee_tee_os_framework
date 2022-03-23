/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: kms secure hardware extensions function
 * Create: 2022-01-25
 */
#ifndef KMS_SHE_H
#define KMS_SHE_H
#include "tee_internal_api.h"
#include "kms_pub_def.h"

#define MP_AES_KEY_SIZE 128
#define MP_BLOCK_SIZE 16
#define MP_RESULT_LEN 16

#define MP_MIN_PAD_LEN 6
#define MP_PAD_START_BYTE 0x80
#define MP_MAX_MSG_BIT_LEN 0xFFFFFFFFFF
#define BITS_PER_BYTE 8
#define MP_BLOCK_MAX_OFFSET 15
#define MP_PAD_MSG_LENGTH_LEN 5

#define SHE_BLOCK_LEN 16
#define MAX_AUTH_KEY_LEN 64
#define EXPORT_KEY_LEN 16

#define SHE_M1_LENGTH 16 /* UID(120bits) || ID(4bits) || AUTHID(4bits)  */
#define SHE_M2_HEADER_LENGTH 16 /* COUNTER(28bits) || KEY_FLAGS(6bits) || "0..0"(94bits) */
#define SHE_COUNTER_LENGTH 15
#define SHE_M2_LENGTH 32
#define SHE_M3_LENGTH 16
#define SHE_M4_LENGTH 32
#define SHE_M5_LENGTH 16
struct she_opera_input {
    uint8_t m1[SHE_M1_LENGTH];
    uint8_t m2_header[SHE_M2_HEADER_LENGTH];
};

struct she_key {
    uint8_t auth_key_buffer[MAX_AUTH_KEY_LEN];
    uint8_t enc_key_buffer[MP_RESULT_LEN];
    uint8_t mac_key_buffer[MP_RESULT_LEN];
    uint8_t export_key_buffer[EXPORT_KEY_LEN];
};
struct she_export_output {
    uint8_t m1_buffer[SHE_M1_LENGTH];
    uint8_t m2_buffer[SHE_M2_LENGTH];
    uint8_t m3_buffer[SHE_M3_LENGTH];
};

#define SHE_M4_ENC_LENGTH 16
struct she_verify_expect {
    uint8_t m4_buffer[SHE_M4_LENGTH];
    uint8_t m5_buffer[SHE_M5_LENGTH];
};

TEE_Result she_export_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *opt_handle,
    struct kms_buffer_data *gp_key_blob, struct kms_buffer_data *out_key);
TEE_Result she_verify_key(const struct kms_buffer_data *param_set, struct kms_buffer_data *opt_handle,
    struct kms_buffer_data *gp_key_blob, struct kms_buffer_data *verify_data);

#endif
