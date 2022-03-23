/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2021. All rights reserved.
 * Description: get key for verifying TA's singature header file
 * Create: 2020.04.27
 */
#ifndef GTASK_TA_VERIFY_KEY_H
#define GTASK_TA_VERIFY_KEY_H

#include <crypto_wrapper.h>

enum verify_key_len {
    PUB_KEY_2048_BITS = 2048,
    PUB_KEY_4096_BITS = 4096,
    PUB_KEY_256_BITS  = 256
};

enum verify_key_style {
    PUB_KEY_DEBUG = 0,
    PUB_KEY_RELEASE = 1,
};

struct ta_verify_key {
    uint32_t key_len;
    uint32_t key_style;
    const void *key;
};

TEE_Result get_ta_verify_pubkey(struct ta_verify_key *key_info);
TEE_Result oh_get_ta_pub_key(void **key, uint32_t alg);
#endif
