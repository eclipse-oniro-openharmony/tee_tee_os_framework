/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: get key for verifying TA's singature
 * Author: huangjiankang@huawei.com
 * Create: 2020.04.27
 */
#include "ta_verify_key.h"
#include "ta_load_key.h"

static const rsa_pub_key_t g_ta_verify_pub_key = { { 0 }, 0, { 0 }, 0 };

static const struct ta_verify_key g_verify_key[] = {
    { PUB_KEY_2048_BITS, PUB_KEY_RELEASE, &g_ta_verify_pub_key },
};

TEE_Result get_ta_verify_pubkey(struct ta_verify_key *key_info)
{
    return query_ta_verify_pubkey(g_verify_key, sizeof(g_verify_key) / sizeof(g_verify_key[0]), key_info);
}
TEE_Result oh_get_ta_pub_key(void **key, uint32_t alg)
{
    (void)key;
    (void)alg;
    return TEE_SUCCESS;
}
