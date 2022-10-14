/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: get key for verifying TA's singature
 * Create: 2021.08.17
 */
#include "ta_verify_key.h"
#include "ta_load_key.h"

TEE_Result get_ta_verify_pubkey(struct ta_verify_key *key_info)
{
    return query_ta_verify_pubkey(NULL, 0, key_info);
}

TEE_Result oh_get_ta_pub_key(void **key, uint32_t alg)
{
    (void)key;
    (void)alg;
    return TEE_SUCCESS;
}
