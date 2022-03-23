/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: gatekeeper auth token code header
 * Create: 2021-11-30
 */
#ifndef GATEKEEPER_AUTH_TOKEN_H
#define GATEKEEPER_AUTH_TOKEN_H

#include <stdint.h>
#include <stdbool.h>
#include <tee_ext_api.h>
#include "tee_defines.h"
#include "gatekeeper.h"

/* Data format for an authentication record used to prove successful authentication. */
struct auth_token_t {
    uint8_t version;
    uint64_t challenge;
    uint64_t user_id; /* not android user id, it is secure user id */
    uint64_t authenticator_id;
    uint32_t authenticator_type;
    uint64_t timestamp;
    uint8_t hmac[HMAC_SIZE];
} __attribute__((__packed__));

TEE_Result gk_get_auth_token_timestamp(uint32_t param_types, TEE_Param *params, const caller_info *caller_info);
bool update_auth_token(uint32_t uid, const uint8_t *auth_token, uint32_t auth_token_len);
bool delete_auth_token(uint32_t uid);

#endif