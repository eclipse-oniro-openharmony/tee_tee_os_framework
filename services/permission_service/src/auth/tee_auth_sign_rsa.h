/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cms signature auth
 * Create: 2020.11.29
 */

#ifndef GTASK_TEE_AUTH_SIGN_RSA_H
#define GTASK_TEE_AUTH_SIGN_RSA_H

#include "tee_defines.h"
#include <crypto_wrapper.h>

const rsa_pub_key_t *get_cahash_rsa_pub_key(void);

#endif
