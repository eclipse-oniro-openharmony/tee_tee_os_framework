/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cms signature auth
 * Author: wangchunxu1@huawei.com
 * Create: 2020.06.18
 */

#ifndef GTASK_TEE_CMSCBB_H
#define GTASK_TEE_CMSCBB_H

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/obj_mac.h>
#include "cmscbb_sdk.h"
#include "cmscbb_err_def.h"
#include "tee_log.h"

#define SHA256_HASH_LEN 32

typedef struct crypto_md_st {
    SHA256_CTX ctx;
    CVB_UINT32 hash_algo;
} gt_crypto_md;

typedef struct crypto_vrf_st {
    gt_crypto_md md_ctx;
    RSA *rsa_key;
} gt_crypto_vrf;

#endif
