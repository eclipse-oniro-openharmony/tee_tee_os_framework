/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Crypto API at driver adaptor.
 * Create: 2022-01-13
 */
#ifndef CRYPTO_SYSCALL_EC_H
#define CRYPTO_SYSCALL_EC_H

#include "crypto_syscall_common.h"

int32_t check_ecc_private_key_len(const struct ecc_priv_key_t *ecc_private_key);
int32_t check_ecc_pub_key_len(const struct ecc_pub_key_t *ecc_pub_key);
int32_t ecc_generate_keypair_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_encrypt_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_decrypt_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_sign_digest_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);
int32_t ecc_verify_digest_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);

#endif
