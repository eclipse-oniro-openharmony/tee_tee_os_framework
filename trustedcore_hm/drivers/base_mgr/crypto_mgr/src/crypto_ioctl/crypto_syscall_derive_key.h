/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implement crypto syscall derive key
 * Create: 2022-01-19
 */
#ifndef CRYPTO_SYSCALL_DERIVE_KEY_H
#define CRYPTO_SYSCALL_DERIVE_KEY_H

#include "crypto_syscall_common.h"

int32_t ecdh_derive_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t dh_generate_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t dh_derive_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t derive_root_key_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t pbkdf2_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);

#endif
