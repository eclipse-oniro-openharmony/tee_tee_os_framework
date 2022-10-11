/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implement crypto syscall cipher
 * Create: 2022-01-19
 */
#ifndef CRYPTO_SYSCALL_CIPHER_H
#define CRYPTO_SYSCALL_CIPHER_H

#include "crypto_syscall_common.h"

int32_t cipher_init_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t cipher_update_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t cipher_dofinal_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);
int32_t cipher_call(const struct drv_data *drv, unsigned long args, uint32_t args_len,
    const struct crypto_drv_ops_t *ops);

#endif
