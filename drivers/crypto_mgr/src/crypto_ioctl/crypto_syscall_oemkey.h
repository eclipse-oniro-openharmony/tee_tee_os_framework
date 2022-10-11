/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: Crypto API at driver adaptor.
 * Create: 2022-01-13
 */
#ifndef CRYPTO_SYSCALL_OEMKEY_H
#define CRYPTO_SYSCALL_OEMKEY_H

#include "crypto_syscall_common.h"

int32_t get_oemkey_call(const struct drv_data *drv, unsigned long args,
    uint32_t args_len, const struct crypto_drv_ops_t *ops);

#endif
