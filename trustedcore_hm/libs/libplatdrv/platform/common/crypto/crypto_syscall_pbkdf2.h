/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall pbkdf2 func.
 * Create: 2020-06-26
 */
#ifndef CRYPTO_SYSCALL_PBKDF2_H
#define CRYPTO_SYSCALL_PBKDF2_H

#include <drv_call_check.h>
#include "crypto_syscall.h"

int32_t pbkdf2_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void pbkdf2_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

#endif
