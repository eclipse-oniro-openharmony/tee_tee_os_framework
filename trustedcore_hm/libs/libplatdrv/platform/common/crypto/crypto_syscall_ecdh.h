/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall ecdh func.
 * Create: 2020-06-26
 */
#ifndef CRYPTO_SYSCALL_ECDH_H
#define CRYPTO_SYSCALL_ECDH_H

#include <drv_call_check.h>
#include "crypto_syscall.h"

int32_t ecdh_derive_key_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void ecdh_derive_key_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

#endif
