/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall dh func.
 * Create: 2020-06-26
 */
#ifndef CRYPTO_SYSCALL_DH_H
#define CRYPTO_SYSCALL_DH_H

#include <drv_call_check.h>
#include "crypto_syscall.h"

int32_t dh_generate_key_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void dh_generate_key_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
int32_t dh_derive_key_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void dh_derive_key_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

#endif
