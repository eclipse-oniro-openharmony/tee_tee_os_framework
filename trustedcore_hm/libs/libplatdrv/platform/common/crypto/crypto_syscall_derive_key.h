/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall common func.
 * Create: 2020-11-09
 */
#ifndef CRYPTO_SYSCALL_DERIVE_KEY_H
#define CRYPTO_SYSCALL_DERIVE_KEY_H

#include <stdbool.h>
#include <drv_call_check.h>

int32_t derive_root_key_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

void derive_root_key_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

#endif
