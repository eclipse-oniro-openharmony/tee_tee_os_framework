/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall cipher func.
 * Create: 2020-06-26
 */
#ifndef CRYPTO_SYSCALL_CIPHER_H
#define CRYPTO_SYSCALL_CIPHER_H

#include <drv_call_check.h>
#include "crypto_syscall.h"

int32_t cipher_init_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void cipher_init_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
int32_t cipher_update_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void cipher_update_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
int32_t cipher_dofinal_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
int32_t cipher_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void cipher_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

#endif
