/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall rsa func.
 * Create: 2020-06-26
 */
#ifndef CRYPTO_SYSCALL_RSA_H
#define CRYPTO_SYSCALL_RSA_H

#include <drv_call_check.h>
#include "crypto_syscall.h"

int32_t rsa_generate_keypair_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);
void rsa_generate_keypair_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);
int32_t check_rsa_pub_key_len(const struct call_params *map_param, uint32_t map_param_count);
int32_t check_rsa_private_key_len(const struct call_params *map_param, uint32_t map_param_count, uint32_t index);
#endif
