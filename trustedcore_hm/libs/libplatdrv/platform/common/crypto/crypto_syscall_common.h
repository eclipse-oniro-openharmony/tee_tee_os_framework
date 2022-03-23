/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall common func.
 * Create: 2020-06-26
 */
#ifndef CRYPTO_SYSCALL_COMMON_H
#define CRYPTO_SYSCALL_COMMON_H

#include <stdbool.h>
#include <drv_call_check.h>

struct asymmetric_common_t {
    uint32_t access_right;
    size_t struct_size;
};

bool is_map_params_valid(const struct call_params *map_param);

bool check_map_param(const struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);

int32_t common_dofinal_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);

int32_t before_map_check(struct call_params *map_param);

int32_t ctx_copy_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

void map_init_two_param(struct call_params *map_param, const struct asymmetric_common_t *arg1,
    const struct asymmetric_common_t *arg2);

void map_init_three_param(struct call_params *map_param, const struct asymmetric_common_t *arg1,
    const struct asymmetric_common_t *arg2, const struct asymmetric_common_t *arg3);

void map_init_four_param(struct call_params *map_param, const struct asymmetric_common_t *arg1,
    const struct asymmetric_common_t *arg2, const struct asymmetric_common_t *arg3,
    const struct asymmetric_common_t *arg4);

void ctx_copy_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);

int32_t generate_random_map(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);

void generate_random_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);

int32_t build_ctx_map_param(struct call_params *map_param, uint32_t map_param_count);

void asymmetric_map_init_param0(struct call_params *map_param, uint32_t map_param_count, uint32_t access_right,
    size_t struct_size);

void asymmetric_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count, uint32_t access_right);

int32_t asymmetric_common_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count, const struct asymmetric_common_t *asymmetric_common_params);

void asymmetric_common_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);

void common_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

int32_t common_init_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count);

void common_init_map_end(struct call_params *map_param);

int32_t ae_cipher_init_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count);

#endif
