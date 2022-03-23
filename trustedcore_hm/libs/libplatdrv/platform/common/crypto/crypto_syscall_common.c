/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall common api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_common.h"
#include <sre_log.h>
#include "crypto_syscall.h"
#include "crypto_driver_adaptor.h"

bool is_map_params_valid(const struct call_params *map_param)
{
    bool is_valid = false;

    if (map_param == NULL)
        return true;

    for (uint32_t i = 0; i < map_param->mmaped_ptr_cnt; i++) {
        is_valid = (map_param->mmaped_ptrs[i].addr.addr_64 == 0 &&
                    map_param->mmaped_ptrs[i].len == 0) ||
                   (map_param->mmaped_ptrs[i].addr.addr_64 != 0 &&
                    map_param->mmaped_ptrs[i].len != 0);
        if (!is_valid)
            return false;
    }

    return true;
}

bool check_map_param(const struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX ||
        tmp_addr == NULL || tmp_addr_count < TMP_ADDR_MAX);
    return check;
}

int32_t common_dofinal_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *temp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, temp_addr, tmp_addr_count))
        return CRYPTO_BAD_PARAMETERS;

    map_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    map_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(map_param, map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("build ctx failed");
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = temp_addr[TMP_ADDR1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = temp_addr[TMP_ADDR2_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void ctx_copy_map_init_param0(struct call_params *map_param, uint32_t map_param_count)
{
    (void)map_param_count;
    if (map_param[0].args == NULL)
        return;

    map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct ctx_handle_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static int32_t ctx_copy_map_init_param1(struct call_params *map_param, const uint64_t *tmp_addr)
{
    map_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[1].addr_type = A64;

    struct ctx_handle_t *ctx = (struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (ctx != NULL) {
        if (!check_ctx_size(ctx->engine, ctx->alg_type, ctx->ctx_size, ctx->driver_ability)) {
            tloge("context size is invalid");
            return CRYPTO_BAD_PARAMETERS;
        }
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len = ctx->ctx_size;
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }

    ctx = (struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (ctx != NULL) {
        if (!check_ctx_size(ctx->engine, ctx->alg_type, ctx->ctx_size, ctx->driver_ability)) {
            tloge("context size is invalid");
            return CRYPTO_BAD_PARAMETERS;
        }
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len = ctx->ctx_size;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

int32_t before_map_check(struct call_params *map_param)
{
    if (!is_map_params_valid(map_param))
        return CRYPTO_BAD_PARAMETERS;

    return check_addr_access_right(map_param);
}

static void map_init_single_param(struct call_params *map_param, uint32_t args_index,
    uint32_t mmaped_ptrs_index, const struct asymmetric_common_t *arg)
{
    if (map_param->args[args_index] != 0) {
        map_param->mmaped_ptrs[mmaped_ptrs_index].addr.addr_64 = map_param->args[args_index];
        map_param->mmaped_ptrs[mmaped_ptrs_index].len = arg->struct_size;
        map_param->mmaped_ptrs[mmaped_ptrs_index].access_flag = arg->access_right;
    }
}

void map_init_two_param(struct call_params *map_param, const struct asymmetric_common_t *arg1,
    const struct asymmetric_common_t *arg2)
{
    bool check = (map_param == NULL || arg1 == NULL || arg2 == NULL);
    if (check)
        return;
    map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[0].addr_type = A64;
    map_init_single_param(&map_param[0], ARG0_INDEX, MMAP_PTR0_INDEX, arg1);
    map_init_single_param(&map_param[0], ARG1_INDEX, MMAP_PTR1_INDEX, arg2);
}

void map_init_three_param(struct call_params *map_param, const struct asymmetric_common_t *arg1,
    const struct asymmetric_common_t *arg2, const struct asymmetric_common_t *arg3)
{
    bool check = (map_param == NULL || arg1 == NULL || arg2 == NULL || arg3 == NULL);
    if (check)
        return;
    map_param[0].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    map_param[0].addr_type = A64;
    map_init_single_param(&map_param[0], ARG0_INDEX, MMAP_PTR0_INDEX, arg1);
    map_init_single_param(&map_param[0], ARG1_INDEX, MMAP_PTR1_INDEX, arg2);
    map_init_single_param(&map_param[0], ARG2_INDEX, MMAP_PTR2_INDEX, arg3);
}

void map_init_four_param(struct call_params *map_param, const struct asymmetric_common_t *arg1,
    const struct asymmetric_common_t *arg2, const struct asymmetric_common_t *arg3,
    const struct asymmetric_common_t *arg4)
{
    bool check = (map_param == NULL || arg1 == NULL || arg2 == NULL || arg3 == NULL || arg4 == NULL);
    if (check)
        return;
    map_param[0].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    map_param[0].addr_type = A64;
    map_init_single_param(&map_param[0], ARG2_INDEX, MMAP_PTR0_INDEX, arg1);
    map_init_single_param(&map_param[0], ARG3_INDEX, MMAP_PTR1_INDEX, arg2);
    map_init_single_param(&map_param[0], ARG4_INDEX, MMAP_PTR2_INDEX, arg3);
    map_init_single_param(&map_param[0], ARG5_INDEX, MMAP_PTR2_INDEX, arg4);
}

int32_t ctx_copy_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    ctx_copy_map_init_param0(map_param, map_param_count);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->ctx_buffer;

    ret = ctx_copy_map_init_param1(map_param, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->ctx_buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void ctx_copy_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}

int32_t generate_random_map(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX || tmp_addr == NULL ||
        tmp_addr_count < TMP_ADDR_MAX || map_param[0].args == NULL || map_param[0].args[ARG1_INDEX] > UINT32_MAX);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    map_param[0].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
    map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = (uint32_t)map_param[0].args[ARG1_INDEX];
    map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    map_param[0].addr_type = A64;

    int ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    return DRV_CALL_OK;
}

void generate_random_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[0]);
}

int32_t build_ctx_map_param(struct call_params *map_param, uint32_t map_param_count)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ctx_handle_t *ctx = (struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (ctx == NULL) {
        tloge("context is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    if (!check_ctx_size(ctx->engine, ctx->alg_type, ctx->ctx_size, ctx->driver_ability)) {
        tloge("context size is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = ctx->ctx_buffer;
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len = ctx->ctx_size;
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    return CRYPTO_SUCCESS;
}

void asymmetric_map_init_param0(struct call_params *map_param, uint32_t map_param_count,
    uint32_t access_right, size_t struct_size)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX || map_param[0].args == NULL);
    if (check)
        return;

    map_param[0].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = struct_size;
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG2_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct asymmetric_params_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG3_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = map_param[0].args[ARG3_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct memref_t);
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG4_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = map_param[0].args[ARG4_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].len = sizeof(struct memref_t);
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = access_right;
    }
}

void asymmetric_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count, uint32_t access_right)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    map_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    map_param[1].addr_type = A64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        if (UINT32_MAX / sizeof(struct crypto_attribute_t) >
            ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->
            param_count)
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
                ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->
                param_count * sizeof(struct crypto_attribute_t);
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = access_right;
    }
}

int32_t asymmetric_common_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count, const struct asymmetric_common_t *asymmetric_common_params)
{
    bool check = (asymmetric_common_params == NULL || map_param == NULL || map_param_count < MAP_PARAM_MAX ||
        tmp_addr == NULL || tmp_addr_count < TMP_ADDR_MAX || map_param[0].args == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    asymmetric_map_init_param0(map_param, map_param_count, asymmetric_common_params->access_right,
        asymmetric_common_params->struct_size);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->
            attribute;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer;

    asymmetric_map_init_param1(map_param, map_param_count, tmp_addr, tmp_addr_count,
        asymmetric_common_params->access_right);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->attribute =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void asymmetric_common_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->attribute =
            tmp_addr[TMP_ADDR0_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}

void common_init_map_init_param0(struct call_params *map_param, uint32_t map_param_count)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX || map_param[0].args == NULL);
    if (check)
        return;

    map_param[0].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct symmerit_key_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG2_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct ae_init_data);
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
}

int32_t common_init_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return CRYPTO_BAD_PARAMETERS;

    map_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    map_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(map_param, map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("build ctx failed");
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct symmerit_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_size;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct ae_init_data *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->nonce_len;
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

void common_init_map_end(struct call_params *map_param)
{
    if (map_param == NULL)
        return;

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct ae_init_data *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->nonce =
            map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
}

int32_t ae_cipher_init_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) || map_param[0].args == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    common_init_map_init_param0(map_param, map_param_count);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct symmerit_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct ae_init_data *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->nonce;

    ret = common_init_map_init_param1(map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    common_init_map_end(map_param);
    return DRV_CALL_OK;
}
