/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall common api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_hash.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

int32_t hash_init_map(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count) ||
        hash_map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hash_map_param[0].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    hash_map_param[0].addr_type = A64;
    if (hash_map_param[0].args[ARG0_INDEX] != 0) {
        hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = hash_map_param[0].args[ARG0_INDEX];
        hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }

    int32_t ret = before_map_check(&hash_map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac init map 0 access_right check failed\n", hash_map_param[0].swi_id);
        return ret;
    }

    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;

    hash_map_param[1].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    hash_map_param[1].addr_type = A64;

    ret = build_ctx_map_param(hash_map_param, hash_map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&hash_map_param[0]);
        return ret;
    }

    ret = before_map_check(&hash_map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hash init map 1 access_right check failed\n", hash_map_param[0].swi_id);
        unmap_maped_ptrs(&hash_map_param[0]);
        return ret;
    }

    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void hash_init_unmap(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hash_map_param[1]);
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    unmap_maped_ptrs(&hash_map_param[0]);
}

static void hash_update_map_build_param0(struct call_params *hash_map_param)
{
    struct asymmetric_common_t args0 = { 0 };
    struct asymmetric_common_t args1 = { 0 };
    args0.struct_size = sizeof(struct ctx_handle_t);
    args0.access_right = ACCESS_WRITE_RIGHT;
    args1.struct_size = sizeof(struct memref_t);
    args1.access_right = ACCESS_READ_RIGHT;

    map_init_two_param(hash_map_param, &args0, &args1);
}

static int32_t hash_update_map_init_param1(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    const uint64_t *tmp_addr)
{
    int32_t ret = build_ctx_map_param(hash_map_param, hash_map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("build ctx failed");
        return ret;
    }

    hash_map_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    hash_map_param[1].addr_type = A64;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

int32_t hash_update_map(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count) ||
        hash_map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hash_update_map_build_param0(hash_map_param);

    int32_t ret = before_map_check(&hash_map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:update map 0 access_right check failed\n", hash_map_param[0].swi_id);
        return ret;
    }

    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;

    ret = hash_update_map_init_param1(hash_map_param, hash_map_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&hash_map_param[0]);
        return ret;
    }

    ret = before_map_check(&hash_map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hash update map 1 access_right check failed\n", hash_map_param[0].swi_id);
        unmap_maped_ptrs(&hash_map_param[0]);
        return ret;
    }

    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void hash_update_unmap(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *temp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, temp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hash_map_param[1]);
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            temp_addr[TMP_ADDR0_INDEX];
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            temp_addr[TMP_ADDR1_INDEX];
    unmap_maped_ptrs(&hash_map_param[0]);
}

static void hash_dofinal_map_build_param0(struct call_params *hash_map_param)
{
    struct asymmetric_common_t arg0 = { 0 };
    struct asymmetric_common_t arg1 = { 0 };
    struct asymmetric_common_t arg2 = { 0 };
    arg0.struct_size = sizeof(struct ctx_handle_t);
    arg0.access_right = ACCESS_WRITE_RIGHT;
    arg1.struct_size = sizeof(struct memref_t);
    arg1.access_right = ACCESS_READ_RIGHT;
    arg2.struct_size = sizeof(struct memref_t);
    arg2.access_right = ACCESS_WRITE_RIGHT;

    map_init_three_param(hash_map_param, &arg0, &arg1, &arg2);
}

static void hash_dofinal_map_end(struct call_params *hash_map_param)
{
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
}

int32_t hash_dofinal_map(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count) ||
        hash_map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hash_dofinal_map_build_param0(hash_map_param);

    int32_t ret = before_map_check(&hash_map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", hash_map_param[0].swi_id);
        return ret;
    }

    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;

    ret = common_dofinal_map_init_param1(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&hash_map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&hash_map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", hash_map_param[0].swi_id);
        unmap_maped_ptrs(&hash_map_param[0]);
        return ret;
    }

    hash_dofinal_map_end(hash_map_param);

    return DRV_CALL_OK;
}

void hash_dofinal_unmap(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hash_map_param[1]);
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&hash_map_param[0]);
}

static void hash_map_init_param0(struct call_params *hash_map_param)
{
    hash_map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    hash_map_param[0].addr_type = A64;
    if (hash_map_param[0].args[ARG1_INDEX] != 0) {
        hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = hash_map_param[0].args[ARG1_INDEX];
        hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct memref_t);
        hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (hash_map_param[0].args[ARG2_INDEX] != 0) {
        hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = hash_map_param[0].args[ARG2_INDEX];
        hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void hash_map_init_param1(struct call_params *hash_map_param, const uint64_t *tmp_addr)
{
    hash_map_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    hash_map_param[1].addr_type = A64;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0) {
        hash_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        hash_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->size;
        hash_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}
int32_t hash_map(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count) ||
        hash_map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hash_map_init_param0(hash_map_param);

    int32_t ret = before_map_check(&hash_map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac map 0 access_right check failed\n", hash_map_param[0].swi_id);
        return ret;
    }

    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->buffer;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;

    hash_map_init_param1(hash_map_param, tmp_addr);

    ret = before_map_check(&hash_map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac map 1 access_right check failed\n", hash_map_param[0].swi_id);
        unmap_maped_ptrs(&hash_map_param[0]);
        return ret;
    }

    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            hash_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void hash_unmap(struct call_params *hash_map_param, uint32_t hash_map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hash_map_param, hash_map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hash_map_param[1]);
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hash_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    unmap_maped_ptrs(&hash_map_param[0]);
}
