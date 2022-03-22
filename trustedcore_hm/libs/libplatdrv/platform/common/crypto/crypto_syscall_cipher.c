/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall cipher api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_cipher.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

static int32_t cipher_init_map_init_param1(struct call_params *cipher_param, uint32_t cipher_param_count,
    const uint64_t *tmp_addr)
{
    cipher_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    cipher_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(cipher_param, cipher_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher init map init build ctx failed");
        return ret;
    }

    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        struct symmerit_key_t *cipher_key =
            (struct symmerit_key_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
        cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len = cipher_key->key_size;
        cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void cipher_init_map_end(struct call_params *cipher_mapparam)
{
    if (cipher_mapparam[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)cipher_mapparam[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            cipher_mapparam[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (cipher_mapparam[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)cipher_mapparam[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer =
            cipher_mapparam[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (cipher_mapparam[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_mapparam[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            cipher_mapparam[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
}

static void cipher_init_map_build_param0(struct call_params *cipher_param)
{
    struct asymmetric_common_t args1 = { 0 };
    struct asymmetric_common_t args2 = { 0 };
    struct asymmetric_common_t args3 = { 0 };
    args1.struct_size = sizeof(struct ctx_handle_t);
    args1.access_right = ACCESS_WRITE_RIGHT;
    args2.struct_size = sizeof(struct symmerit_key_t);
    args2.access_right = ACCESS_READ_RIGHT;
    args3.struct_size = sizeof(struct memref_t);
    args3.access_right = ACCESS_READ_RIGHT;

    map_init_three_param(cipher_param, &args1, &args2, &args3);
}

int32_t cipher_init_map(struct call_params *cipher_param, uint32_t cipher_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(cipher_param, cipher_param_count, tmp_addr, tmp_addr_count);
    if (check || cipher_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    cipher_init_map_build_param0(cipher_param);

    int32_t ret = before_map_check(&cipher_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher init map 0 access_right check failed\n", cipher_param[0].swi_id);
        return ret;
    }

    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct symmerit_key_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;

    ret = cipher_init_map_init_param1(cipher_param, cipher_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&cipher_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&cipher_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher init map 1 access_right check failed\n", cipher_param[0].swi_id);
        unmap_maped_ptrs(&cipher_param[0]);
        return ret;
    }

    cipher_init_map_end(cipher_param);
    return DRV_CALL_OK;
}

void cipher_init_unmap(struct call_params *cipher_param, uint32_t cipher_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(cipher_param, cipher_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&cipher_param[1]);
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&cipher_param[0]);
}

static int32_t cipher_update_map_init_param1(struct call_params *cipher_param, uint32_t cipher_param_count,
    const uint64_t *tmp_addr)
{
    cipher_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    cipher_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(cipher_param, cipher_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("cipher update map init build ctx failed");
        return ret;
    }

    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void cipher_update_map_end(struct call_params *cipher_param)
{
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            cipher_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
}

static void cipher_update_final_map_build_param0(struct call_params *cipher_param)
{
    struct asymmetric_common_t args0 = { 0 };
    struct asymmetric_common_t args1 = { 0 };
    struct asymmetric_common_t args2 = { 0 };
    args0.struct_size = sizeof(struct ctx_handle_t);
    args0.access_right = ACCESS_WRITE_RIGHT;
    args1.struct_size = sizeof(struct memref_t);
    args1.access_right = ACCESS_READ_RIGHT;
    args2.struct_size = sizeof(struct memref_t);
    args2.access_right = ACCESS_WRITE_RIGHT;

    map_init_three_param(cipher_param, &args0, &args1, &args2);
}

int32_t cipher_update_map(struct call_params *map_param, uint32_t cipher_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, cipher_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    cipher_update_final_map_build_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher update map 0 access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;

    ret = cipher_update_map_init_param1(map_param, cipher_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher update map 1 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    cipher_update_map_end(map_param);

    return DRV_CALL_OK;
}

void cipher_update_unmap(struct call_params *cipher_param, uint32_t cipher_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(cipher_param, cipher_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&cipher_param[1]);
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&cipher_param[0]);
}

int32_t cipher_dofinal_map(struct call_params *cipher_param, uint32_t cipher_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(cipher_param, cipher_param_count, tmp_addr, tmp_addr_count) ||
        cipher_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    cipher_update_final_map_build_param0(cipher_param);

    int32_t ret = before_map_check(&cipher_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher dofinal map 0 access_right check failed\n", cipher_param[0].swi_id);
        return ret;
    }

    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;

    ret = common_dofinal_map_init_param1(cipher_param, cipher_param_count, tmp_addr, tmp_addr_count);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&cipher_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&cipher_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher dofinal map 1 access_right check failed\n", cipher_param[0].swi_id);
        unmap_maped_ptrs(&cipher_param[0]);
        return ret;
    }

    cipher_update_map_end(cipher_param);

    return DRV_CALL_OK;
}

static void cipher_map_build_param0(struct call_params *cipher_param)
{
    struct asymmetric_common_t args1 = { 0 };
    struct asymmetric_common_t args2 = { 0 };
    struct asymmetric_common_t args3 = { 0 };
    struct asymmetric_common_t args4 = { 0 };

    args1.struct_size = sizeof(struct symmerit_key_t);
    args1.access_right = ACCESS_READ_RIGHT;
    args2.struct_size = sizeof(struct memref_t);
    args2.access_right = ACCESS_READ_RIGHT;
    args3.struct_size = sizeof(struct memref_t);
    args3.access_right = ACCESS_READ_RIGHT;
    args4.struct_size = sizeof(struct memref_t);
    args4.access_right = ACCESS_WRITE_RIGHT;

    map_init_four_param(cipher_param, &args1, &args2, &args3, &args4);
}

static void cipher_map_init_tmp_addr(const struct call_params *cipher_param, uint64_t *tmp_addr)
{
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct symmerit_key_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_buffer;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR3_INDEX] =
            ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer;
}

static void cipher_map_init_param1(struct call_params *mapinit_param, const uint64_t *tmp_addr)
{
    mapinit_param[1].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    mapinit_param[1].addr_type = A64;
    if (mapinit_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0) {
        mapinit_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        mapinit_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
            ((struct symmerit_key_t *)(uintptr_t)mapinit_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_size;
        mapinit_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (mapinit_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        mapinit_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        mapinit_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)mapinit_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        mapinit_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (mapinit_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        mapinit_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        mapinit_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)mapinit_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        mapinit_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (mapinit_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0) {
        mapinit_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR3_INDEX];
        mapinit_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].len =
            ((struct memref_t *)(uintptr_t)mapinit_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->size;
        mapinit_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

int32_t cipher_map(struct call_params *cipher_param, uint32_t cipher_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(cipher_param, cipher_param_count, tmp_addr, tmp_addr_count) ||
        cipher_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    cipher_map_build_param0(cipher_param);

    int32_t ret = before_map_check(&cipher_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher map 0 access_right check failed\n", cipher_param[0].swi_id);
        return ret;
    }

    cipher_map_init_tmp_addr(cipher_param, tmp_addr);
    cipher_map_init_param1(cipher_param, tmp_addr);

    ret = before_map_check(&cipher_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:cipher map 1 access_right check failed\n", cipher_param[0].swi_id);
        unmap_maped_ptrs(&cipher_param[0]);
        return ret;
    }

    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_buffer =
            cipher_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            cipher_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            cipher_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            cipher_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void cipher_unmap(struct call_params *cipher_param, uint32_t cipher_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(cipher_param, cipher_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&cipher_param[1]);
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    if (cipher_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)cipher_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR3_INDEX];
    unmap_maped_ptrs(&cipher_param[0]);
}
