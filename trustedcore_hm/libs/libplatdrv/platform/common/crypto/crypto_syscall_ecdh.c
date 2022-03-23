/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall ecdh api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_ecdh.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

static void ecdh_derive_key_map_init_param0(struct call_params *map_param)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ecc_pub_key_t);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG2_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct ecc_priv_key_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG3_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = map_param[0].args[ARG3_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct asymmetric_params_t);
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG4_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = map_param[0].args[ARG4_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].len = sizeof(struct memref_t);
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void ecdh_derive_key_map_init_param1(struct call_params *map_param, const uint64_t *tmp_addr)
{
    map_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[1].addr_type = A64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        if (UINT32_MAX / sizeof(struct crypto_attribute_t) >
            ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->
            param_count)
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
                ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->
                param_count * sizeof(struct crypto_attribute_t);
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void ecdh_derive_key_build_param1(const struct call_params *map_param, uint64_t *tmp_addr)
{
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->
            attribute;
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer;
}

int32_t ecdh_derive_key_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (check || map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    ecdh_derive_key_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    ecdh_derive_key_build_param1(map_param, tmp_addr);

    ecdh_derive_key_map_init_param1(map_param, tmp_addr);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->attribute =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void ecdh_derive_key_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct asymmetric_params_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->attribute =
            tmp_addr[TMP_ADDR0_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}
