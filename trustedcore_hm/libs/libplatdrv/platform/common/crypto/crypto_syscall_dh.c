/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall dh api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_dh.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

static void dh_generate_key_map_init_param0(struct call_params *map_param)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct dh_key_t);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (map_param[0].args[ARG2_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct memref_t);
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void dh_generate_key_map_init_param1(struct call_params *dh_param, const uint64_t *tmp_addr)
{
    dh_param[1].mmaped_ptr_cnt = MMAP_PTR4_INDEX + 1;
    dh_param[1].addr_type = A64;
    if (dh_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        dh_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        dh_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
            ((struct dh_key_t *)(uintptr_t)dh_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime_size;
        dh_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
        dh_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        dh_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct dh_key_t *)(uintptr_t)dh_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator_size;
        dh_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
        dh_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        dh_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct dh_key_t *)(uintptr_t)dh_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.generate_key_t.q_size;
        dh_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (dh_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64) {
        dh_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR3_INDEX];
        dh_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].len =
            ((struct memref_t *)(uintptr_t)dh_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        dh_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (dh_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64) {
        dh_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR4_INDEX];
        dh_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].len =
            ((struct memref_t *)(uintptr_t)dh_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        dh_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void dh_generate_key_map_init_tmp_addr(const struct call_params *map_param, uint64_t *tmp_addr)
{
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime;
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator;
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.generate_key_t.q;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)
        tmp_addr[TMP_ADDR3_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)
        tmp_addr[TMP_ADDR4_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;
}

int32_t dh_generate_key_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (check || map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    dh_generate_key_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    dh_generate_key_map_init_tmp_addr(map_param, tmp_addr);

    dh_generate_key_map_init_param1(map_param, tmp_addr);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:generate access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.generate_key_t.q = map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void dh_generate_key_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *temp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, temp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime =
            temp_addr[TMP_ADDR0_INDEX];
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator =
            temp_addr[TMP_ADDR1_INDEX];
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.generate_key_t.q = temp_addr[TMP_ADDR2_INDEX];
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            temp_addr[TMP_ADDR3_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            temp_addr[TMP_ADDR4_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}

static void dh_derive_key_map_init_param0(struct call_params *derive_key_map_param)
{
    derive_key_map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    derive_key_map_param[0].addr_type = A64;
    if (derive_key_map_param[0].args[ARG0_INDEX] != 0) {
        derive_key_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = derive_key_map_param[0].args[ARG0_INDEX];
        derive_key_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct dh_key_t);
        derive_key_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (derive_key_map_param[0].args[ARG1_INDEX] != 0) {
        derive_key_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = derive_key_map_param[0].args[ARG1_INDEX];
        derive_key_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        derive_key_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void dh_derive_key_map_init_param1(struct call_params *map_param, const uint64_t *tmp_addr)
{
    map_param[1].mmaped_ptr_cnt = MMAP_PTR4_INDEX + 1;
    map_param[1].addr_type = A64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime_size;
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator_size;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.pub_key_size;
        map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
        map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR3_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].len =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.priv_key_size;
        map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64) {
        map_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR4_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void dh_derive_key_map_init_tmp_addr(const struct call_params *map_param, uint64_t *tmp_addr)
{
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime;
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator;
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.pub_key;
        tmp_addr[TMP_ADDR3_INDEX] =
            ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.priv_key;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)
        tmp_addr[TMP_ADDR4_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
}

int32_t dh_derive_key_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *temp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(map_param, map_param_count, temp_addr, tmp_addr_count);
    if (check || map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    dh_derive_key_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    dh_derive_key_map_init_tmp_addr(map_param, temp_addr);
    dh_derive_key_map_init_param1(map_param, temp_addr);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:derive key access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.pub_key =
            map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.priv_key =
            map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64;
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR4_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void dh_derive_key_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64) {
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->prime =
            tmp_addr[TMP_ADDR0_INDEX];
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->generator =
            tmp_addr[TMP_ADDR1_INDEX];
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.pub_key =
            tmp_addr[TMP_ADDR2_INDEX];
        ((struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->
            dh_param.derive_key_t.priv_key =
            tmp_addr[TMP_ADDR3_INDEX];
    }
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR4_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}
