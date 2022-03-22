/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall rsa api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_rsa.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

static void rsa_generate_keypair_map_init_param0(struct call_params *map_param, uint32_t map_param_count)
{
    (void)map_param_count;
    map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct memref_t);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG3_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG3_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct rsa_priv_key_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void rsa_generate_keypair_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    (void)map_param_count;
    (void)tmp_addr_count;
    map_param[1].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    map_param[1].addr_type = A64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
}

int32_t rsa_generate_keypair_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    int32_t ret;

    if (map_param == NULL || map_param_count < MAP_PARAM_MAX ||
        tmp_addr == NULL || tmp_addr_count < TMP_ADDR_MAX || map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    rsa_generate_keypair_map_init_param0(map_param, map_param_count);
    if (!is_map_params_valid(&map_param[0])) {
        tloge("cmd 0x%x:Map params is invalid failed\n", map_param[0].swi_id);
        return CRYPTO_BAD_PARAMETERS;
    }
    ret = check_addr_access_right(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:Access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->buffer;

    rsa_generate_keypair_map_init_param1(map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (!is_map_params_valid(&map_param[1])) {
        tloge("cmd 0x%x:Map params is invalid failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }
    ret = check_addr_access_right(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:Access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void rsa_generate_keypair_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX || tmp_addr == NULL ||
        tmp_addr_count < TMP_ADDR_MAX);
    if (check)
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}


int32_t check_rsa_pub_key_len(const struct call_params *map_param, uint32_t map_param_count)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct rsa_pub_key_t *rsa_pub_key =
        (struct rsa_pub_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64);
    if (rsa_pub_key == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (rsa_pub_key->e_len > RSA_EXPONENT_LEN || rsa_pub_key->n_len > RSA_MAX_KEY_SIZE) {
        tloge("rsa key size is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    return DRV_CALL_OK;
}

int32_t check_rsa_private_key_len(const struct call_params *map_param, uint32_t map_param_count, uint32_t index)
{
    bool check_param = (map_param == NULL || map_param_count < MAP_PARAM_MAX || index > (MMAP_PTR_MAX - 1));
    if (check_param)
        return CRYPTO_BAD_PARAMETERS;

    struct rsa_priv_key_t *rsa_private_key =
        (struct rsa_priv_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[index].addr.addr_64);
    if (rsa_private_key == NULL)
        return CRYPTO_BAD_PARAMETERS;

    bool check = (rsa_private_key->e_len > RSA_EXPONENT_LEN ||
        rsa_private_key->n_len > RSA_MAX_KEY_SIZE || rsa_private_key->d_len > RSA_MAX_KEY_SIZE ||
        rsa_private_key->p_len > RSA_MAX_KEY_SIZE_CRT || rsa_private_key->q_len > RSA_MAX_KEY_SIZE_CRT ||
        rsa_private_key->dp_len > RSA_MAX_KEY_SIZE_CRT || rsa_private_key->dq_len > RSA_MAX_KEY_SIZE_CRT ||
        rsa_private_key->qinv_len > RSA_MAX_KEY_SIZE_CRT);
    if (check) {
        tloge("rsa key size is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    return DRV_CALL_OK;
}
