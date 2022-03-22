/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall ecc api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_ecc.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

int32_t ecc_generate_keypair_map(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    int32_t ret;

    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX || tmp_addr == NULL ||
        tmp_addr_count < TMP_ADDR_MAX || map_param[0].args == NULL);
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG2_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ecc_pub_key_t);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (map_param[0].args[ARG3_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG3_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct ecc_priv_key_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (!is_map_params_valid(&map_param[0])) {
        tloge("cmd 0x%x:map params is invalid failed\n", map_param[0].swi_id);
        return CRYPTO_BAD_PARAMETERS;
    }
    ret = check_addr_access_right(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    return DRV_CALL_OK;
}

void ecc_generate_keypair_unmap(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX || tmp_addr == NULL ||
        tmp_addr_count < TMP_ADDR_MAX);
    if (check)
        return;

    unmap_maped_ptrs(&map_param[0]);
}

int32_t check_ecc_pub_key_len(const struct call_params *map_param, uint32_t map_param_count)
{
    if (map_param == NULL || map_param_count < MAP_PARAM_MAX)
        return CRYPTO_BAD_PARAMETERS;

    struct ecc_pub_key_t *ecc_pub_key =
        (struct ecc_pub_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64);
    if (ecc_pub_key == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (ecc_pub_key->x_len > ECC_KEY_LEN || ecc_pub_key->y_len > ECC_KEY_LEN) {
        tloge("ecc key is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    return DRV_CALL_OK;
}

int32_t check_ecc_private_key_len(const struct call_params *map_param, uint32_t map_param_count, uint32_t index)
{
    bool check = (map_param == NULL || map_param_count < MAP_PARAM_MAX || index > (MMAP_PTR_MAX - 1));
    if (check)
        return CRYPTO_BAD_PARAMETERS;

    struct ecc_priv_key_t *ecc_private_key =
        (struct ecc_priv_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[index].addr.addr_64);
    if (ecc_private_key == NULL)
        return CRYPTO_BAD_PARAMETERS;

    if (ecc_private_key->r_len > ECC_KEY_LEN) {
        tloge("ecc key is invalid");
        return CRYPTO_BAD_PARAMETERS;
    }
    return DRV_CALL_OK;
}
