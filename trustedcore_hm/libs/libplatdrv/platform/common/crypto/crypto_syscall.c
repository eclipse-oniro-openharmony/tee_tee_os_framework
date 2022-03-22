/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implement crypto hal syscall
 * Create: 2020-03-24
 */
#include "crypto_syscall.h"
#include <securec.h>
#include <drv_module.h>
#include <drv_call_check.h>
#include <drv_param_type.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <list.h>
#include <hm_unistd.h>
#include <tee_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_ae.h"
#include "crypto_syscall_cipher.h"
#include "crypto_syscall_common.h"
#include "crypto_syscall_dh.h"
#include "crypto_syscall_ecc.h"
#include "crypto_syscall_ecdh.h"
#include "crypto_syscall_hash.h"
#include "crypto_syscall_hmac.h"
#include "crypto_syscall_pbkdf2.h"
#include "crypto_syscall_rsa.h"
#include "crypto_syscall_derive_key.h"

struct crypto_ops_list_t {
    uint32_t engine;
    const struct crypto_ops_t *ops;
    struct list_head list;
};

static struct list_head g_crypto_ops_head = LIST_HEAD_INIT(g_crypto_ops_head);

static uint32_t change_pkcs5_to_nopad(uint32_t alg_type)
{
    switch (alg_type) {
    case CRYPTO_TYPE_AES_ECB_PKCS5:
        return CRYPTO_TYPE_AES_ECB_NOPAD;
    case CRYPTO_TYPE_AES_CBC_PKCS5:
        return CRYPTO_TYPE_AES_CBC_NOPAD;
    case CRYPTO_TYPE_AES_CBC_MAC_PKCS5:
        return CRYPTO_TYPE_AES_CBC_MAC_NOPAD;
    default:
        break;
    }

    return alg_type;
}

static int32_t get_ctx_size(const struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    uint32_t driver_ability;
    uint32_t alg_type = (uint32_t)map_param[0].args[ARG0_INDEX];

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG1_INDEX])
            continue;
        bool check = (crypto_ops->ops == NULL || crypto_ops->ops->get_ctx_size == NULL);
        if (check)
            break;

        if (crypto_ops->ops->get_driver_ability == NULL)
            driver_ability = 0;
        else
            driver_ability = (uint32_t)(crypto_ops->ops->get_driver_ability());

        if ((driver_ability & DRIVER_PADDING) != DRIVER_PADDING)
            alg_type = change_pkcs5_to_nopad(alg_type);

        return crypto_ops->ops->get_ctx_size(alg_type);
    }

    return 0;
}

static int32_t get_ctx_size_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;

    bool check = (map_param_count < MAP_PARAM_MAX || map_param[0].args[ARG0_INDEX] > UINT32_MAX);
    if (check) {
        tloge("Invalid params\n");
        return 0;
    }

    ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return 0;
    }

    return get_ctx_size(map_param);
}

static int32_t ctx_copy(struct call_params *map_param, uint32_t alg_type, uint32_t src_ctx_size, uint32_t dst_ctx_size)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        bool check = (crypto_ops->ops == NULL || crypto_ops->ops->ctx_copy == NULL);
        if (check)
            break;
        ret = crypto_ops->ops->ctx_copy(alg_type,
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64), src_ctx_size,
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64), dst_ctx_size);
        break;
    }
    return ret;
}

static int32_t ctx_copy_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint32_t alg_type;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    uint32_t src_ctx_size;
    uint32_t dst_ctx_size;
    uint32_t driver_ability;

    if (map_param_count < MAP_PARAM_MAX)
        return CRYPTO_BAD_PARAMETERS;

    ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = ctx_copy_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ctx copy map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0 ||
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 == 0) {
        tloge("ctx copy map failed 0x%x\n", map_param[0].swi_id);
        hash_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    driver_ability =
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->driver_ability;
    if ((driver_ability & DRIVER_PADDING) == DRIVER_PADDING)
        alg_type =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->alg_type;
    else
        alg_type = change_pkcs5_to_nopad(
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->alg_type);

    src_ctx_size =
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_size;
    dst_ctx_size =
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->ctx_size;

    ret = ctx_copy(map_param, alg_type, src_ctx_size, dst_ctx_size);

    ctx_copy_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    return ret;
}

static int32_t do_power_on(const struct crypto_ops_t *ops)
{
    if (ops->power_on == NULL)
        return CRYPTO_SUCCESS;

    return ops->power_on();
}

static void do_power_off(const struct crypto_ops_t *ops)
{
    int32_t ret;
    if (ops->power_off == NULL)
        return;

    ret = ops->power_off();
    if (ret != CRYPTO_SUCCESS)
        tloge("do power off failed, ret = 0x%x\n", ret);
}

static int32_t check_syscall_param(const struct call_params *map_param, uint32_t map_param_count,
    uint64_t ull_permissions)
{
    if (map_param_count < MAP_PARAM_MAX)
        return CRYPTO_BAD_PARAMETERS;

    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK)
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);

    return ret;
}

static int32_t get_driver_ability_call(struct call_params *map_param, uint32_t map_param_count,
    uint64_t ull_permissions)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return 0;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG0_INDEX])
            continue;
        bool check = (crypto_ops->ops == NULL || crypto_ops->ops->get_driver_ability == NULL);
        if (check)
            break;
        return crypto_ops->ops->get_driver_ability();
    }

    return 0;
}

static int32_t hash_init(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        bool check = (crypto_ops->ops == NULL || crypto_ops->ops->hash_init == NULL);
        if (check)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hash_init(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->alg_type);
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t hash_init_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hash_init_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hash init map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("hash init map ctx failed 0x%x\n", map_param[0].swi_id);
        hash_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hash_init(map_param);

    hash_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    return ret;
}

static int32_t hash_update(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        bool check = (crypto_ops->ops == NULL || crypto_ops->ops->hash_update == NULL);
        if (check)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hash_update(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t hash_update_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hash_update_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hash update map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("hash update map failed 0x%x\n", map_param[0].swi_id);
        hash_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hash_update(map_param);

    hash_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    return ret;
}

static int32_t hash_dofinal(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->hash_dofinal == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hash_dofinal(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t hash_dofinal_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hash_dofinal_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hash dofinal map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("hash dofinal map failed 0x%x\n", map_param[0].swi_id);
        hash_dofinal_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hash_dofinal(map_param);

    hash_dofinal_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t hash_fun(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG3_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->hash == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hash(
            (uint32_t)map_param[0].args[ARG0_INDEX],
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t hash_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hash_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hash map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("hash check args failed 0x%x\n", map_param[0].swi_id);
        hash_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hash_fun(map_param);

    hash_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t hmac_init(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->hmac_init == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hmac_init(
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->alg_type,
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct symmerit_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t hmac_init_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hmac_init_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hmac init map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("hmac init map failed 0x%x\n", map_param[0].swi_id);
        hmac_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hmac_init(map_param);

    hmac_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t hmac_update(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->hmac_update == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hmac_update(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t hmac_update_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hmac_update_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hmac update map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("hmac update map failed 0x%x\n", map_param[0].swi_id);
        hmac_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hmac_update(map_param);

    hmac_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t hmac_dofinal(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        bool check = (crypto_ops->ops == NULL || crypto_ops->ops->hmac_dofinal == NULL);
        if (check)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hmac_dofinal(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t hmac_dofinal_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hmac_dofinal_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hmac dofinal map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("hmac dofinal map failed 0x%x\n", map_param[0].swi_id);
        hmac_dofinal_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hmac_dofinal(map_param);

    hmac_dofinal_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t hmac_fun(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG4_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->hmac == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->hmac(
            (uint32_t)map_param[0].args[ARG0_INDEX],
            (struct symmerit_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t hmac_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = hmac_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("hmac map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("hmac check args failed 0x%x\n", map_param[0].swi_id);
        hmac_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hmac_fun(map_param);

    hmac_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t cipher_init(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    uint32_t driver_ability;
    uint32_t alg_type;

    driver_ability =
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->driver_ability;
    if ((driver_ability & DRIVER_PADDING) == DRIVER_PADDING)
        alg_type =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->alg_type;
    else
        alg_type = change_pkcs5_to_nopad(
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->alg_type);

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->cipher_init == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->cipher_init(
            alg_type,
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->direction,
            (struct symmerit_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t cipher_init_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = ae_cipher_init_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("cipher init map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("cipher init map failed 0x%x\n", map_param[0].swi_id);
        cipher_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = cipher_init(map_param);

    cipher_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t cipher_update(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->cipher_update == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->cipher_update(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t cipher_update_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = cipher_update_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("cipher update map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("cipher update map failed 0x%x\n", map_param[0].swi_id);
        cipher_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = cipher_update(map_param);

    cipher_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t cipher_dofinal(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->cipher_dofinal == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->cipher_dofinal(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t cipher_dofinal_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = cipher_dofinal_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("cipher dofinal map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("cipher dofinal map failed 0x%x\n", map_param[0].swi_id);
        cipher_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = cipher_dofinal(map_param);

    cipher_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t cipher_fun(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG6_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->cipher == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->cipher(
            (uint32_t)map_param[0].args[ARG0_INDEX],
            (uint32_t)map_param[0].args[ARG1_INDEX],
            (struct symmerit_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t cipher_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = cipher_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("cipher map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX ||
        map_param[0].args[ARG1_INDEX] > UINT32_MAX) {
        tloge("cipher check args failed 0x%x\n", map_param[0].swi_id);
        cipher_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = cipher_fun(map_param);

    cipher_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ae_init(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ae_init == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ae_init(
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->alg_type,
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->direction,
            (struct symmerit_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct ae_init_data *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t ae_init_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = ae_cipher_init_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ae init map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("ae init map failed 0x%x\n", map_param[0].swi_id);
        ae_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ae_init(map_param);

    ae_init_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ae_update_aad(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ae_update_aad == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ae_update_aad(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }
    return ret;
}

static int32_t ae_update_aad_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = ae_update_aad_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ae update map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("ae update map failed 0x%x\n", map_param[0].swi_id);
        ae_update_aad_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ae_update_aad(map_param);

    ae_update_aad_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ae_update(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ae_update == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ae_update(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ae_update_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = ae_update_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ae update map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("ae update map failed 0x%x\n", map_param[0].swi_id);
        ae_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ae_update(map_param);

    ae_update_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ae_enc_final(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ae_enc_final == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ae_enc_final(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ae_enc_final_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = ae_enc_final_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ae enc final map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("ae enc final map failed 0x%x\n", map_param[0].swi_id);
        ae_final_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ae_enc_final(map_param);

    ae_final_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ae_dec_final(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine !=
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ae_dec_final == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ae_dec_final(
            (void *)(uintptr_t)(map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ae_dec_final_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = ae_dec_final_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ae dec final map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 == 0) {
        tloge("ae dec final map failed 0x%x\n", map_param[0].swi_id);
        ae_final_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ae_dec_final(map_param);

    ae_final_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t rsa_generate_keypair(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG4_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->rsa_generate_keypair == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->rsa_generate_keypair(
            (uint32_t)map_param[0].args[ARG0_INDEX],
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (bool)map_param[0].args[ARG2_INDEX],
            (struct rsa_priv_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t rsa_generate_keypair_call(struct call_params *map_param,
    uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    int32_t ret = rsa_generate_keypair_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("rsa generate keypair map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX ||
        map_param[0].args[ARG2_INDEX] > UINT32_MAX) {
        tloge("rsa generate keypair check args failed 0x%x\n", map_param[0].swi_id);
        rsa_generate_keypair_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    if (check_rsa_private_key_len(map_param, map_param_count, MMAP_PTR1_INDEX) != DRV_CALL_OK) {
        tloge("check rsa key failed\n");
        rsa_generate_keypair_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = rsa_generate_keypair(map_param);

    rsa_generate_keypair_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t rsa_encrypt(struct call_params *rsa_encrypt_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != rsa_encrypt_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->rsa_encrypt == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->rsa_encrypt(
            (uint32_t)rsa_encrypt_param[0].args[ARG0_INDEX],
            (struct rsa_pub_key_t *)(uintptr_t)(rsa_encrypt_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(rsa_encrypt_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_encrypt_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_encrypt_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t rsa_encrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_WRITE_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct rsa_pub_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("rsa encrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("rsa encrypt check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_rsa_pub_key_len(map_param, map_param_count);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa public key failed 0x%x", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = rsa_encrypt(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t rsa_decrypt(struct call_params *rsa_decrypt_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != rsa_decrypt_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->rsa_decrypt == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->rsa_decrypt(
            (uint32_t)rsa_decrypt_param[0].args[ARG0_INDEX],
            (struct rsa_priv_key_t *)(uintptr_t)(rsa_decrypt_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(rsa_decrypt_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_decrypt_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_decrypt_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t rsa_decrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_WRITE_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct rsa_priv_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("rsa decrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("rsa decrypt check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_rsa_private_key_len(map_param, map_param_count, MMAP_PTR0_INDEX);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa private key failed 0x%x\n", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = rsa_decrypt(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t rsa_sign_digest(struct call_params *rsa_sign_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != rsa_sign_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->rsa_sign_digest == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->rsa_sign_digest(
            (uint32_t)rsa_sign_param[0].args[ARG0_INDEX],
            (struct rsa_priv_key_t *)(uintptr_t)(rsa_sign_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(rsa_sign_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_sign_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_sign_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t rsa_sign_digest_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_WRITE_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct rsa_priv_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("rsa sign digest map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("rsa sign digest check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_rsa_private_key_len(map_param, map_param_count, MMAP_PTR0_INDEX);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa private key failed 0x%x\n", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = rsa_sign_digest(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t rsa_verify_digest(struct call_params *rsa_verify_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != rsa_verify_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->rsa_verify_digest == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->rsa_verify_digest(
            (uint32_t)rsa_verify_param[0].args[ARG0_INDEX],
            (struct rsa_pub_key_t *)(uintptr_t)(rsa_verify_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(rsa_verify_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_verify_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(rsa_verify_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t rsa_verify_digest_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_READ_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct rsa_pub_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("rsa verify digest map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("rsa verify digest check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_rsa_pub_key_len(map_param, map_param_count);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa public key failed 0x%x", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = rsa_verify_digest(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ecc_generate_keypair(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG4_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ecc_generate_keypair == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ecc_generate_keypair(
            (uint32_t)map_param[0].args[ARG0_INDEX],
            (uint32_t)map_param[0].args[ARG1_INDEX],
            (struct ecc_pub_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
            (struct ecc_priv_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ecc_generate_keypair_call(struct call_params *map_param,
    uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    int32_t ret = ecc_generate_keypair_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ecc generate keypair map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX || map_param[0].args[ARG1_INDEX] > UINT32_MAX) {
        tloge("ecc generate keypair check args failed 0x%x\n", map_param[0].swi_id);
        ecc_generate_keypair_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    if (check_ecc_pub_key_len(map_param, map_param_count) != DRV_CALL_OK ||
        check_ecc_private_key_len(map_param, map_param_count, MMAP_PTR1_INDEX) != DRV_CALL_OK) {
        tloge("check ecc key failed\n");
        ecc_generate_keypair_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ecc_generate_keypair(map_param);

    ecc_generate_keypair_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ecc_encrypt(struct call_params *ecc_encrypt_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != ecc_encrypt_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ecc_encrypt == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ecc_encrypt(
            (uint32_t)ecc_encrypt_param[0].args[ARG0_INDEX],
            (struct ecc_pub_key_t *)(uintptr_t)(ecc_encrypt_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(ecc_encrypt_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_encrypt_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_encrypt_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ecc_encrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_WRITE_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct ecc_pub_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("ecc encrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("ecc encrypt check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_ecc_pub_key_len(map_param, map_param_count);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa public key failed 0x%x\n", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ecc_encrypt(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ecc_decrypt(struct call_params *ecc_decrypt_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != ecc_decrypt_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ecc_decrypt == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ecc_decrypt(
            (uint32_t)ecc_decrypt_param[0].args[ARG0_INDEX],
            (struct ecc_priv_key_t *)(uintptr_t)(ecc_decrypt_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(ecc_decrypt_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_decrypt_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_decrypt_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ecc_decrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_WRITE_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct ecc_priv_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("ecc decrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("ecc decrypt check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_ecc_private_key_len(map_param, map_param_count, MMAP_PTR0_INDEX);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa public key failed 0x%x", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ecc_decrypt(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ecc_sign_digest(struct call_params *ecc_sign_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != ecc_sign_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ecc_sign_digest == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ecc_sign_digest(
            (uint32_t)ecc_sign_param[0].args[ARG0_INDEX],
            (struct ecc_priv_key_t *)(uintptr_t)(ecc_sign_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(ecc_sign_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_sign_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_sign_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ecc_sign_digest_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_WRITE_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct ecc_priv_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("ecc sign digest map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("ecc sign digest check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_ecc_private_key_len(map_param, map_param_count, MMAP_PTR0_INDEX);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa public key failed 0x%x", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ecc_sign_digest(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ecc_verify_digest(struct call_params *ecc_verify_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != ecc_verify_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ecc_verify_digest == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ecc_verify_digest(
            (uint32_t)ecc_verify_param[0].args[ARG0_INDEX],
            (struct ecc_pub_key_t *)(uintptr_t)(ecc_verify_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(ecc_verify_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_verify_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(ecc_verify_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ecc_verify_digest_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    struct asymmetric_common_t asymmetric_common_params = {0};
    asymmetric_common_params.access_right = ACCESS_READ_RIGHT;
    asymmetric_common_params.struct_size = sizeof(struct ecc_pub_key_t);

    int32_t ret = asymmetric_common_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, &asymmetric_common_params);
    if (ret != DRV_CALL_OK) {
        tloge("ecc verify digest map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("ecc verify digest check args failed 0x%x\n", map_param[0].swi_id);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = check_ecc_pub_key_len(map_param, map_param_count);
    if (ret != DRV_CALL_OK) {
        tloge("check rsa public key failed 0x%x", ret);
        asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ecc_verify_digest(map_param);

    asymmetric_common_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t ecdh_derive_key(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->ecdh_derive_key == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->ecdh_derive_key(
            (uint32_t)map_param[0].args[ARG0_INDEX],
            (struct ecc_pub_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct ecc_priv_key_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (struct asymmetric_params_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t ecdh_derive_key_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = ecdh_derive_key_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("ecdh derive map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("ecdh derive key check args failed 0x%x\n", map_param[0].swi_id);
        ecdh_derive_key_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = ecdh_derive_key(map_param);

    ecdh_derive_key_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t dh_generate_key(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG3_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->dh_generate_key == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->dh_generate_key(
            (struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
            (struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64,
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t dh_generate_key_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = dh_generate_key_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("dh generate map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = dh_generate_key(map_param);

    dh_generate_key_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t dh_derive_key(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG2_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->dh_derive_key == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->dh_derive_key(
            (struct dh_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t dh_derive_key_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = dh_derive_key_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("dh derive key map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = dh_derive_key(map_param);

    dh_derive_key_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static uint8_t g_cached_random[CACHED_RANDOM_SIZE] = {0};
static uint32_t g_used_block_count = TOTAL_RANDOM_BLOCK;

static int32_t hm_do_generate_random(void *buffer, size_t size)
{
    int32_t ret = CRYPTO_NOT_SUPPORTED;
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->ops != NULL && crypto_ops->ops->generate_random != NULL) {
            ret = do_power_on(crypto_ops->ops);
            if (ret != CRYPTO_SUCCESS)
                break;
            ret = crypto_ops->ops->generate_random(buffer, size);
            do_power_off(crypto_ops->ops);
            break;
        }
    }

    return ret;
}

static int32_t generate_random_from_cached(void *buffer, size_t size)
{
    if (g_used_block_count > TOTAL_RANDOM_BLOCK) {
        tloge("Invalid cache block size\n");
        return CRYPTO_BAD_PARAMETERS;
    }

    if (g_used_block_count == TOTAL_RANDOM_BLOCK ||
        size > (TOTAL_RANDOM_BLOCK - g_used_block_count) * ONE_BLOCK_SIZE) {
        (void)memset_s(g_cached_random, sizeof(g_cached_random), 0, sizeof(g_cached_random));
        int32_t ret = hm_do_generate_random(g_cached_random, sizeof(g_cached_random));
        if (ret != CRYPTO_SUCCESS)
            return ret;

        g_used_block_count = 0;
    }

    uint32_t need_block_count = (size % ONE_BLOCK_SIZE == 0) ? (size / ONE_BLOCK_SIZE) : (size / ONE_BLOCK_SIZE + 1);
    errno_t rc = memcpy_s(buffer, size, g_cached_random + g_used_block_count * ONE_BLOCK_SIZE, size);
    if (rc != EOK) {
        tloge("memory copy failed, rc=0x%x\n", rc);
        return CRYPTO_ERROR_SECURITY;
    }

    rc = memset_s(g_cached_random + g_used_block_count * ONE_BLOCK_SIZE,
        sizeof(g_cached_random) - g_used_block_count * ONE_BLOCK_SIZE, 0, size);
    if (rc != EOK)
        tloge("memory set failed, rc=0x%x\n", rc);

    g_used_block_count += need_block_count;

    return CRYPTO_SUCCESS;
}

int32_t hw_generate_random(void *buffer, size_t size)
{
    if (buffer == NULL || size == 0)
        return CRYPTO_BAD_PARAMETERS;

    if (size < CACHED_RANDOM_SIZE)
        return generate_random_from_cached(buffer, size);

    return hm_do_generate_random(buffer, size);
}

static int32_t generate_random_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = generate_random_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("generate random map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG1_INDEX] > UINT32_MAX) {
        tloge("generate random check args failed 0x%x\n", map_param[0].swi_id);
        generate_random_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hw_generate_random((void *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
        (size_t)(map_param[0].args[ARG1_INDEX]));

    generate_random_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    return ret;
}

static int32_t get_entropy_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = generate_random_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("get entropy map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG1_INDEX] > UINT32_MAX) {
        tloge("get entropy check args failed 0x%x\n", map_param[0].swi_id);
        generate_random_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    void *buffer = (void *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64);
    size_t size = (size_t)(map_param[0].args[ARG1_INDEX]);

    ret = CRYPTO_NOT_SUPPORTED;
    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->ops != NULL && crypto_ops->ops->get_entropy != NULL) {
            ret = do_power_on(crypto_ops->ops);
            if (ret != CRYPTO_SUCCESS)
                break;
            ret = crypto_ops->ops->get_entropy(buffer, size);
            do_power_off(crypto_ops->ops);
            break;
        }
    }

    generate_random_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    return ret;
}

int32_t hw_derive_root_key(uint32_t key_type, const struct memref_t *data_in, struct memref_t *data_out)
{
    if (data_in == NULL || data_out == NULL)
        return CRYPTO_BAD_PARAMETERS;

    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->ops != NULL && crypto_ops->ops->derive_root_key != NULL) {
            ret = do_power_on(crypto_ops->ops);
            if (ret != CRYPTO_SUCCESS)
                break;
            ret = crypto_ops->ops->derive_root_key(key_type, data_in, data_out);
            do_power_off(crypto_ops->ops);
            break;
        }
    }
    return ret;
}

#define DX_ROOT_KEY_SIZE 16
static int32_t do_derive_iter(uint32_t key_type, const struct memref_t *temp_in,
    struct memref_t *data_out, uint32_t iter_num)
{
    int32_t ret;

    if (temp_in->size < DX_ROOT_KEY_SIZE)
        return CRYPTO_BAD_PARAMETERS;

    for (uint32_t i = 0; i < iter_num; i++) {
        ret = hw_derive_root_key(key_type, temp_in, data_out);
        if (ret != CRYPTO_SUCCESS)
            break;

        int32_t rc = memcpy_s((uint8_t *)(uintptr_t)temp_in->buffer, temp_in->size,
            (uint8_t *)(uintptr_t)data_out->buffer, data_out->size);
        if (rc != 0) {
            ret = CRYPTO_ERROR_SECURITY;
            break;
        }
    }

    return ret;
}

static int32_t hw_derive_root_key_iter(uint32_t key_type, const struct memref_t *data_in,
    struct memref_t *data_out, uint32_t iter_num)
{
    int32_t ret;

    if (data_in == NULL || data_out == NULL || data_in->size == 0)
        return CRYPTO_BAD_PARAMETERS;

    uint8_t *temp_in_buff = malloc(data_in->size);
    if (temp_in_buff == NULL)
        return CRYPTO_BAD_PARAMETERS;

    (void)memcpy_s(temp_in_buff, data_in->size, (uint8_t *)(uintptr_t)data_in->buffer, data_in->size);
    struct memref_t temp_in = {0};
    temp_in.buffer = (uint64_t)(uintptr_t)temp_in_buff;
    temp_in.size = data_in->size;

    if (iter_num == 1)
        ret = hw_derive_root_key(key_type, &temp_in, data_out);
    else
        ret = do_derive_iter(key_type, &temp_in, data_out, iter_num);

    free(temp_in_buff);
    return ret;
}

static int32_t derive_root_key_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (map_param_count < MAP_PARAM_MAX)
        return CRYPTO_BAD_PARAMETERS;

    ret = check_call_permission(ull_permissions, CC_KEY_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = derive_root_key_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("derive root key map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG0_INDEX] > UINT32_MAX) {
        tloge("derive root key check args failed 0x%x\n", map_param[0].swi_id);
        derive_root_key_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = hw_derive_root_key_iter(
        (uint32_t)map_param[0].args[ARG0_INDEX],
        (const struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
        (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
        (uint32_t)map_param[0].args[ARG3_INDEX]);

    derive_root_key_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t pbkdf2_fun(struct call_params *map_param)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    int32_t ret = CRYPTO_NOT_SUPPORTED;

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != map_param[0].args[ARG5_INDEX])
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->pbkdf2 == NULL)
            break;
        ret = do_power_on(crypto_ops->ops);
        if (ret != CRYPTO_SUCCESS)
            break;
        ret = crypto_ops->ops->pbkdf2(
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64),
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64),
            (uint32_t)map_param[0].args[ARG2_INDEX],
            (uint32_t)map_param[0].args[ARG3_INDEX],
            (struct memref_t *)(uintptr_t)(map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64));
        do_power_off(crypto_ops->ops);
        break;
    }

    return ret;
}

static int32_t pbkdf2_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    int32_t ret;
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};

    if (check_syscall_param(map_param, map_param_count, ull_permissions) != DRV_CALL_OK)
        return CRYPTO_BAD_PARAMETERS;

    ret = pbkdf2_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("pbkdf2 map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    if (map_param[0].args[ARG2_INDEX] > UINT32_MAX ||
        map_param[0].args[ARG3_INDEX] > UINT32_MAX) {
        tloge("pbkdf2 check args failed 0x%x\n", map_param[0].swi_id);
        pbkdf2_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = pbkdf2_fun(map_param);

    pbkdf2_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

#define SWI_ID_INDEX(swi_id) ((swi_id) - SW_SYSCALL_CRYPTO_BASE)
typedef int32_t (*crypto_syscall_func)(struct call_params *map_param,
    uint32_t map_param_count, uint64_t ull_permissions);
static crypto_syscall_func g_crypto_syscall_func_list[] = {
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_GET_CTX_SIZE)]         = get_ctx_size_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_CTX_COPY)]             = ctx_copy_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HASH_INIT)]            = hash_init_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HASH_UPDATE)]          = hash_update_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HASH_DOFINAL)]         = hash_dofinal_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HASH)]                 = hash_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HMAC_INIT)]            = hmac_init_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HMAC_UPDATE)]          = hmac_update_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HMAC_DOFINAL)]         = hmac_dofinal_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_HMAC)]                 = hmac_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_CIPHER_INIT)]          = cipher_init_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_CIPHER_UPDATE)]        = cipher_update_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_CIPHER_DOFINAL)]       = cipher_dofinal_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_CIPHER)]               = cipher_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_AE_INIT)]              = ae_init_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_AE_UPDATE_AAD)]        = ae_update_aad_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_AE_UPDATE)]            = ae_update_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_AE_ENC_FINAL)]         = ae_enc_final_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_AE_DEC_FINAL)]         = ae_dec_final_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_RSA_GENERATE_KEYPAIR)] = rsa_generate_keypair_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_RSA_ENCRYPT)]          = rsa_encrypt_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_RSA_DECRYPT)]          = rsa_decrypt_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_RSA_SIGN_DIGEST)]      = rsa_sign_digest_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_RSA_VERIFY_DIGEST)]    = rsa_verify_digest_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_ECC_GENERATE_KEYPAIR)] = ecc_generate_keypair_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_ECC_ENCRYPT)]          = ecc_encrypt_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_ECC_DECRYPT)]          = ecc_decrypt_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_ECC_SIGN_DIGEST)]      = ecc_sign_digest_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_ECC_VERIFY_DIGEST)]    = ecc_verify_digest_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_ECDH_DERIVE_KEY)]      = ecdh_derive_key_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_DH_GENERATE_KEY)]      = dh_generate_key_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_DH_DERIVE_KEY)]        = dh_derive_key_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_GENERATE_RANDOM)]      = generate_random_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_GET_ENTROPY)]          = get_entropy_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_DERIVE_ROOT_KEY)]      = derive_root_key_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_PBKDF2)]               = pbkdf2_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_GET_DRV_ABILITY)]      = get_driver_ability_call,
    [SWI_ID_INDEX(SW_SYSCALL_CRYPTO_MAX)]                  = NULL,
};

int32_t crypto_driver_syscall(int swi_id, struct drv_param *params, uint64_t ull_permissions)
{
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    struct call_params map_param[MAP_PARAM_MAX] = {0};

    map_param[0].swi_id = swi_id;
    map_param[0].pid = (int32_t)params->pid;
    map_param[0].self_pid = hm_getpid();
    map_param[0].args = (uint64_t *)(uintptr_t)(params->args);
    map_param[0].job_handler = params->job_handler;
    for (uint32_t i = 1; i < MAP_PARAM_MAX; i++)
        (void)memcpy_s(&map_param[i], sizeof(map_param[i]), &map_param[0], sizeof(map_param[0]));

    bool check = (swi_id <= SW_SYSCALL_CRYPTO_BASE || swi_id >= SW_SYSCALL_CRYPTO_MAX ||
        g_crypto_syscall_func_list[SWI_ID_INDEX(swi_id)] == NULL);
    if (check)
        return -1;

    args[ARG0_INDEX] =
        (uint64_t)g_crypto_syscall_func_list[SWI_ID_INDEX(swi_id)](map_param, MAP_PARAM_MAX, ull_permissions);
    return 0;
}

bool check_ctx_size(uint32_t engine, uint32_t alg_type, uint32_t ctx_size, uint32_t driver_ability)
{
    struct list_head *pos = NULL;
    struct crypto_ops_list_t *crypto_ops = NULL;
    uint32_t expected_ctx_size;
    bool ret = false;

    if ((driver_ability & DRIVER_PADDING) != DRIVER_PADDING)
        alg_type = change_pkcs5_to_nopad(alg_type);

    list_for_each(pos, &g_crypto_ops_head) {
        crypto_ops = list_entry(pos, struct crypto_ops_list_t, list);
        if (crypto_ops->engine != engine)
            continue;
        if (crypto_ops->ops == NULL || crypto_ops->ops->get_ctx_size == NULL)
            break;
        expected_ctx_size = (uint32_t)crypto_ops->ops->get_ctx_size(alg_type);
        if (ctx_size == expected_ctx_size)
            ret = true;
        break;
    }
    return ret;
}

int32_t register_crypto_ops(uint32_t engine, const struct crypto_ops_t *ops)
{
    struct crypto_ops_list_t *tmp_ops = NULL;
    tmp_ops = malloc(sizeof(*tmp_ops));
    if (tmp_ops == NULL)
        return -1;
    tmp_ops->engine = engine;
    tmp_ops->ops = ops;
    list_add_tail(&(tmp_ops->list), &g_crypto_ops_head);
    return 0;
}

DECLARE_TC_DRV(
    crypto_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    crypto_driver_syscall,
    NULL,
    NULL
);
