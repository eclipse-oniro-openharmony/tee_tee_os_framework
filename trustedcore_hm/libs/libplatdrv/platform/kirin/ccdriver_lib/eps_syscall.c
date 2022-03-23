/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: hieps driver syscall
 * Create: 2019-12
 */

#include <securec.h>
#include <tee_log.h>
#include <hm_unistd.h>
#include <errno.h>
#include <drv_module.h>
#include <drv_call_check.h>
#include <drv_param_type.h>
#include <sre_syscalls_id.h>
#include <sre_access_control.h>
#include <crypto_syscall.h>
#include <crypto_syscall_common.h>
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990)
#include <api_cipher.h>
#include <cdrm_runtime_env.h>
#include <cdrmr_cipher.h>
#include <cdrmr_hash.h>
#include <cdrmr_hmac.h>
#include <chinadrm.h>
#include <cdrmr_sm2.h>
#endif
#include "eps_adapt.h"

#define CLIENT_SK_MAX_LEN  (2 * 1024)
#define BLKLEN_AES         16
#define IVLEN_AES          16
#define HIGH_ADDRESS_SHIFT 0x20u
#define USR_SP_SHIFT       8
#define EPS_SUPPORT        1
#define EPS_NOT_SUPPORT    0
#define TMP_ADDR_MAX       5
#define SIGN_MODE          0
#define VERIFY_MODE        1

struct syscall_to_api {
    int32_t swi_id;
    int32_t (*crypto_syscall_func)(struct call_params *, uint32_t, uint64_t);
};

static int32_t eps_support_cdrmenhance_call(struct call_params *map_param, uint32_t map_param_count,
    uint64_t ull_permissions)
{
    (void)map_param_count;
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

#ifdef EPS_ENABLE
    ret = eps_support_cdrmenhance() ? EPS_SUPPORT : EPS_NOT_SUPPORT;
#else
    ret = EPS_NOT_SUPPORT;
#endif
    return ret;
}

#ifdef EPS_ENABLE
static int32_t eps_ctl(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    (void)map_param_count;
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    return eps_ctrl((uint32_t)map_param[0].args[ARG0_INDEX], (uint32_t)map_param[0].args[ARG1_INDEX]);
}
#endif

#ifdef EPS_FOR_990
static void eps_sm2_sign_verify_map_init_param0(struct call_params *map_param, uint32_t sign_mode)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    map_param[0].addr_type = A64;

    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        if (sign_mode == SIGN_MODE)
            map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(ECCrefPrivateKey);
        else
            map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(ECCrefPublicKey);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (map_param[0].args[ARG3_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = map_param[0].args[ARG3_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].len = sizeof(ECCSignature);
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static int32_t eps_sm2_sign_verify_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count, uint32_t sign_mode)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL);
    if (check)
        return -1;

    eps_sm2_sign_verify_map_init_param0(map_param, sign_mode);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK)
        tloge("cmd 0x%x:eps sm2 sign param0 access_right check failed\n", map_param[0].swi_id);

    return ret;
}

static void eps_sm2_sign_verify_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;
    unmap_maped_ptrs(&map_param[0]);
}

static int32_t eps_sm2_sign_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm2_sign_verify_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, SIGN_MODE);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm2 sign map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = cdrmr_cipher_sm2_sign((ECCrefPrivateKey *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
        (uint8_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64, map_param[0].args[ARG2_INDEX],
        (ECCSignature *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64);

    eps_sm2_sign_verify_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t eps_sm2_verify_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm2_sign_verify_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX, VERIFY_MODE);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm2 verify map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = cdrmr_cipher_sm2_verify((ECCrefPublicKey *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
        (uint8_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64, map_param[0].args[ARG2_INDEX],
        (ECCSignature *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64);

    eps_sm2_sign_verify_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static void eps_sm2_encrypt_map_init_param0(struct call_params *map_param)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    map_param[0].addr_type = A64;

    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(ECCrefPublicKey);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }

    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }

    if (map_param[0].args[ARG3_INDEX] != 0) {
        uint32_t cipher_len = 0;
        if (map_param[0].args[ARG4_INDEX] < UINT32_MAX - sizeof(ECCCipher))
            cipher_len = sizeof(ECCCipher) + map_param[0].args[ARG4_INDEX];

        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = map_param[0].args[ARG3_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].len = cipher_len;
        map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static int32_t eps_sm2_encrypt_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL);
    if (check)
        return -1;

    eps_sm2_encrypt_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm2 encrypt map param0 access_right check failed\n", map_param[0].swi_id);
        return -1;
    }

    return ret;
}

static void eps_sm2_encrypt_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;
    unmap_maped_ptrs(&map_param[0]);
}


static int32_t eps_sm2_encrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm2_encrypt_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm2 encrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = cdrmr_cipher_sm2_encrypt((ECCrefPublicKey *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
        (uint8_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64,
        (uint32_t)map_param[0].args[ARG2_INDEX],
        (ECCCipher *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64);

    eps_sm2_encrypt_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static void eps_sm2_decrypt_map_init_param0(struct call_params *map_param)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    map_param[0].addr_type = A64;

    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(ECCrefPrivateKey);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }

    if (map_param[0].args[ARG2_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG2_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(uint32_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }

    if (map_param[0].args[ARG3_INDEX] != 0) {
        uint32_t cipher_len = 0;
        if (map_param[0].args[ARG4_INDEX] < UINT32_MAX - sizeof(ECCCipher))
            cipher_len = sizeof(ECCCipher) + map_param[0].args[ARG4_INDEX];

        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = map_param[0].args[ARG3_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = cipher_len;
        map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
}

static void eps_sm2_decrypt_map_init_param1(struct call_params *map_param)
{
    map_param[1].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    map_param[1].addr_type = A64;

    uint32_t input_len = 0;

    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        input_len = *(uint32_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len = input_len;
        map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static int32_t eps_sm2_decrypt_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL);
    if (check)
        return -1;

    eps_sm2_decrypt_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm2 decrypt map param0 access_right check failed\n", map_param[0].swi_id);
        return -1;
    }

    eps_sm2_decrypt_map_init_param1(map_param);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm2 decrypt param1 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return -1;
    }

    return ret;
}

static void eps_sm2_decrypt_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    unmap_maped_ptrs(&map_param[0]);
}

static int32_t eps_sm2_decrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm2_decrypt_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm2 decrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = cdrmr_cipher_sm2_decrypt(
        (ECCrefPrivateKey *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
        (uint8_t *)(uintptr_t)map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
        (uint32_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64,
        (ECCCipher *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64);

    eps_sm2_decrypt_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static void eps_sm4_map_init_param0(struct call_params *map_param)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    map_param[0].addr_type = A64;

    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct cdrm_trans_params);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
}

static void eps_sm4_map_init_param1(struct call_params *map_param, uint64_t *tmp_addr, struct cdrm_trans_params *temp)
{
    map_param[1].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    map_param[1].addr_type = A64;

    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len = temp->pkey_len;
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;

    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len = temp->iv_len;
    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;

    map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len = temp->input_len;
    map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;

    map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR3_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].len = sizeof(uint32_t);
    map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
}

static void eps_sm4_map_init_param2(struct call_params *map_param, uint64_t *tmp_addr)
{
    map_param[MMAP_PTR2_INDEX].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    map_param[MMAP_PTR2_INDEX].addr_type = A64;

    map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR4_INDEX];
    map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].len =
        *(uint32_t *)(uintptr_t)map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64;
    map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
}

static int32_t eps_sm4_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL);
    if (check)
        return -1;

    eps_sm4_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm4 map param0 access_right check failed\n", map_param[0].swi_id);
        return -1;
    }

    struct cdrm_trans_params *temp =
        (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (temp == NULL) {
        unmap_maped_ptrs(&map_param[0]);
        return -1;
    }

    tmp_addr[TMP_ADDR0_INDEX] = temp->pkey;
    tmp_addr[TMP_ADDR1_INDEX] = temp->iv;
    tmp_addr[TMP_ADDR2_INDEX] = temp->input_buffer;
    tmp_addr[TMP_ADDR3_INDEX] = temp->output_len;

    eps_sm4_map_init_param1(map_param, tmp_addr, temp);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        unmap_maped_ptrs(&map_param[0]);
        tloge("cmd 0x%x:eps sm4 map param1 access_right check failed\n", map_param[0].swi_id);
        return -1;
    }

    tmp_addr[TMP_ADDR4_INDEX] = temp->output_buffer;

    eps_sm4_map_init_param2(map_param, tmp_addr);

    ret = before_map_check(&map_param[MMAP_PTR2_INDEX]);
    if (ret != DRV_CALL_OK) {
        unmap_maped_ptrs(&map_param[0]);
        unmap_maped_ptrs(&map_param[1]);
        tloge("cmd 0x%x:eps sm4 map param2 access_right check failed\n", map_param[0].swi_id);
        return -1;
    }

    temp->pkey = map_param[MMAP_PTR1_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    temp->iv = map_param[MMAP_PTR1_INDEX].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    temp->input_buffer = map_param[MMAP_PTR1_INDEX].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
    temp->output_len = map_param[MMAP_PTR1_INDEX].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64;
    temp->output_buffer = map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;

    return ret;
}

static void eps_sm4_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[MMAP_PTR2_INDEX]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0) {
        struct cdrm_trans_params *temp =
            (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
        if (temp == NULL)
            return;

        temp->pkey = tmp_addr[TMP_ADDR0_INDEX];
        temp->iv = tmp_addr[TMP_ADDR1_INDEX];
        temp->input_buffer = tmp_addr[TMP_ADDR2_INDEX];
        temp->output_len = tmp_addr[TMP_ADDR3_INDEX];
        temp->output_buffer = tmp_addr[TMP_ADDR4_INDEX];
    }

    unmap_maped_ptrs(&map_param[1]);
    unmap_maped_ptrs(&map_param[0]);
}

static int32_t eps_sm4_encrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm4_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm4 encrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    struct cdrm_trans_params *temp =
        (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (temp == NULL)
        return -1;

    ret = cdrmr_crypto_symmetric_encrypt((CDRMR_Symmetric_Crypto_Algorithm)map_param[0].args[ARG0_INDEX],
        (unsigned char *)(uintptr_t)temp->pkey, temp->pkey_len, (unsigned char *)(uintptr_t)temp->iv,
        temp->iv_len, (unsigned char *)(uintptr_t)temp->input_buffer, temp->input_len,
        (unsigned char *)(uintptr_t)temp->output_buffer, (uint32_t *)(uintptr_t)temp->output_len);

    eps_sm4_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static int32_t eps_sm4_decrypt_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm4_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm4 decrypt map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    struct cdrm_trans_params *temp =
        (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (temp == NULL)
        return -1;

    ret = cdrmr_crypto_symmetric_decrypt((CDRMR_Symmetric_Crypto_Algorithm)map_param[0].args[ARG0_INDEX],
        (unsigned char *)(uintptr_t)temp->pkey, temp->pkey_len, (unsigned char *)(uintptr_t)temp->iv,
        temp->iv_len, (unsigned char *)(uintptr_t)temp->input_buffer, temp->input_len,
        (unsigned char *)(uintptr_t)temp->output_buffer, (uint32_t *)(uintptr_t)temp->output_len);

    eps_sm4_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static void eps_sm4_config_map_init_param0(struct call_params *map_param)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[0].addr_type = A64;

    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct cdrmr_cipher_user_ctx);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }

    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct cdrm_trans_params);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void eps_sm4_config_map_init_param1(struct call_params *map_param, uint64_t *tmp_addr,
    struct cdrm_trans_params *temp)
{
    if (temp == NULL)
        return;
    map_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[1].addr_type = A64;

    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len = temp->pkey_len;
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;

    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len = temp->iv_len;
    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
}

static int32_t eps_sm4_conifg_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL);
    if (check)
        return -1;

    eps_sm4_config_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm4 config map param0 access_right check failed\n", map_param[0].swi_id);
        return -1;
    }

    struct cdrm_trans_params *temp = NULL;
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0) {
        temp = (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
        if (temp == NULL) {
            unmap_maped_ptrs(&map_param[0]);
            return -1;
        }

        tmp_addr[TMP_ADDR0_INDEX] = temp->pkey;
        tmp_addr[TMP_ADDR1_INDEX] = temp->iv;
    }

    eps_sm4_config_map_init_param1(map_param, tmp_addr, temp);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm4 config map param1 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return -1;
    }

    if (temp != NULL) {
        temp->pkey = map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
        temp->iv = map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    }

    return ret;
}

static void eps_sm4_config_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        struct cdrm_trans_params *temp =
            (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
        temp->pkey = tmp_addr[TMP_ADDR0_INDEX];
        temp->iv = tmp_addr[TMP_ADDR1_INDEX];
    }
    unmap_maped_ptrs(&map_param[0]);
}

static int32_t eps_sm4_config_call(struct call_params *map_param, uint32_t map_param_count, uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm4_conifg_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm4 config map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    struct cdrm_trans_params *temp =
        (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (temp == NULL)
        return -1;

    ret = cdrmr_cipher_config_handle(
        (struct cdrmr_cipher_user_ctx *)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
        (CDRMR_Symmetric_Crypto_Algorithm)temp->alg, (unsigned char *)(uintptr_t)temp->pkey,
        temp->pkey_len, (unsigned char *)(uintptr_t)temp->iv, temp->iv_len);

    eps_sm4_config_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}

static void eps_sm4_cenc_map_init_param1(struct call_params *map_param, uint64_t *tmp_addr,
    struct cdrm_trans_params *temp)
{
    map_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[1].addr_type = A64;

    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len = temp->input_len;
    map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;

    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(uint32_t);
    map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_WRITE_RIGHT;
}

static void eps_sm4_cenc_map_init_param2(struct call_params *map_param, uint64_t *tmp_addr)
{
    map_param[MMAP_PTR2_INDEX].mmaped_ptr_cnt = MMAP_PTR0_INDEX + 1;
    map_param[MMAP_PTR2_INDEX].addr_type = A64;

    map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
    map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].len =
        *(uint32_t *)(uintptr_t)map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
}

static int32_t eps_sm4_cenc_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count) ||
        map_param[0].args == NULL);
    if (check)
        return -1;

    eps_sm4_config_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm4 cenc map param0 access_right check failed\n", map_param[0].swi_id);
        return -1;
    }

    struct cdrm_trans_params *temp =
        (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (temp == NULL) {
        unmap_maped_ptrs(&map_param[0]);
        return -1;
    }

    tmp_addr[TMP_ADDR0_INDEX] = temp->input_buffer;
    tmp_addr[TMP_ADDR1_INDEX] = temp->output_len;

    eps_sm4_cenc_map_init_param1(map_param, tmp_addr, temp);

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm4 cenc map param1 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return -1;
    }

    tmp_addr[TMP_ADDR2_INDEX] = temp->output_buffer;

    eps_sm4_cenc_map_init_param2(map_param, tmp_addr);

    ret = before_map_check(&map_param[MMAP_PTR2_INDEX]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:eps sm4 cenc map param2 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        unmap_maped_ptrs(&map_param[1]);
        return -1;
    }

    temp->input_buffer = map_param[MMAP_PTR1_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    temp->output_len = map_param[MMAP_PTR1_INDEX].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    temp->output_buffer = map_param[MMAP_PTR2_INDEX].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;

    return ret;
}

static void eps_sm4_cenc_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[MMAP_PTR2_INDEX]);

    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        struct cdrm_trans_params *temp =
            (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
        temp->input_buffer = tmp_addr[TMP_ADDR0_INDEX];
        temp->output_len = tmp_addr[TMP_ADDR1_INDEX];
        temp->output_buffer = tmp_addr[TMP_ADDR2_INDEX];
    }

    unmap_maped_ptrs(&map_param[1]);
    unmap_maped_ptrs(&map_param[0]);
}

static int32_t eps_sm4_cenc_decrypt_call(struct call_params *map_param, uint32_t map_param_count,
    uint64_t ull_permissions)
{
    uint64_t tmp_addr[TMP_ADDR_MAX] = {0};
    int32_t ret = check_call_permission(ull_permissions, CC_CRYPTO_GROUP_PERMISSION);
    if (ret != DRV_CALL_OK) {
        tloge("permission denied to access swi_id 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    ret = eps_sm4_cenc_map(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);
    if (ret != DRV_CALL_OK) {
        tloge("eps sm4 cenc map failed 0x%x\n", map_param[0].swi_id);
        return ret;
    }

    struct cdrm_trans_params *temp =
        (struct cdrm_trans_params *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (temp == NULL)
        return -1;

    ret = cdrmr_cipher_cenc_decrypt(
        (struct cdrmr_cipher_user_ctx *)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64,
        (CDRMR_Cenc_Algorithm)temp->alg, (unsigned char *)(uintptr_t)temp->input_buffer,
        temp->input_len, (unsigned char *)(uintptr_t)temp->output_buffer,
        (uint32_t *)(uintptr_t)temp->output_len);

    eps_sm4_cenc_unmap(map_param, map_param_count, tmp_addr, TMP_ADDR_MAX);

    return ret;
}
#endif

const static struct syscall_to_api g_syscall_api[] = {
    { SW_SYSCALL_EPS_SUPPORTCDRMENHANCE,       eps_support_cdrmenhance_call },
#ifdef EPS_ENABLE
    { SW_SYSCALL_CC_EPS_CTRL,                  eps_ctl },
#endif
#ifdef EPS_FOR_990
    { SW_SYSCALL_CC_EPS_SM2_SIGN,              eps_sm2_sign_call },
    { SW_SYSCALL_CC_EPS_SM2_VERIFY,            eps_sm2_verify_call },
    { SW_SYSCALL_CC_EPS_SM2_ENCRYPT,           eps_sm2_encrypt_call },
    { SW_SYSCALL_CC_EPS_SM2_DECRYPT,           eps_sm2_decrypt_call },
    { SW_SYSCALL_CC_EPS_SM4_SYMMETRIC_ENCRYPT, eps_sm4_encrypt_call },
    { SW_SYSCALL_CC_EPS_SM4_SYMMETRIC_DECRYPT, eps_sm4_decrypt_call },
    { SW_SYSCALL_CC_EPS_SM4_CONFIG,            eps_sm4_config_call },
    { SW_SYSCALL_CC_EPS_SM4_CENC_DECRYPT,      eps_sm4_cenc_decrypt_call },
#endif
};

int32_t eps_adapt_driver_syscall(int32_t swi_id, struct drv_param *params, uint64_t permissions)
{
    if (params == NULL || params->args == 0)
        return -1;

    uint64_t *args = (uint64_t *)(uintptr_t)params->args;
    struct call_params map_param[MAP_PARAM_MAX] = {0};

    map_param[0].swi_id = swi_id;
    map_param[0].pid = params->pid;
    map_param[0].self_pid = hm_getpid();
    map_param[0].args = (uint64_t *)(uintptr_t)(params->args);
    map_param[0].job_handler = params->job_handler;

    for (uint32_t i = 1; i < MAP_PARAM_MAX; i++)
        (void)memcpy_s(&map_param[i], sizeof(map_param[i]), &map_param[0], sizeof(map_param[0]));

    bool check = (swi_id < SW_SYSCALL_EPS_SUPPORTCDRMENHANCE || swi_id > SW_SYSCALL_CC_EPS_SM4_CENC_DECRYPT);
    if (check)
        return -1;

    for (size_t i = 0; i < sizeof(g_syscall_api) / sizeof(g_syscall_api[0]); i++) {
        if (swi_id == g_syscall_api[i].swi_id)
            args[ARG0_INDEX] = g_syscall_api[i].crypto_syscall_func(map_param, MAP_PARAM_MAX, permissions);
    }
    return 0;
}

DECLARE_TC_DRV(
    eps_adapt_driver,
    0,
    0,
    0,
    TC_DRV_MODULE_INIT,
    NULL,
    NULL,
    eps_adapt_driver_syscall,
    NULL,
    NULL
);
