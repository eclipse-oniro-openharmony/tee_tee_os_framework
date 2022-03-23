/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall ae api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_ae.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

static int32_t ae_init_map_init_param1(struct call_params *ae_map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr)
{
    ae_map_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    ae_map_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(ae_map_param, map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("build ctx failed");
        return ret;
    }

    if (ae_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        ae_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        ae_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct symmerit_key_t *)(uintptr_t)ae_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_size;
        ae_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (ae_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        ae_map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        ae_map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct ae_init_data *)(uintptr_t)ae_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->nonce_len;
        ae_map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void ae_init_map_build_param0(struct call_params *map_param)
{
    struct asymmetric_common_t args1 = { 0 };
    struct asymmetric_common_t args2 = { 0 };
    struct asymmetric_common_t args3 = { 0 };
    args1.struct_size = sizeof(struct ctx_handle_t);
    args1.access_right = ACCESS_WRITE_RIGHT;
    args2.struct_size = sizeof(struct symmerit_key_t);
    args2.access_right = ACCESS_READ_RIGHT;
    args3.struct_size = sizeof(struct ae_init_data);
    args3.access_right = ACCESS_READ_RIGHT;

    map_init_three_param(map_param, &args1, &args2, &args3);
}

static void ae_init_build_param1(const struct call_params *map_param, uint64_t *tmp_addr)
{
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct symmerit_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct ae_init_data *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->nonce;
}

int32_t ae_init_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (check || map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    ae_init_map_build_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae init map 0 access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    ae_init_build_param1(map_param, tmp_addr);

    ret = ae_init_map_init_param1(map_param, map_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae map init 1 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    common_init_map_end(map_param);

    return DRV_CALL_OK;
}

void ae_init_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct ae_init_data *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->nonce =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}

static void ae_update_aad_map_init_param0(struct call_params *map_param)
{
    map_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[0].addr_type = A64;
    if (map_param[0].args[ARG0_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = map_param[0].args[ARG0_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (map_param[0].args[ARG1_INDEX] != 0) {
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = map_param[0].args[ARG1_INDEX];
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
}

static int32_t ae_update_aad_map_init_param1(struct call_params *map_param, uint32_t map_param_count,
    const uint64_t *tmp_addr)
{
    map_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    map_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(map_param, map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Build CTX Failed");
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void ae_update_aad_build_param1(const struct call_params *map_param, uint64_t *tmp_addr)
{
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
}

int32_t ae_update_aad_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (check || map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    ae_update_aad_map_init_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae update aad map 0 access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    ae_update_aad_build_param1(map_param, tmp_addr);

    ret = ae_update_aad_map_init_param1(map_param, map_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae update aad map 1 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void ae_update_aad_unmap(struct call_params *update_aad_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(update_aad_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&update_aad_param[1]);
    if (update_aad_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)update_aad_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (update_aad_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)update_aad_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    unmap_maped_ptrs(&update_aad_param[0]);
}

static int32_t ae_update_map_init_param1(struct call_params *ae_update_param, uint32_t map_param_count,
    const uint64_t *tmp_addr)
{
    ae_update_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    ae_update_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(ae_update_param, map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Build ctx failed");
        return ret;
    }
    if (ae_update_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        ae_update_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        ae_update_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_update_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        ae_update_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (ae_update_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        ae_update_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        ae_update_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_update_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        ae_update_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void ae_update_map_end(struct call_params *map_param)
{
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
}

static void ae_update_map_build_param0(struct call_params *map_param)
{
    struct asymmetric_common_t args1 = { 0 };
    struct asymmetric_common_t args2 = { 0 };
    struct asymmetric_common_t args3 = { 0 };
    args1.struct_size = sizeof(struct ctx_handle_t);
    args1.access_right = ACCESS_WRITE_RIGHT;
    args2.struct_size = sizeof(struct memref_t);
    args2.access_right = ACCESS_READ_RIGHT;
    args3.struct_size = sizeof(struct memref_t);
    args3.access_right = ACCESS_WRITE_RIGHT;

    map_init_three_param(map_param, &args1, &args2, &args3);
}

static void ae_update_build_param1(const struct call_params *update_param, uint64_t *tmp_addr)
{
    if (update_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)update_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (update_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)update_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (update_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)update_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;
}

int32_t ae_update_map(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (check || map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    ae_update_map_build_param0(map_param);

    int32_t ret = before_map_check(&map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae update map 0 access_right check failed\n", map_param[0].swi_id);
        return ret;
    }

    ae_update_build_param1(map_param, tmp_addr);

    ret = ae_update_map_init_param1(map_param, map_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae update map 1 access_right check failed\n", map_param[0].swi_id);
        unmap_maped_ptrs(&map_param[0]);
        return ret;
    }

    ae_update_map_end(map_param);
    return DRV_CALL_OK;
}

void ae_update_unmap(struct call_params *unmap_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(unmap_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&unmap_param[1]);
    if (unmap_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)unmap_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (unmap_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)unmap_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (unmap_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)unmap_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&unmap_param[0]);
}

static void ae_final_map_init_tmp_addr(const struct call_params *map_param, uint64_t *tmp_addr)
{
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR3_INDEX] =
            ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer;
}

static void ae_enc_final_map_init_param0(struct call_params *enc_final_param)
{
    enc_final_param[0].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    enc_final_param[0].addr_type = A64;
    if (enc_final_param[0].args[ARG0_INDEX] != 0) {
        enc_final_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = enc_final_param[0].args[ARG0_INDEX];
        enc_final_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        enc_final_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (enc_final_param[0].args[ARG1_INDEX] != 0) {
        enc_final_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = enc_final_param[0].args[ARG1_INDEX];
        enc_final_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        enc_final_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (enc_final_param[0].args[ARG2_INDEX] != 0) {
        enc_final_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = enc_final_param[0].args[ARG2_INDEX];
        enc_final_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct memref_t);
        enc_final_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (enc_final_param[0].args[ARG3_INDEX] != 0) {
        enc_final_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = enc_final_param[0].args[ARG3_INDEX];
        enc_final_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].len = sizeof(struct memref_t);
        enc_final_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static int32_t ae_enc_final_map_init_param1(struct call_params *ae_enc_param, uint32_t map_param_count,
    const uint64_t *tmp_addr)
{
    ae_enc_param[1].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    ae_enc_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(ae_enc_param, map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("Build ctx failed");
        return ret;
    }
    if (ae_enc_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_enc_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (ae_enc_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_enc_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (ae_enc_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0) {
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR3_INDEX];
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_enc_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->size;
        ae_enc_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

int32_t ae_enc_final_map(struct call_params *ae_enc_map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(ae_enc_map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (check || ae_enc_map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    ae_enc_final_map_init_param0(ae_enc_map_param);

    int32_t ret = before_map_check(&ae_enc_map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae enc final map 0 access_right check failed\n", ae_enc_map_param[0].swi_id);
        return ret;
    }

    ae_final_map_init_tmp_addr(ae_enc_map_param, tmp_addr);

    ret = ae_enc_final_map_init_param1(ae_enc_map_param, map_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&ae_enc_map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&ae_enc_map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae enc final map 1 access_right check failed\n", ae_enc_map_param[0].swi_id);
        unmap_maped_ptrs(&ae_enc_map_param[0]);
        return ret;
    }

    if (ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            ae_enc_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            ae_enc_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            ae_enc_map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
    if (ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)ae_enc_map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            ae_enc_map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void ae_final_unmap(struct call_params *map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(map_param, map_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&map_param[1]);
    if (map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    if (map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR3_INDEX];
    unmap_maped_ptrs(&map_param[0]);
}

static void ae_dec_final_map_init_param0(struct call_params *dec_final_param)
{
    dec_final_param[0].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    dec_final_param[0].addr_type = A64;
    if (dec_final_param[0].args[ARG0_INDEX] != 0) {
        dec_final_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = dec_final_param[0].args[ARG0_INDEX];
        dec_final_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        dec_final_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (dec_final_param[0].args[ARG1_INDEX] != 0) {
        dec_final_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = dec_final_param[0].args[ARG1_INDEX];
        dec_final_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        dec_final_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (dec_final_param[0].args[ARG2_INDEX] != 0) {
        dec_final_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = dec_final_param[0].args[ARG2_INDEX];
        dec_final_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct memref_t);
        dec_final_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (dec_final_param[0].args[ARG3_INDEX] != 0) {
        dec_final_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = dec_final_param[0].args[ARG3_INDEX];
        dec_final_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].len = sizeof(struct memref_t);
        dec_final_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static int32_t ae_dec_final_map_init_param1(struct call_params *ae_dec_param, uint32_t map_param_count,
    const uint64_t *tmp_addr)
{
    ae_dec_param[1].mmaped_ptr_cnt = MMAP_PTR3_INDEX + 1;
    ae_dec_param[1].addr_type = A64;

    int32_t ret = build_ctx_map_param(ae_dec_param, map_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("build ctx failed");
        return ret;
    }
    if (ae_dec_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_dec_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (ae_dec_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_dec_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (ae_dec_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0) {
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR3_INDEX];
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].len =
            ((struct memref_t *)(uintptr_t)ae_dec_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->size;
        ae_dec_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

int32_t ae_dec_final_map(struct call_params *ae_dec_map_param, uint32_t map_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    bool check = check_map_param(ae_dec_map_param, map_param_count, tmp_addr, tmp_addr_count);
    if (check || ae_dec_map_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    ae_dec_final_map_init_param0(ae_dec_map_param);

    int32_t ret = before_map_check(&ae_dec_map_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae dec final map 0 access_right check failed\n", ae_dec_map_param[0].swi_id);
        return ret;
    }

    ae_final_map_init_tmp_addr(ae_dec_map_param, tmp_addr);

    ret = ae_dec_final_map_init_param1(ae_dec_map_param, map_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&ae_dec_map_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&ae_dec_map_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:ae dec final map 1 access_right check failed\n", ae_dec_map_param[0].swi_id);
        unmap_maped_ptrs(&ae_dec_map_param[0]);
        return ret;
    }

    if (ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            ae_dec_map_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            ae_dec_map_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            ae_dec_map_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
    if (ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)ae_dec_map_param[0].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64)->buffer =
            ae_dec_map_param[1].mmaped_ptrs[MMAP_PTR3_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}
