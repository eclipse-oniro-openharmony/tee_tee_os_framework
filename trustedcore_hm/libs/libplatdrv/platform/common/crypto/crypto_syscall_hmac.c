/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Api for crypto syscall hmac api.
 * Create: 2020-06-26
 */
#include "crypto_syscall_hmac.h"
#include <sre_log.h>
#include "crypto_driver_adaptor.h"
#include "crypto_syscall_common.h"

static void hmac_init_map_init_param0(struct call_params *hmac_param)
{
    hmac_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    hmac_param[0].addr_type = A64;
    if (hmac_param[0].args[ARG0_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = hmac_param[0].args[ARG0_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (hmac_param[0].args[ARG1_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = hmac_param[0].args[ARG1_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct symmerit_key_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
}

static int32_t hmac_init_map_init_param1(struct call_params *init_param, uint32_t hmac_param_count,
    const uint64_t *tmp_addr)
{
    init_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    init_param[1].addr_type = A64;
    int32_t ret = build_ctx_map_param(init_param, hmac_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("build ctx failed");
        return ret;
    }
    if (init_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        init_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        init_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct symmerit_key_t *)(uintptr_t)init_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_size;
        init_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void hmac_init_build_param1(const struct call_params *hmac_param, uint64_t *tmp_addr)
{
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct symmerit_key_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer;
}

int32_t hmac_init_map(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count) ||
        hmac_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hmac_init_map_init_param0(hmac_param);

    int32_t ret = before_map_check(&hmac_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac init map 0 access_right check failed\n", hmac_param[0].swi_id);
        return ret;
    }

    hmac_init_build_param1(hmac_param, tmp_addr);

    ret = hmac_init_map_init_param1(hmac_param, hmac_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&hmac_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&hmac_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac initt map 1 access_right check failed\n", hmac_param[0].swi_id);
        unmap_maped_ptrs(&hmac_param[0]);
        return ret;
    }

    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void hmac_init_unmap(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hmac_param[1]);
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->key_buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    unmap_maped_ptrs(&hmac_param[0]);
}

static void hmac_update_map_init_param0(struct call_params *hmac_update_param)
{
    hmac_update_param[0].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    hmac_update_param[0].addr_type = A64;
    if (hmac_update_param[0].args[ARG0_INDEX] != 0) {
        hmac_update_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = hmac_update_param[0].args[ARG0_INDEX];
        hmac_update_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        hmac_update_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (hmac_update_param[0].args[ARG1_INDEX] != 0) {
        hmac_update_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = hmac_update_param[0].args[ARG1_INDEX];
        hmac_update_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        hmac_update_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
}

static int32_t hmac_update_map_init_param1(struct call_params *hmac_param, uint32_t hmac_param_count,
    const uint64_t *tmp_addr)
{
    hmac_param[1].mmaped_ptr_cnt = MMAP_PTR1_INDEX + 1;
    hmac_param[1].addr_type = A64;
    int32_t ret = build_ctx_map_param(hmac_param, hmac_param_count);
    if (ret != CRYPTO_SUCCESS) {
        tloge("build ctx failed");
        return ret;
    }
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    return CRYPTO_SUCCESS;
}

static void hmac_update_build_param1(const struct call_params *hmac_param, uint64_t *tmp_addr)
{
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
}

int32_t hmac_update_map(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count) ||
        hmac_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hmac_update_map_init_param0(hmac_param);

    int32_t ret = before_map_check(&hmac_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac update map 0 access_right check failed\n", hmac_param[0].swi_id);
        return ret;
    }

    hmac_update_build_param1(hmac_param, tmp_addr);

    ret = hmac_update_map_init_param1(hmac_param, hmac_param_count, tmp_addr);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&hmac_param[0]);
        return ret;
    }

    ret = before_map_check(&hmac_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac update init 1 access_right check failed\n", hmac_param[0].swi_id);
        unmap_maped_ptrs(&hmac_param[0]);
        return ret;
    }

    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void hmac_update_unmap(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *temp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, temp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hmac_param[1]);
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            temp_addr[TMP_ADDR0_INDEX];
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            temp_addr[TMP_ADDR1_INDEX];
    unmap_maped_ptrs(&hmac_param[0]);
}

static void hmac_dofinal_map_init_param0(struct call_params *hmac_param)
{
    hmac_param[0].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    hmac_param[0].addr_type = A64;
    if (hmac_param[0].args[ARG0_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = hmac_param[0].args[ARG0_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct ctx_handle_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
    if (hmac_param[0].args[ARG1_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = hmac_param[0].args[ARG1_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (hmac_param[0].args[ARG2_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = hmac_param[0].args[ARG2_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct memref_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void hmac_dofinal_map_end(struct call_params *hmac_param)
{
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;
}

static void hmac_dofinal_build_param1(const struct call_params *hmac_param, uint64_t *tmp_addr)
{
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;
}

int32_t hmac_dofinal_map(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count) ||
        hmac_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hmac_dofinal_map_init_param0(hmac_param);

    int32_t ret = before_map_check(&hmac_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac map 0 access_right check failed\n", hmac_param[0].swi_id);
        return ret;
    }

    hmac_dofinal_build_param1(hmac_param, tmp_addr);

    ret = common_dofinal_map_init_param1(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count);
    if (ret != CRYPTO_SUCCESS) {
        unmap_maped_ptrs(&hmac_param[0]);
        return CRYPTO_BAD_PARAMETERS;
    }

    ret = before_map_check(&hmac_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac final map 1 access_right check failed\n", hmac_param[0].swi_id);
        unmap_maped_ptrs(&hmac_param[0]);
        return ret;
    }

    hmac_dofinal_map_end(hmac_param);

    return DRV_CALL_OK;
}

void hmac_dofinal_unmap(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hmac_param[1]);
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct ctx_handle_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->ctx_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&hmac_param[0]);
}

static void hmac_map_init_param0(struct call_params *hmac_param)
{
    hmac_param[0].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    hmac_param[0].addr_type = A64;
    if (hmac_param[0].args[ARG1_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = hmac_param[0].args[ARG1_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].len = sizeof(struct symmerit_key_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (hmac_param[0].args[ARG2_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = hmac_param[0].args[ARG2_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].len = sizeof(struct memref_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (hmac_param[0].args[ARG3_INDEX] != 0) {
        hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = hmac_param[0].args[ARG3_INDEX];
        hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].len = sizeof(struct memref_t);
        hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void hmac_map_init_param1(struct call_params *hmac_param, const uint64_t *tmp_addr)
{
    hmac_param[1].mmaped_ptr_cnt = MMAP_PTR2_INDEX + 1;
    hmac_param[1].addr_type = A64;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0) {
        hmac_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR0_INDEX];
        hmac_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].len =
            ((struct symmerit_key_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_size;
        hmac_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0) {
        hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR1_INDEX];
        hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].len =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->size;
        hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].access_flag = ACCESS_READ_RIGHT;
    }
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0) {
        hmac_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 = tmp_addr[TMP_ADDR2_INDEX];
        hmac_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].len =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->size;
        hmac_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].access_flag = ACCESS_WRITE_RIGHT;
    }
}

static void hmac_build_param1(const struct call_params *hmac_param, uint64_t *tmp_addr)
{
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR0_INDEX] =
            ((struct symmerit_key_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_buffer;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR1_INDEX] =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        tmp_addr[TMP_ADDR2_INDEX] =
            ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer;
}

int32_t hmac_map(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count) ||
        hmac_param[0].args == NULL)
        return CRYPTO_BAD_PARAMETERS;

    hmac_map_init_param0(hmac_param);

    int32_t ret = before_map_check(&hmac_param[0]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac map 0 access_right check failed\n", hmac_param[0].swi_id);
        return ret;
    }

    hmac_build_param1(hmac_param, tmp_addr);

    hmac_map_init_param1(hmac_param, tmp_addr);

    ret = before_map_check(&hmac_param[1]);
    if (ret != DRV_CALL_OK) {
        tloge("cmd 0x%x:hmac map 1 access_right check failed\n", hmac_param[0].swi_id);
        unmap_maped_ptrs(&hmac_param[0]);
        return ret;
    }

    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64;
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            hmac_param[1].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64;

    return DRV_CALL_OK;
}

void hmac_unmap(struct call_params *hmac_param, uint32_t hmac_param_count,
    uint64_t *tmp_addr, uint32_t tmp_addr_count)
{
    if (check_map_param(hmac_param, hmac_param_count, tmp_addr, tmp_addr_count))
        return;

    unmap_maped_ptrs(&hmac_param[1]);
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64 != 0)
        ((struct symmerit_key_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR0_INDEX].addr.addr_64)->key_buffer =
            tmp_addr[TMP_ADDR0_INDEX];
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR1_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR1_INDEX];
    if (hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64 != 0)
        ((struct memref_t *)(uintptr_t)hmac_param[0].mmaped_ptrs[MMAP_PTR2_INDEX].addr.addr_64)->buffer =
            tmp_addr[TMP_ADDR2_INDEX];
    unmap_maped_ptrs(&hmac_param[0]);
}
