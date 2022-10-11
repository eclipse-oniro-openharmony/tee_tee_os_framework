/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk derive takey2
 * Create: 2022-10-08
 */
#include "huk_derive_takey2.h"
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <mem_ops_ext.h>
#include <crypto_driver_adaptor.h>
#include <crypto_hal_derive_key.h>
#include "huk_derive_takey.h"
#include "huk_service_config.h"

#define KEY_DERIVE_BLOCK_SIZE 16
#define ITER_DERIVE_KEY2_SIZE (KEY_DERIVE_BLOCK_SIZE * 2)
static TEE_Result do_derive_takey2(const uint8_t *salt, uint32_t salt_size,
    uint8_t *key, uint32_t key_size, uint32_t inner_iter_num)
{
    errno_t rc;
    TEE_Result ret;
    uint8_t *tmp_sec = NULL;
    uint32_t tmp_size;

    tmp_size = salt_size + 1; /* add additional 1 byte to store count */
    tmp_sec  = TEE_Malloc(tmp_size, 0);
    if (tmp_sec == NULL) {
        tloge("alloc mem failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    rc = memcpy_s(tmp_sec, tmp_size, salt, salt_size);
    if (rc != EOK) {
        tloge("copy data failed, rc 0x%x\n", rc);
        TEE_Free(tmp_sec);
        return TEE_ERROR_SECURITY;
    }

    for (uint32_t i = 0; i < key_size / KEY_DERIVE_BLOCK_SIZE; i++) {
        tmp_sec[salt_size] = (uint8_t)i;
        ret = do_derive_takey(tmp_sec, tmp_size, key + KEY_DERIVE_BLOCK_SIZE * i,
            KEY_DERIVE_BLOCK_SIZE, inner_iter_num);
        if (ret != TEE_SUCCESS) {
            tloge("derive key for num:%u failed, ret=0x%x\n", i, ret);
            TEE_Free(tmp_sec);
            return ret;
        }
    }

    TEE_Free(tmp_sec);
    return TEE_SUCCESS;
}

static TEE_Result do_derive_takey2_iter(const struct huk_access_table *huk_access, struct memref_t *salt_shard,
    struct memref_t *takey_shared, uint32_t outer_iter_num, uint32_t inner_iter_num)
{
    TEE_Result ret;
    uint32_t salt_tmp_size = salt_shard->size > ITER_DERIVE_KEY2_SIZE ? salt_shard->size : ITER_DERIVE_KEY2_SIZE;
    salt_tmp_size += (uint32_t)sizeof(TEE_UUID);
    uint8_t *salt_tmp = TEE_Malloc(salt_tmp_size, 0);
    if (salt_tmp == NULL) {
        tloge("huk derive takey malloc salt memory failed\n");
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    uint8_t *key_tmp = TEE_Malloc(takey_shared->size, 0);
    if (key_tmp == NULL) {
        tloge("huk derive takey malloc key memory failed\n");
        TEE_Free(salt_tmp);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    errno_t rc = memcpy_s(salt_tmp, salt_tmp_size, (uint8_t *)(uintptr_t)salt_shard->buffer, salt_shard->size);
    if (rc != EOK) {
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    (void)memcpy_s(salt_tmp + salt_shard->size, sizeof(TEE_UUID), &(huk_access->uuid), sizeof(TEE_UUID));
    for (uint32_t i = 0; i < outer_iter_num; i++) {
        ret = do_derive_takey2(salt_tmp, salt_tmp_size, key_tmp, takey_shared->size, inner_iter_num);
        if (ret != TEE_SUCCESS)
            goto clean;

        rc = memcpy_s(salt_tmp, salt_tmp_size, key_tmp, ITER_DERIVE_KEY2_SIZE);
        if (rc != EOK) {
            ret = TEE_ERROR_SECURITY;
            goto clean;
        }
    }

    if (memcpy_s((uint8_t *)(uintptr_t)takey_shared->buffer, takey_shared->size, key_tmp, takey_shared->size) != EOK) {
        tloge("huk copy takey failed\n");
        ret = TEE_ERROR_SECURITY;
    }

clean:
    (void)memset_s(salt_tmp, salt_tmp_size, 0, salt_tmp_size);
    TEE_Free(salt_tmp);
    (void)memset_s(key_tmp, takey_shared->size, 0, takey_shared->size);
    TEE_Free(key_tmp);
    return ret;
}

TEE_Result huk_task_derive_takey2_iter(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    uint64_t vmaddr_salt_shared = 0;
    uint64_t vmaddr_takey_shared = 0;
    TEE_Result ret;

    ret = huk_task_takey_msg_check(msg);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = ret;
        return ret;
    }

    uint32_t key_size = msg->data.takey_msg.key_size;
    uint32_t salt_size = msg->data.takey_msg.salt_size;
    if (key_size < ITER_DERIVE_KEY2_SIZE) {
        rsp->data.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.key_buf, key_size, self_pid, &vmaddr_takey_shared) != 0) {
        tloge("huk service map takey2 buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }

    if (huk_srv_map_from_task(sndr_pid, msg->data.takey_msg.salt_buf, salt_size, self_pid, &vmaddr_salt_shared) != 0) {
        tloge("huk service map salt2 buffer from 0x%x failed\n", sndr_pid);
        huk_srv_task_unmap(vmaddr_takey_shared, key_size);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }

    struct memref_t salt_shared = {0};
    struct memref_t takey_shared = {0};
    salt_shared.buffer = vmaddr_salt_shared;
    salt_shared.size = salt_size;
    takey_shared.buffer = vmaddr_takey_shared;
    takey_shared.size = key_size;
    struct huk_access_table huk_access = { msg->header.send.msg_id, *uuid };
    ret = do_derive_takey2_iter(&huk_access, &salt_shared, &takey_shared,
        msg->data.takey_msg.outer_iter_num, msg->data.takey_msg.inner_iter_num);

    huk_srv_task_unmap(vmaddr_salt_shared, salt_size);
    huk_srv_task_unmap(vmaddr_takey_shared, key_size);
    rsp->data.ret = ret;
    return ret;
}
