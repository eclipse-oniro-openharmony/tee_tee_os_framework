/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk derive key
 * Create: 2022-10-25
 */
#include "huk_derive_key.h"
#include <securec.h>
#include <errno.h>
#include <mem_ops_ext.h>
#include <tee_log.h>
#include "tee_inner_uuid.h"
#include "huk_service_msg.h"
#include "huk_service_msg_call.h"

void *huk_alloc_shared_mem(uint32_t size)
{
    void *p = NULL;
    TEE_UUID uuid = TEE_SERVICE_HUK;

    p = tee_alloc_sharemem_aux(&uuid, size);
    if (p != NULL)
        (void)memset_s(p, size, 0, size);

    return p;
}

void huk_free_shared_mem(uint8_t *p, uint32_t size)
{
    if (p == NULL) {
        tloge("param is null\n");
        return;
    }
    (void)memset_s(p, size, 0, size);
    if (tee_free_sharemem(p, size) != 0)
        tloge("free shared mem failed\n");
}

TEE_Result derive_takey(uint32_t msg_id, const struct meminfo_t *salt_info, struct meminfo_t *takey_info,
    uint32_t outer_iter_num, uint32_t inner_iter_num)
{
    if (salt_info == NULL || takey_info == NULL || salt_info->buffer == 0 || salt_info->size == 0 ||
        salt_info->size > CMAC_DERV_MAX_DATA_IN_SIZE ||  takey_info->buffer == 0 || takey_info->size == 0 ||
        takey_info->size > CMAC_DERV_MAX_DATA_IN_SIZE || outer_iter_num == 0 || inner_iter_num == 0) {
        tloge("derive takey check params failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct huk_srv_msg msg;
    struct huk_srv_rsp rsp;
    (void)memset_s(&msg, sizeof(struct huk_srv_msg), 0, sizeof(struct huk_srv_msg));
    (void)memset_s(&rsp, sizeof(struct huk_srv_msg), 0, sizeof(struct huk_srv_msg));

    uint8_t *salt_shared = huk_alloc_shared_mem(salt_info->size);
    if (salt_shared == NULL) {
        tloge("malloc salt buff shared failed, size = 0x%x\n", salt_info->size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(salt_shared, salt_info->size, (uint8_t *)(uintptr_t)salt_info->buffer, salt_info->size) != EOK) {
        tloge("copy salt failed\n");
        huk_free_shared_mem(salt_shared, salt_info->size);
        return TEE_ERROR_GENERIC;
    }

    uint8_t *takey_shared = huk_alloc_shared_mem(takey_info->size);
    if (takey_shared == NULL) {
        tloge("malloc key buff shared failed, size = 0x%x\n", takey_info->size);
        huk_free_shared_mem(salt_shared, salt_info->size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.data.takey_msg.outer_iter_num = outer_iter_num;
    msg.data.takey_msg.inner_iter_num = inner_iter_num;
    msg.data.takey_msg.salt_buf = (uintptr_t)salt_shared;
    msg.data.takey_msg.salt_size = salt_info->size;
    msg.data.takey_msg.key_buf = (uintptr_t)takey_shared;
    msg.data.takey_msg.key_size = takey_info->size;
    msg.header.send.msg_id = msg_id;

    if (huk_srv_msg_call(&msg, &rsp) < 0 || rsp.data.ret != TEE_SUCCESS) {
        tloge("derive takey msg call failed\n");
        rsp.data.ret = TEE_ERROR_GENERIC;
        goto clean;
    }
    if (memcpy_s((uint8_t *)(uintptr_t)takey_info->buffer, takey_info->size, takey_shared, takey_info->size) != EOK) {
        tloge("copy takey shared failed\n");
        rsp.data.ret = TEE_ERROR_GENERIC;
    }
clean:
    huk_free_shared_mem(salt_shared, salt_info->size);
    huk_free_shared_mem(takey_shared, takey_info->size);
    return rsp.data.ret;
}

/*
 * For compatible platforms, derive the key directly;
 * for new platforms, salt + the uuid obtained from the huk service to be new salt, and then derive the key
 */
TEE_Result tee_internal_derive_key(const uint8_t *salt, uint32_t saltsize, uint8_t *key, uint32_t keysize)
{
    if (salt == NULL || key == NULL || saltsize == 0 || saltsize > CMAC_DERV_MAX_DATA_IN_SIZE ||
        keysize == 0 || keysize > CMAC_DERV_MAX_DATA_IN_SIZE) {
        tloge("derive key check params failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct meminfo_t salt_info = {0};
    struct meminfo_t key_info = {0};
    salt_info.buffer = (uintptr_t)salt;
    salt_info.size = saltsize;
    key_info.buffer = (uintptr_t)key;
    key_info.size = keysize;
    TEE_Result ret = derive_takey(CMD_HUK_DERIVE_TAKEY, &salt_info, &key_info, 1, 1);
    if (ret != TEE_SUCCESS)
        tloge("derive key failed, ret = 0x%x\n", ret);
    return ret;
}
