/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: TEE huk API.
 * Author: PengShuai pengshuai@huawei.com
 * Create: 2020-05-22
 */
#include "tee_internal_huk_api.h"
#include <securec.h>
#include <errno.h>
#include <mem_ops_ext.h>
#include <tee_defines.h>
#include <ipclib.h>
#include <sys/usrsyscall_ext.h>
#include <tee_log.h>
#include <tee_ext_api.h>
#include <tee_crypto_api.h>
#include <ta_framework.h>
#include "huk_service_msg.h"
#include "huk_service_msg_call.h"


static inline void huk_free_shared_mem(void *p, uint32_t size)
{
    if (p == NULL)
        return;

    (void)memset_s(p, size, 0, size);
    if (tee_free_sharemem(p, size) != 0)
        tloge("free shared mem failed\n");
}

static inline void *huk_alloc_shared_mem(uint32_t size)
{
    void *p = NULL;
    TEE_UUID uuid = TEE_SERVICE_HUK;

    p = tee_alloc_sharemem_aux(&uuid, size);
    if (p != NULL)
        (void)memset_s(p, size, 0, size);

    return p;
}

static void huk_init_srv_msg(struct huk_srv_msg *msg, struct huk_srv_rsp *rsp)
{
    if (msg != NULL)
        (void)memset_s(msg, sizeof(*msg), 0, sizeof(*msg));

    if (rsp != NULL)
        (void)memset_s(rsp, sizeof(*rsp), 0, sizeof(*rsp));
}

static TEE_Result derive_takey(uint32_t msg_id, const struct meminfo_t *salt_info, struct meminfo_t *takey_info,
    uint32_t outer_iter_num, uint32_t inner_iter_num)
{
    struct huk_srv_msg msg;
    struct huk_srv_rsp rsp;
    uint8_t *takey_shared = NULL;
    uint8_t *salt_shared = NULL;

    huk_init_srv_msg(&msg, &rsp);
    salt_shared = huk_alloc_shared_mem(salt_info->size);
    if (salt_shared == NULL) {
        tloge("malloc salt buff shared failed, size = 0x%x\n", salt_info->size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    if (memcpy_s(salt_shared, salt_info->size, (uint8_t *)(uintptr_t)salt_info->buffer, salt_info->size) != EOK) {
        tloge("copy salt failed\n");
        huk_free_shared_mem(salt_shared, salt_info->size);
        return TEE_ERROR_SECURITY;
    }

    takey_shared = huk_alloc_shared_mem(takey_info->size);
    if (takey_shared == NULL) {
        tloge("malloc key buff shared failed, size = 0x%x\n", takey_info->size);
        huk_free_shared_mem(salt_shared, takey_info->size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.data.takey_msg.outer_iter_num = outer_iter_num;
    msg.data.takey_msg.inner_iter_num = inner_iter_num;
    msg.header.send.msg_id = msg_id;
    msg.data.takey_msg.salt_buf = (uintptr_t)salt_shared;
    msg.data.takey_msg.salt_size = salt_info->size;
    msg.data.takey_msg.key_buf = (uintptr_t)takey_shared;
    msg.data.takey_msg.key_size = takey_info->size;
    rsp.data.ret = TEE_ERROR_GENERIC;

    if (huk_srv_msg_call(&msg, &rsp) < 0)
        goto takey_clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (memcpy_s((uint8_t *)(uintptr_t)takey_info->buffer, takey_info->size,
            takey_shared, takey_info->size) != EOK)
            rsp.data.ret = TEE_ERROR_SECURITY;
    }
takey_clean:
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
    TEE_Result ret;

    if (salt == NULL || key == NULL) {
        tloge("params are null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (saltsize == 0 || saltsize > CMAC_DERV_MAX_DATA_IN_SIZE || keysize == 0) {
        tloge("invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct meminfo_t salt_info = {0};
    struct meminfo_t key_info = {0};
    salt_info.buffer = (uintptr_t)salt;
    salt_info.size = saltsize;
    key_info.buffer = (uintptr_t)key;
    key_info.size = keysize;
    ret = derive_takey(CMD_HUK_DERIVE_TAKEY, &salt_info, &key_info, 1, 1);
    if (ret != TEE_SUCCESS)
        return ret;

    return TEE_SUCCESS;
}

TEE_Result get_device_id_prop(uint8_t *dst, uint32_t len)
{
    struct huk_srv_msg msg;
    struct huk_srv_rsp rsp;
    uint8_t *dev_id_shared = NULL;

    huk_init_srv_msg(&msg, &rsp);
    if (dst == NULL || len != sizeof(TEE_UUID)) {
        tloge("invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    dev_id_shared = huk_alloc_shared_mem(len);
    if (dev_id_shared == NULL) {
        tloge("malloc device id buff shared failed, size = 0x%x\n", len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    msg.header.send.msg_id = CMD_HUK_GET_DEVICEID;
    msg.data.deviceid_msg.buf = (uintptr_t)dev_id_shared;
    msg.data.deviceid_msg.size = len;
    rsp.data.ret = TEE_ERROR_GENERIC;

    if (huk_srv_msg_call(&msg, &rsp) < 0)
        goto takey_clean;

    if (rsp.data.ret == TEE_SUCCESS) {
        if (memcpy_s(dst, len, dev_id_shared, len) != EOK)
            rsp.data.ret = TEE_ERROR_SECURITY;
    }

takey_clean:
    huk_free_shared_mem(dev_id_shared, len);
    return rsp.data.ret;
}
