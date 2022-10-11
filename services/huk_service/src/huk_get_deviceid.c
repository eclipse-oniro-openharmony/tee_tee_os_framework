/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk get deviceid
 * Create: 2022-10-08
 */
#include "huk_get_deviceid.h"
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <mem_ops_ext.h>
#include <tee_private_api.h>
#include <crypto_driver_adaptor.h>
#include <crypto_hal_derive_key.h>
#include <tee_config.h>
#include "huk_derive_takey.h"
#include "huk_service_config.h"

#define TEE_DEVICE_ID_LEN sizeof(TEE_UUID)

static TEE_Result huk_task_deviceid_msg_check(const struct huk_srv_msg *msg)
{
    if ((msg == NULL) || (msg->data.deviceid_msg.buf == 0) ||
        (msg->data.deviceid_msg.size != TEE_DEVICE_ID_LEN)) {
        tloge("huk device id check messages failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    return TEE_SUCCESS;
}

static TEE_Result huk_get_die_id(uint8_t *die_id, uint32_t die_id_size)
{
    TEE_Result ret;

    (void)die_id_size;
    ret = (TEE_Result)tee_ext_get_dieid((uint32_t *)die_id);
    if (ret != TEE_SUCCESS && ret != TEE_ERROR_NOT_SUPPORTED)
        tloge("read efuse die ID failed, ret = 0x%x\n", ret);
    return ret;
}

static TEE_Result huk_derive_key(const uint8_t *salt_buff, uint32_t salt_len, uint8_t *key, uint32_t key_len)
{
    TEE_Result ret;
    struct memref_t salt = {0};
    struct memref_t cmac = {0};

    salt.buffer = (uintptr_t)salt_buff;
    salt.size = salt_len;

    cmac.buffer = (uintptr_t)key;
    cmac.size = key_len;
    ret = (TEE_Result)tee_crypto_derive_root_key(CRYPTO_KEYTYPE_HUK, &salt, &cmac, 1);
    if (ret != TEE_SUCCESS) {
        tloge("huk device id derive failed, ret %x\n", ret);
        return ret;
    }
    return TEE_SUCCESS;
}

TEE_Result huk_task_get_deviceid(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
    uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    uint64_t vmaddr_devid_shared = 0;
    uint8_t dev_id[TEE_DEVICE_ID_LEN] = {0};

    (void)uuid;
    TEE_Result ret = huk_task_deviceid_msg_check(msg);
    if (ret != TEE_SUCCESS) {
        rsp->data.ret = TEE_ERROR_BAD_PARAMETERS;
        return rsp->data.ret;
    }

    uint32_t die_id_size = get_die_id_size();
    if ((die_id_size == INVALID_DIE_ID_SIZE) || (die_id_size > DIE_ID_SIZE_MAX)) {
        tloge("get die id size failed, size is %u\n", die_id_size);
        rsp->data.ret = TEE_ERROR_NOT_SUPPORTED;
        return rsp->data.ret;
    }
    uint8_t *die_id = TEE_Malloc(die_id_size, 0x0);
    if (die_id == NULL) {
        tloge("malloc die id failed!\n");
        rsp->data.ret = TEE_ERROR_OUT_OF_MEMORY;
        return rsp->data.ret;
    }
    uint32_t size = msg->data.deviceid_msg.size;
    if (huk_srv_map_from_task(sndr_pid, msg->data.deviceid_msg.buf, size, self_pid, &vmaddr_devid_shared) != 0) {
        tloge("huk service map device id buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        TEE_Free(die_id);
        return rsp->data.ret;
    }
    ret = huk_get_die_id(die_id, die_id_size);
    if (ret != TEE_SUCCESS)
        goto end_clean;

    ret = huk_derive_key(die_id, die_id_size, dev_id, (uint32_t)sizeof(dev_id));
    if (ret != TEE_SUCCESS)
        goto end_clean;

    if (memcpy_s((uint8_t *)(uintptr_t)vmaddr_devid_shared, size,
                 dev_id, sizeof(dev_id)) != EOK)
        ret = TEE_ERROR_SECURITY;

end_clean:
    huk_srv_task_unmap(vmaddr_devid_shared, size);
    rsp->data.ret = ret;
    (void)memset_s(dev_id, sizeof(dev_id), 0, sizeof(dev_id));
    TEE_Free(die_id);
    return ret;
}
