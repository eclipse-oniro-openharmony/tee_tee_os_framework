/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk provision key
 * Create: 2022-10-08
 */
#include "huk_provision_key.h"
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <mem_ops_ext.h>
#include <crypto_driver_adaptor.h>
#include <crypto_hal_derive_key.h>
#include <oemkey.h>
#include "huk_derive_takey.h"
#include "huk_service_config.h"

TEE_Result huk_task_provision_key(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
                                         uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid)
{
    TEE_Result ret;
    errno_t rc;
    uint64_t vmaddr = 0;
    uint8_t key_temp[AES_CMAC_RESULT_SIZE_IN_BYTES] = {0};
    uint32_t size = msg->data.provisionkey_msg.size;
    if (msg == NULL || msg->data.provisionkey_msg.buf == 0 || size < AES_CMAC_RESULT_SIZE_IN_BYTES) {
        tloge("huk provision key invalid msg\n");
        rsp->data.ret = TEE_ERROR_BAD_PARAMETERS;
        return rsp->data.ret;
    }

    if (!check_huk_access_permission(msg->header.send.msg_id, uuid)) {
        tloge("can not access this\n");
        rsp->data.ret = TEE_ERROR_ACCESS_DENIED;
        return rsp->data.ret;
    }
    if (huk_srv_map_from_task(sndr_pid, msg->data.provisionkey_msg.buf, size, self_pid, &vmaddr) != 0) {
        tloge("huk service map provision key buffer from 0x%x failed\n", sndr_pid);
        rsp->data.ret = TEE_ERROR_GENERIC;
        return rsp->data.ret;
    }
    ret = (TEE_Result)tee_hal_get_provision_key(key_temp, AES_CMAC_RESULT_SIZE_IN_BYTES);
    if (ret != TEE_SUCCESS) {
        tloge("huk get provision key failed, %x\n", ret);
    } else {
        rc = memcpy_s((uint8_t *)(uintptr_t)vmaddr, size, key_temp, AES_CMAC_RESULT_SIZE_IN_BYTES);
        if (rc != EOK)
            ret = TEE_ERROR_SECURITY;
        rsp->data.provisionkey_rsp.size = AES_CMAC_RESULT_SIZE_IN_BYTES;
    }
    (void)memset_s(key_temp, sizeof(key_temp), 0, sizeof(key_temp));
    huk_srv_task_unmap(vmaddr, size);
    rsp->data.ret = ret;
    return ret;
}
