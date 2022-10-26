/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: huk get device id
 * Create: 2022-10-25
 */
#include "tee_huk_get_device_id.h"
#include "tee_huk_derive_key.h"
#include <securec.h>
#include <errno.h>
#include <mem_ops_ext.h>
#include <tee_log.h>
#include "huk_service_msg.h"
#include "huk_service_msg_call.h"

TEE_Result get_device_id_prop(uint8_t *dst, uint32_t len)
{
    if (dst == NULL || len != sizeof(TEE_UUID)) {
        tloge("invalid param\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    struct huk_srv_msg msg;
    struct huk_srv_rsp rsp;
    (void)memset_s(&msg, sizeof(struct huk_srv_msg), 0, sizeof(struct huk_srv_msg));
    (void)memset_s(&rsp, sizeof(struct huk_srv_msg), 0, sizeof(struct huk_srv_msg));

    uint8_t *dev_id_shared = huk_alloc_shared_mem(len);
    if (dev_id_shared == NULL) {
        tloge("malloc device id buff shared failed, size = 0x%x\n", len);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    msg.data.deviceid_msg.buf = (uintptr_t)dev_id_shared;
    msg.data.deviceid_msg.size = len;
    msg.header.send.msg_id = CMD_HUK_GET_DEVICEID;

    if (huk_srv_msg_call(&msg, &rsp) < 0 || rsp.data.ret != TEE_SUCCESS) {
        tloge("get device id msg call failed\n");
        rsp.data.ret = TEE_ERROR_GENERIC;
        goto clean;
    }
    if (memcpy_s(dst, len, dev_id_shared, len) != EOK) {
        tloge("copy device id shared failed\n");
        rsp.data.ret = TEE_ERROR_GENERIC;
    }
clean:
    huk_free_shared_mem(dev_id_shared, len);
    return rsp.data.ret;
}
