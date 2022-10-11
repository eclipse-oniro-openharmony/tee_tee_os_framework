/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: TEE huk srv msg call API.
 * Create: 2022-04-01
 */

#include "huk_service_msg_call.h"

int32_t huk_srv_msg_call(struct huk_srv_msg *msg, struct huk_srv_rsp *rsp)
{
    uint32_t ret;
    uint32_t ss_agent_handle;

    if (msg == NULL || rsp == NULL)
        return HM_ERROR;

    if (ipc_hunt_by_name(0, SSA_SERVICE_NAME, &ss_agent_handle) != 0) {
        tloge("Get ssa handle error\n");
        return HM_ERROR;
    }

    ret = (uint32_t)ipc_msg_snd(msg->header.send.msg_id, ss_agent_handle, msg, sizeof(*msg));
    if (ret != SRE_OK) {
        tloge("msg snd error %x\n", ret);
        return HM_ERROR;
    }

    ret = (uint32_t)ipc_msg_rcv_safe(OS_WAIT_FOREVER, NULL, rsp, sizeof(*rsp), ss_agent_handle);
    if (ret != SRE_OK) {
        tloge("msg rcv error %x\n", ret);
        rsp->data.ret = ret;
    }

    return ret;
}
