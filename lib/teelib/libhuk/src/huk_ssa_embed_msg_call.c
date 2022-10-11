/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: TEE huk srv msg call API.
 * Create: 2022-04-01
 */

#include <tee_log.h>
#include <sys/usrsyscall_ext.h>
#include "huk_service_msg_call.h"
#include "ssa_snd_msg.h"
#include "tee_init.h"
#include "tee_inner_uuid.h"

int32_t huk_srv_msg_call(struct huk_srv_msg *msg, struct huk_srv_rsp *rsp)
{
    int32_t ret;
    uint32_t ss_agent_handle;

    if (msg == NULL || rsp == NULL)
        return HM_ERROR;

    ss_agent_handle = get_global_handle();
    ret = (int32_t)send_msg_to_ssa(msg->header.send.msg_id, msg, sizeof(*msg));
    if (ret != SRE_OK) {
        tloge("msg snd error %x\n", ret);
        return HM_ERROR;
    }

    ret = (int32_t)ipc_msg_rcv_safe(OS_WAIT_FOREVER, NULL, rsp, sizeof(*rsp), ss_agent_handle);
    if (ret != SRE_OK) {
        tloge("msg rcv error %x\n", ret);
        rsp->data.ret = ret;
    }

    return ret;
}
