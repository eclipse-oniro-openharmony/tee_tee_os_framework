/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: tee agent common implementation
 * Create: 2022-01-15
 */
#include "tee_service_public.h"
#include <sys/usrsyscall_ext.h>
#include <securec.h>
#include "ta_framework.h"
#include "tee_log.h"
#include "ipclib.h"

void tee_common_ipc_proc_cmd(const char *task_name,
                             uint32_t snd_cmd, const tee_service_ipc_msg *snd_msg,
                             uint32_t ack_cmd, tee_service_ipc_msg_rsp *rsp_msg)
{
    int32_t ret;
    cref_t ch = 0;
    struct tee_service_ipc_msg_req req_msg = {0};

    if (task_name == NULL || snd_msg == NULL || rsp_msg == NULL)
        return;

    (void)ack_cmd;
    req_msg.cmd = snd_cmd;
    errno_t rc = memcpy_s(&req_msg.msg, sizeof(req_msg.msg), snd_msg, sizeof(*snd_msg));
    if (rc != EOK) {
        tloge("msg cpy failed, task=%s, rc=%d\n", task_name, rc);
        return;
    }

    ret = hm_ipc_get_ch_from_path(task_name, &ch);
    if (ret != 0) {
        tloge("get ch from pathmgr failed, task=%s, ret=0x%x\n", task_name, ret);
        return;
    }

    ret = hm_msg_call(ch, &req_msg, sizeof(req_msg), rsp_msg, sizeof(*rsp_msg), 0, HM_NO_TIMEOUT);
    if (ret != 0)
        tloge("msg send to 0x%llx failed: 0x%x\n", ch, ret);

    ret = (int32_t)hm_ipc_release_path(task_name, ch);
    if (ret != 0) {
        tloge("release path failed, task=%s, ret=0x%x\n", task_name, ret);
        return;
    }
}
