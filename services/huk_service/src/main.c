/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: huk manager task.
 * Author: PengShuai pengshuai@huawei.com
 * Create: 2020-05-22
 */
#include <securec.h>
#include <sys/mman.h>
#include <tee_log.h>
#include <tee_mem_mgmt_api.h>
#include <mem_ops_ext.h>
#include <tee_defines.h>
#include <ac.h>
#include <ac_dynamic.h>
#include <api/errno.h>
#include <sys/usrsyscall.h>
#include <sre_syscalls_ext.h>
#include <ipclib.h>
#include <tamgr_ext.h>
#include <procmgr_ext.h>
#include <tee_private_api.h>
#include <ta_framework.h>
#include <chip_info.h>
#include <tee_ext_api.h>
#include <tee_config.h>
#include <tee_ss_agent_api.h>
#include "huk_derive_takey.h"
#include "huk_get_deviceid.h"
#include "huk_service_msg.h"

#define MAGIC_STR_LEN               20

#define WEAK __attribute__((weak))

#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIX   0x87654321

typedef TEE_Result (*cmd_func)(const struct huk_srv_msg *msg, struct huk_srv_rsp *rsp,
                               uint32_t self_pid, uint32_t sndr_pid, const TEE_UUID *uuid);

struct cmd_operate_config_s {
    uint32_t cmd_id;
    cmd_func operate_func;
};

static cref_t huk_get_mymsghdl(void)
{
    struct hmapi_thread_local_storage *tls = NULL;

    tls = hmapi_tls_get();
    if (tls == NULL)
        return CREF_NULL;

    if (tls->msghdl == 0) {
        cref_t msghdl;
        msghdl = hm_msg_create_hdl();
        if (is_ref_err(msghdl))
            return CREF_NULL;

        tls->msghdl = msghdl;
    }

    return tls->msghdl;
}

static const struct cmd_operate_config_s g_cmd_operate_config[] = {
    { CMD_HUK_DERIVE_TAKEY,         huk_task_derive_takey },
    { CMD_HUK_GET_DEVICEID,         huk_task_get_deviceid },
};
#define CMD_COUNT (sizeof(g_cmd_operate_config) / sizeof(g_cmd_operate_config[0]))

static void handle_cmd(const struct huk_srv_msg *msg, cref_t msghdl, uint32_t sndr_pid,
                       uint16_t msg_type, const TEE_UUID *uuid)
{
    uint32_t cmd_id;
    uint32_t self_pid;
    int32_t rc;
    struct huk_srv_rsp rsp;
    uint32_t i;

    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
    rsp.data.ret = TEE_ERROR_GENERIC;
    cmd_id = msg->header.send.msg_id;
    self_pid = get_selfpid();
    if (self_pid == SRE_PID_ERR) {
        tloge("huk service get self pid error\n");
        rsp.data.ret = TEE_ERROR_GENERIC;
        goto ret_flow;
    }

    for (i = 0; i < CMD_COUNT; i++) {
        if ((cmd_id != g_cmd_operate_config[i].cmd_id) || (g_cmd_operate_config[i].operate_func == NULL))
            continue;
        rsp.data.ret = g_cmd_operate_config[i].operate_func(msg, &rsp, self_pid, sndr_pid, uuid);
        if (rsp.data.ret != TEE_SUCCESS && rsp.data.ret != TEE_ERROR_NOT_SUPPORTED)
            tloge("cmd 0x%x error, ret = 0x%x\n", cmd_id, rsp.data.ret);
        break;
    }
    if (i == CMD_COUNT)
        tloge("the cmd id 0x%x is not supported\n", cmd_id);

ret_flow:
    if (msg_type == HM_MSG_TYPE_CALL) {
        rc = hm_msg_reply(msghdl, &rsp, sizeof(rsp));
        if (rc != 0)
            tloge("reply error 0x%x\n", rc);
    }
}

__attribute__((visibility ("default"))) void tee_task_entry(int init_build)
{
    (void)init_build;
    struct huk_srv_msg msg;
    spawn_uuid_t uuid;
    cref_t ch = 0;
    msginfo_t info = {0};
    int32_t ret_hm;
    struct channel_ipc_args ipc_args = {0};

    (void)memset_s(&msg, sizeof(msg), 0, sizeof(msg));
    cref_t msghdl = huk_get_mymsghdl();
    if (is_ref_err(msghdl) != 0) {
        tloge("Cannot create msg hdl, %s\n", hmapi_strerror((int)msghdl));
        hm_exit((int)msghdl);
    }

    if (hm_create_ipc_native(HUK_PATH, &ch) != 0) {
        tloge("create main thread native channel failed!\n");
        hm_exit(-1);
    }

    if (ac_init_simple() != 0) {
        tloge("ac init error\n");
        hm_exit(-1);
    }

    ret_hm = hm_tamgr_register(HUK_TASK_NAME);
    if (ret_hm != 0) {
        tloge("hm tamgr register fail is %d!\n", ret_hm);
        hm_exit(-1);
    }

    ipc_args.channel = ch;
    ipc_args.recv_buf = &msg;
    ipc_args.recv_len = sizeof(msg);
    while (1) {
        ret_hm = hm_msg_receive(&ipc_args, msghdl, &info, 0, -1);
        if (ret_hm < 0) {
            tloge("huk service: message receive failed, %llx, %s\n", ret_hm, hmapi_strerror(ret_hm));
            continue;
        }

        if (hm_getuuid((pid_t)info.src_cred.pid, &uuid) != 0)
            tloge("huk service get uuid failed\n");

        if (info.src_cred.pid == 0)
            handle_cmd(&msg, msghdl, GLOBAL_HANDLE, info.msg_type, &(uuid.uuid));
        else
            handle_cmd(&msg, msghdl, (uint32_t)hmpid_to_pid(TCBCREF2TID(info.src_tcb_cref), info.src_cred.pid),
                       info.msg_type, &(uuid.uuid));
    }

    tloge("huk service abort!\n");
}
