/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2021. All rights reserved.
 * Description: tee common public service implementation
 * Create: 2019-08-19
 */

#include "tee_commom_public_service.h"
#include <sys/mman.h>
#include <msg_ops.h>
#include <mem_ops_ext.h> // __task_unmap_from_ns_page
#include <sys/usrsyscall_ext.h>
#include <sys/hmapi_ext.h>
#include <api/kcalls.h>
#include <procmgr_ext.h>
#include "tee_init.h"
#include "tee_ext_api.h"
#include "tee_log.h"
#include "tee_init.h"
#include "securec.h"
#include "ipclib.h"
#include "tee_c_env.h"
#include "tee_internal_task_pub.h"

#define WEAK            __attribute__((weak))
#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIC   0x87654321

uint32_t WEAK g_ta_bss_start = BSS_START_MAGIC; // Unified rectification
uint32_t WEAK g_ta_bss_end   = BSS_END_MAGIC;   // Unified rectification

typedef void (*func_ptr)(void);

static void _init()
{
#ifndef CONFIG_DYNLINK
    func_ptr *func = NULL;
    for (func = __init_array_start; func < __init_array_end; func++)
        (*func)();
#endif
}

static void clear_ta_bss(void)
{
#ifndef CONFIG_DYNLINK
    UINT32 *ta_bss_start = &g_ta_bss_start;
    UINT32 *ta_bss_end   = &g_ta_bss_end;
    int sret;

    if (g_ta_bss_start == BSS_START_MAGIC && g_ta_bss_end == BSS_END_MAGIC) {
        tlogd("only weak bss define\n");
        return;
    }

    if (ta_bss_end > ta_bss_start) {
        sret = memset_s((void *)ta_bss_start, ta_bss_end - ta_bss_start, 0, ta_bss_end - ta_bss_start);
        if (sret != EOK)
            tloge("elf _s fail, sret = %d\n", sret);
    } else {
        tloge("bss end <= bss start\n");
    }
#endif
}

TEE_Result tee_common_get_uuid_by_sender(uint32_t sender, TEE_UUID *uuid, uint32_t buffer_size)
{
    spawn_uuid_t sender_uuid;

    if (uuid == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (buffer_size < sizeof(TEE_UUID))
        return TEE_ERROR_BAD_PARAMETERS;

    int32_t ret = hm_getuuid((pid_t)pid_to_hmpid(sender), &sender_uuid);
    if (ret != 0) {
        tloge("get uuid from hm failed, sender is 0x%x\n", sender);
        return TEE_ERROR_ITEM_NOT_FOUND;
    }
    errno_t rc = memcpy_s(uuid, buffer_size, &sender_uuid.uuid, sizeof(sender_uuid.uuid));
    if (rc != EOK) {
        tloge("copy uuid to dest failed, rc=%d\n", rc);
        return TEE_ERROR_GENERIC;
    }
    return TEE_SUCCESS;
}

int tee_map_from_task(uint32_t in_task_id, uint32_t va_addr, uint32_t size, uint32_t *virt_addr)
{
    uint64_t vaddr = 0;
    int ret;

    if (virt_addr == NULL)
        return -1;

    ret = tee_map_sharemem(in_task_id, va_addr, size, &vaddr);
    if (ret == 0)
        *virt_addr = (uint32_t)vaddr;

    return ret;
}
void tee_unmap_from_task(uint32_t va_addr, uint32_t size)
{
    (void)munmap((void *)(uintptr_t)va_addr, size);
}

/* msg can be null, which means we do not care return msg */
static void tee_task_entry_wait_msg(uint32_t want_cmd, uint8_t *msg,
    uint32_t size, uint32_t want_sdr)
{
    uint32_t cmd;
    uint32_t sdr;
    uint32_t ret;
    uint32_t cp_size;
    uint8_t ret_msg[sizeof(tee_service_ipc_msg)];
    errno_t rc;

    while (1) {
        cmd = 0;
        sdr = 0;
        (void)memset_s(ret_msg, sizeof(ret_msg), 0, sizeof(ret_msg));

        ret = (uint32_t)ipc_msg_rcv_a(OS_WAIT_FOREVER, (uint32_t *)(&cmd), ret_msg, sizeof(ret_msg), &sdr);
        if (ret != SRE_OK) {
            tloge("msg rcv error %x\n", ret);
            continue;
        }

        if (cmd == want_cmd && sdr == want_sdr) {
            cp_size = (size < sizeof(ret_msg)) ? size : sizeof(ret_msg);
            rc = memmove_s(msg, size, ret_msg, cp_size);
            if (rc != EOK)
                tloge("memmove msg, size %u error, ret %x\n", cp_size, rc);
            break;
        }
        tloge("receive unexpected msg 0x%x from 0x%x\n", cmd, sdr);
    }
}

static TEE_Result set_service_caller_info(uint32_t task_id, uint32_t cmd)
{
    uint32_t ret;
    struct task_caller_info caller_serv_info;

    caller_serv_info.taskid = task_id;
    caller_serv_info.cmd    = cmd;
    ret = ipc_msg_snd(TEE_TASK_SET_CALLER_INFO, get_global_handle(), &caller_serv_info, sizeof(caller_serv_info));
    if (ret != SRE_OK) {
        tloge("send caller info failed 0x%x\n", ret);
        return TEE_ERROR_COMMUNICATION;
    }

    tee_task_entry_wait_msg(TEE_TASK_SET_CALLER_INFO_ACK, (uint8_t *)&ret, sizeof(ret), get_global_handle());
    if (ret != TEE_SUCCESS) {
        tloge("set callerinfo fail, recv_ret:0x%x", ret);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static void tee_common_init(int init_build)
{
    if (init_build == 0) {
        cinit00();
        clear_ta_bss();
        _init();
    }
}

/*
 * the following two functions can be implemented in the real service
 */
WEAK uint32_t tee_service_init()
{
    return 0;
}

WEAK void tee_service_handle(const tee_service_ipc_msg *msg, uint32_t task_id, tee_service_ipc_msg_rsp *rsp,
                             uint32_t cmd)
{
    (void)msg;
    (void)task_id;
    (void)rsp;
    (void)cmd;
}

static int32_t get_ipc_native_args(const char *task_name, struct tee_service_ipc_msg_req *req_msg,
    struct channel_ipc_args *ipc_args)
{
    cref_t ch = 0;

    int32_t ret = hm_create_ipc_native(task_name, &ch);
    if (ret != 0) {
        tloge("create ipc channel failed, ret=%d\n", ret);
        return ret;
    }

    ipc_args->channel = ch;
    ipc_args->recv_buf = req_msg;
    ipc_args->recv_len = sizeof(*req_msg);
    return 0;
}

static void tee_service_msg_proc(const char *task_name)
{
    cref_t msghdl;
    uint32_t task_id;
    struct hmcap_message_info info = {0};
    struct tee_service_ipc_msg_req req_msg;
    tee_service_ipc_msg_rsp rsp_msg;
    struct channel_ipc_args ipc_args = {0};

    msghdl = hmapi_create_message();
    if (is_ref_err(msghdl)) {
        tloge("create msg hdl failed\n");
        return;
    }

    int32_t ret = get_ipc_native_args(task_name, &req_msg, &ipc_args);
    if (ret != 0)
        return;

    while (1) {
        ret = hmapi_recv_timeout(&ipc_args, &msghdl, 0, HM_NO_TIMEOUT, &info);
        if (ret < 0) {
            tloge("message receive failed, ret=0x%x, reason:%s\n", ret, hmapi_strerror(ret));
            continue;
        }

        task_id = (uint32_t)hmpid_to_pid(TCBCREF2TID(info.src_tcb_cref), info.src_cred.pid);
        tlogd("message receive from task pid=0x%x, task_id=0x%x, cmd=0x%x\n", info.src_cred.pid, task_id, req_msg.cmd);
        if (info.src_cred.pid != get_global_handle()) {
            if (set_service_caller_info(task_id, req_msg.cmd) != TEE_SUCCESS)
                tloge("failed to set caller info, task id 0x%x, cmd 0x%x\n", task_id, req_msg.cmd);
        }
        tee_service_handle(&req_msg.msg, task_id, &rsp_msg, req_msg.cmd);

        if (info.msg_type == HM_MSG_TYPE_CALL) {
            ret = hm_msg_reply(msghdl, &rsp_msg, sizeof(rsp_msg));
            if (ret != 0) {
                tloge("message reply failed, ret=0x%x, reason:%s\n", ret, hmapi_strerror(ret));
                continue;
            }
        }
    }
}

void tee_common_task_entry(int init_build, const char *task_name)
{
    if (task_name == NULL) {
        tloge("tee service entry failed, task name is null\n");
        return;
    }

    set_running_uuid();

    tloge("enter to tee_common_task_entry------------------------------\n");

    tee_common_init(init_build);

    if (tee_service_init() != 0) {
        tloge("tee service init failed\n");
        return;
    }

    tee_service_msg_proc(task_name);
    tloge("tee service meet a serious error\n");
}
