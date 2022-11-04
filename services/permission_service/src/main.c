/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2016-2020. All rights reserved.
 * Description: permission main fun
 * Author: TianJianliang tianjianliang@huawei.com
 * Create: 2016-04-01
 */
#include <stdio.h>
#include <pthread.h> /* for thread */
#include <sys/mman.h>

#include <tee_log.h>
#include <mem_ops_ext.h> /* tee_map_sharemem */
#include <msg_ops.h>
#include <api/errno.h>          /* is_ref_err */
#include <sys/usrsyscall.h>     /* for hm_msg_create_hdl */
#include <ipclib.h>             /* for channel */
#include <sys/usrsyscall_new.h> /* for cref_t */
#include <hm_thread.h>
#include <sys/hm_priorities.h>  /* for `HM_PRIO_TEE_*' */
#include <pthread.h>            /* for thread */
#include <procmgr.h>
#include <ac.h>
#include <ac_dynamic.h>
#include <tee_defines.h>
#include <tee_init.h>
#include <tee_ext_api.h>
#include <ta_framework.h>
#include <mm_kcall_sysmgr.h>
#include <tee_internal_task_pub.h>
#include "permission_service.h"
#include "config_tlv_parser.h"
#include "handle_config.h"
#include "handle_crl_cert.h"
#include "handle_ta_ctrl_list.h"
#include "handle_elf_verify.h"
#include "handle_cert_storage_io.h"
#include "register_ssa_perm.h"
#include "handle_ca_hashfile_verify.h"
#include "tee_mem_mgmt_api.h"
#ifdef DYN_IMPORT_CERT
#include "crypto_wrapper.h"
#endif

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG   "permission service"
#define CERT_PATH "permservice"

static struct ta_init_msg g_permsrv_init_msg = {
    .prop.uuid = TEE_SERVICE_PERM,
};

static spawn_uuid_t g_sender_uuid;

#define WEAK __attribute__((weak))
#define BSS_START_MAGIC 0x12345678
#define BSS_END_MAGIC   0x87654321

uint32_t WEAK TA_BSS_START = BSS_START_MAGIC;
uint32_t WEAK TA_BSS_END = BSS_END_MAGIC;

static cref_t get_mymsghdl(void)
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

static int32_t perm_service_map_from_task(uint32_t in_task_id, uint64_t va_addr, uint32_t size, uint32_t out_task_id,
                                          uint64_t *virt_addr)
{
    (void)out_task_id;
    uint64_t vaddr = 0;
    int32_t ret;

    ret = tee_map_sharemem(in_task_id, va_addr, size, &vaddr);
    if (ret == 0)
        *virt_addr = vaddr;

    return ret;
}

static void perm_service_unmap_from_task(uint64_t virt_addr, uint32_t size)
{
    if (virt_addr == 0)
        return;

    if (munmap((void *)(uintptr_t)virt_addr, size) != 0)
        tloge("perm unmap error\n");
}

static TEE_Result permission_get_buffer(uint64_t src_buffer, uint32_t src_len, uint32_t sndr, uint32_t revdr,
                                        uint8_t *dest_buffer)
{
    uint64_t temp_shared = 0;
    errno_t rc;

    /* must to be map the shared memory */
    if (perm_service_map_from_task(sndr, src_buffer, src_len, revdr, &temp_shared) != 0) {
        tloge("map writeBuffer from 0x%x fail\n", sndr);
        return TEE_ERROR_GENERIC;
    }

    rc = memcpy_s(dest_buffer, src_len, (uint8_t *)(uintptr_t)temp_shared, src_len);
    if (rc != EOK) {
        tloge("Failed to copy config to config buffer\n");
        perm_service_unmap_from_task(temp_shared, src_len);
        return TEE_ERROR_SECURITY;
    }

    perm_service_unmap_from_task(temp_shared, src_len);
    return TEE_SUCCESS;
}

static void perm_init_config_info(struct config_info *config)
{
    (void)memset_s(config, sizeof(*config), 0, sizeof(*config));
}

static TEE_Result check_se_task_id(uint32_t sndr)
{
    TEE_UUID sesrv_uuid = TEE_SERVICE_SE;
    TEE_UUID sem_uuid = TEE_SERVICE_SEM;
    struct config_info config;

    perm_init_config_info(&config);
    if (TEE_MemCompare(&g_sender_uuid.uuid, &sesrv_uuid, sizeof(sesrv_uuid)) == 0)
        return TEE_SUCCESS;

    (void)get_config_by_taskid(sndr, &config);
    if (TEE_MemCompare(&config.uuid, &sem_uuid, sizeof(sem_uuid)) == 0)
        return TEE_SUCCESS;

    return TEE_ERROR_ACCESS_DENIED;
}

static TEE_Result check_sender_permission(uint32_t sndr, const perm_srv_req_msg_t *msg)
{
    if (msg == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    TEE_Result ret = TEE_ERROR_ACCESS_DENIED;

    uint32_t type = msg->req_msg.query_perms.perm_type;
    switch (type) {
    case PERM_TYPE_SE_CAPABILITY:
        ret = check_se_task_id(sndr);
        break;
    default:
        break;
    }

    return ret;
}

static TEE_Result query_perms(const perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp, uint32_t sndr)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    struct config_info config;

    perm_init_config_info(&config);
    if (msg->req_msg.query_perms.checkby == CHECK_BY_TASKID) {
        uint32_t taskid = msg->req_msg.query_perms.taskid;
        ret = get_config_by_taskid(taskid, &config);
    } else if (msg->req_msg.query_perms.checkby == CHECK_BY_UUID) {
        TEE_UUID uuid = msg->req_msg.query_perms.uuid;
        ret = get_config_by_uuid(&uuid, &config);
    } else {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (ret != TEE_SUCCESS || check_sender_permission(sndr, msg) != TEE_SUCCESS) {
        ret = TEE_ERROR_ACCESS_DENIED;
        tloge("sender has no permission to do query\n");
        goto clean;
    }

    uint32_t type = msg->req_msg.query_perms.perm_type;
    switch (type) {
    case PERM_TYPE_SE_CAPABILITY:
        rsp->reply.permsrsp.se_capability = config.control_info.se_info.permissions;
        break;
    case PERM_TYPE_CERT_CAPABILITY:
        rsp->reply.permsrsp.cert_capability = config.control_info.cert_info.permissions;
        break;
    default:
        break;
    }

clean:
    rsp->reply.ret = ret;
    return ret;
}

static TEE_Result notify_unload_ta(const perm_srv_req_msg_t *msg, uint32_t sndr)
{
    TEE_UUID uuid = { 0, 0, 0, { 0 } };
    errno_t rc;

    if (msg == NULL) {
        tloge("params is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (sndr != GLOBAL_HANDLE) {
        tloge("sender has no permission\n");
        return TEE_ERROR_ACCESS_DENIED;
    }

    rc = memcpy_s(&uuid, sizeof(uuid), &msg->req_msg.ta_unload.uuid, sizeof(msg->req_msg.ta_unload.uuid));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    clear_ta_permissions(&uuid);
    return TEE_SUCCESS;
}

static TEE_Result perm_serv_set_crl_cert(const perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp, uint32_t revdr,
                                         uint32_t sndr)
{
    uint32_t msg_size;
    TEE_Result ret;
    uint8_t *msg_buff = NULL;

    if (rsp == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (msg == NULL) {
        rsp->reply.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (msg->req_msg.crl_cert.crl_cert_size > MAX_PERM_SRV_BUFF_SIZE) {
        rsp->reply.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg_size = msg->req_msg.crl_cert.crl_cert_size;
    msg_buff = TEE_Malloc(msg_size, 0);
    if (msg_buff == NULL) {
        tloge("Failed to malloc buffer for crl message\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto clean;
    }

    ret = permission_get_buffer(msg->req_msg.crl_cert.crl_cert_buff, msg_size, sndr, revdr, msg_buff);
    if (ret != TEE_SUCCESS)
        goto clean;

    ret = perm_serv_crl_cert_process(msg_buff, msg_size);

clean:
    rsp->reply.ret = ret;
    TEE_Free(msg_buff);
    return ret;
}

static TEE_Result perm_serv_set_ta_ctrl_list(const perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp, uint32_t revdr,
                                             uint32_t sndr)
{
    uint8_t *msg_buff = NULL;
    uint32_t msg_size;
    TEE_Result ret;

    if (rsp == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    if (msg == NULL) {
        rsp->reply.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (msg->req_msg.ctrl_list.ctrl_list_size > MAX_PERM_SRV_BUFF_SIZE) {
        rsp->reply.ret = TEE_ERROR_BAD_PARAMETERS;
        return TEE_ERROR_BAD_PARAMETERS;
    }

    msg_size = msg->req_msg.ctrl_list.ctrl_list_size;
    msg_buff = TEE_Malloc(msg_size, 0);
    if (msg_buff == NULL) {
        tloge("Failed to malloc buffer for ctrl message\n");
        ret = TEE_ERROR_OUT_OF_MEMORY;
        goto clean;
    }

    ret = permission_get_buffer(msg->req_msg.ctrl_list.ctrl_list_buff, msg_size, sndr, revdr, msg_buff);
    if (ret != TEE_SUCCESS)
        goto clean;

    ret = perm_serv_ta_ctrl_buff_process(msg_buff, msg_size);

clean:
    rsp->reply.ret = ret;
    TEE_Free(msg_buff);
    return ret;
}

#define PERMSRV_SAVE_FILE ".rtosck.permsrv_save_file"
#define PERMSRV_FILE_OPT  ".rtosck.permsrv_file_operation"
static const TEE_UUID g_crl_uuid = TEE_SERVICE_CRLAGENT;

#ifdef DYN_IMPORT_CERT
#define CERT_PERM 0x1U
#endif
static bool check_native_channel_perm(const msginfo_t *info, uint32_t *sender)
{
    TEE_Result ret;
    struct config_info config;

    perm_init_config_info(&config);
    /* get sender pid for rtosck */
    if (info->src_cred.pid == 0) {
        *sender = GLOBAL_HANDLE;
        return true;
    } else {
        *sender = (uint32_t)hmpid_to_pid(TCBCREF2TID(info->src_tcb_cref), info->src_cred.pid);
    }

    ret = get_config_by_taskid(*sender, &config);
    if (ret != TEE_SUCCESS) {
        tloge("get config by taskid failed\n");
        return false;
    }
#ifdef DYN_IMPORT_CERT
    if (config.control_info.cert_info.permissions == CERT_PERM && config.manifest_info.sys_verify_ta == true)
        return true;
#endif
    if (TEE_MemCompare(&g_crl_uuid, &config.uuid, sizeof(config.uuid)) != 0) {
        tloge("request from unexpected ta\n");
        return false;
    }

    return true;
}

static TEE_Result perm_serv_load_cert(perm_srv_reply_msg_t *rsp, uint32_t revdr)
{
    TEE_Result ret;

    register_self_to_ssa(revdr, TEE_TASK_REGISTER_TA);
    hm_yield();

    ret = perm_serv_global_issuer_list_loading();
    if (ret != TEE_SUCCESS) {
        tloge("CRL list loading fail, ret is 0x%x\n", ret);
        goto out;
    }

    ret = perm_serv_global_ctrl_list_loading();
    if (ret != TEE_SUCCESS)
        tloge("TA control list loading fail, ret is 0x%x\n", ret);

out:
    rsp->reply.ret = ret;
    return ret;
}

#ifdef DYN_IMPORT_CERT
/*
 * Description: Verifying and Saving the TA Certificate
 * msg: ta cert msg
 * rsp: reply struct to ta
 */
static TEE_Result perm_serv_cert_verify(perm_srv_reply_msg_t *rsp, const perm_srv_req_msg_t *msg,
                                        uint32_t req_pid, uint32_t slf_pid)
{
    if (msg->req_msg.ta_cert.ta_cert_size <= 0 || msg->req_msg.ta_cert.pub_key_size <= 0) {
        rsp->reply.ret = TEE_ERROR_BAD_PARAMETERS;
        tloge("ta_cert file failed\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret;
    uint64_t cert_map = 0;
    uint64_t key_map = 0;
    /* shared mm between requster and permission service on dst */
    if (perm_service_map_from_task(req_pid, msg->req_msg.ta_cert.ta_cert_buff,
                                   msg->req_msg.ta_cert.ta_cert_size, slf_pid, &cert_map) != 0) {
        ret = TEE_ERROR_GENERIC;
        tloge("map cert failed\n");
        goto err;
    }

    if (perm_service_map_from_task(req_pid, msg->req_msg.ta_cert.pub_key_buff,
        msg->req_msg.ta_cert.pub_key_size, slf_pid, &key_map) != 0) {
        ret = TEE_ERROR_GENERIC;
        tloge("map pub key failed\n");
        goto err;
    }
    /* x509 cert CA check */
    int32_t res = x509_cert_validate((uint8_t *)(uintptr_t)cert_map, msg->req_msg.ta_cert.ta_cert_size,
                                     (uint8_t *)(uintptr_t)key_map, msg->req_msg.ta_cert.pub_key_size);
    if (res <= 0) {
        ret = TEE_ERROR_GENERIC;
        tloge("import cert valid failed\n");
        goto err;
    }

    ret = cert_expiration_check((uint8_t *)(uintptr_t)cert_map, msg->req_msg.ta_cert.ta_cert_size);
    if (ret != TEE_SUCCESS) {
        tloge("cert expired\n");
        goto err;
    }

    /* import bytes in the src to ssa */
    ret = import_cert_to_storage((uint8_t *)(uintptr_t)cert_map, msg->req_msg.ta_cert.ta_cert_size);
    if (ret != TEE_SUCCESS)
        tloge("import cert failed\n");
err:
    if (cert_map != 0)
        perm_service_unmap_from_task(cert_map, msg->req_msg.ta_cert.ta_cert_size);
    if (key_map != 0)
        perm_service_unmap_from_task(key_map, msg->req_msg.ta_cert.pub_key_size);
    rsp->reply.ret = ret;
    return ret;
}

static TEE_Result perm_serv_crt_export(perm_srv_reply_msg_t *rsp, const perm_srv_req_msg_t *req,
                                       uint32_t req_pid, uint32_t slf_pid)
{
    TEE_Result ret;
    uint64_t req_dst = req->req_msg.crt.dst;
    uint32_t req_len = req->req_msg.crt.len;
    uint64_t dst = 0; /* pointer to the addr where cert exported to */
    uint32_t len = 0;

    /* shared mm between requster and permission service on dst */
    if (perm_service_map_from_task(req_pid, req_dst, req_len, slf_pid, &dst) != 0) {
        ret = TEE_ERROR_GENERIC;
        goto err;
    }

    /* export crt bytes to dst */
    ret = export_cert_from_storage((uint8_t *)(uintptr_t)dst, &len, req_len);
    if (ret != TEE_SUCCESS) {
        rsp->reply.permsrsp.crt.len = 0;
        tloge("export crt failed\n");
    } else {
        rsp->reply.permsrsp.crt.len = len;
    }

    /* unshared mm */
    perm_service_unmap_from_task(dst, req_len);
    tlogd("unmap shared mem finished\n");
    return TEE_SUCCESS;
err:
    rsp->reply.ret = ret;
    tloge("export failed ret: %d\n", ret);
    return ret;
}

static TEE_Result perm_serv_crt_remove(perm_srv_reply_msg_t *rsp)
{
    TEE_Result ret;

    ret = remove_cert_from_storage();
    rsp->reply.ret = ret;
    return ret;
}

#endif

static TEE_Result handle_msg_cmd(uint32_t cmd_id, const perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp,
                                 uint32_t sndr, uint32_t self_pid)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    switch (cmd_id) {
    case PERMSRV_LOAD_FILE_CMD:
        ret = perm_serv_load_cert(rsp, self_pid);
        break;
    case SET_CRL_CERT_CMD:
        ret = perm_serv_set_crl_cert(msg, rsp, self_pid, sndr);
        if (ret != TEE_SUCCESS)
            tloge("Set CRL cert error, 0x%x\n", ret);
        break;
    case SET_TA_CTRL_LIST_CMD:
        ret = perm_serv_set_ta_ctrl_list(msg, rsp, self_pid, sndr);
        if (ret != TEE_SUCCESS)
            tloge("Set TA control list error, 0x%x\n", ret);
        break;
    case ELF_VERIFY_CMD:
        ret = perm_serv_elf_verify(msg, sndr);
        break;
#ifdef DYN_IMPORT_CERT
    case CERT_VERIFY_CMD:
        ret = perm_serv_cert_verify(rsp, msg, sndr, self_pid);
        break;
    case PERMSRV_CRT_EXPORT:
        ret = perm_serv_crt_export(rsp, msg, sndr, self_pid);
        break;
    case PERMSRV_CRT_REMOVE:
        ret = perm_serv_crt_remove(rsp);
        break;
#endif
    case CA_HASHFILE_VERIFY_CMD:
        ret = perm_serv_ca_hashfile_verify(rsp, msg, sndr);
        break;
    default:
        tloge("not support the cmd id 0x%x\n", cmd_id);
        break;
    }
    return ret;
}

static TEE_Result handle_cmd_native_channel(const perm_srv_req_msg_t *msg, cref_t msghdl, uint32_t sndr,
    uint16_t msg_type, uint32_t self_pid)
{
    TEE_Result ret;
    int32_t rc;
    perm_srv_reply_msg_t rsp;
    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
    if (msg == NULL) {
        tloge("%s: handle cmd bad parameter\n", LOG_TAG);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ret = handle_msg_cmd(msg->header.send.msg_id, msg, &rsp, sndr, self_pid);
    if (ret == TEE_ERROR_GENERIC)
        tloge("handle cmd failed\n");

    if (msg_type == HM_MSG_TYPE_CALL) {
        rc = hm_msg_reply(msghdl, &rsp, sizeof(rsp));
        if (rc != 0) {
            tloge("reply error 0x%x\n", rc);
            ret = TEE_ERROR_GENERIC;
        }
    }
    return ret;
}

static TEE_Result perm_get_channel(cref_t *msghdl, cref_t *native_channel, cref_t *file_channel)
{
    TEE_Result ret;

    *msghdl = hm_msg_create_hdl();
    if (is_ref_err(*msghdl)) {
        tloge("thread file operation function create msg_hdl failed\n");
        return TEE_ERROR_GENERIC;
    }

    if (hm_create_ipc_native(PERMSRV_FILE_OPT, native_channel) != 0) {
        tloge("create thread native channel failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* create IPC channel */
    if (hm_create_ipc_channel(PERMSRV_SAVE_FILE, file_channel, true, false, true) != 0) {
        tloge("create thread file channel failed\n");
        return TEE_ERROR_GENERIC;
    }

    ret = tee_init(&g_permsrv_init_msg);
    if (ret != TEE_SUCCESS)
        /* no care the return code */
        tloge("TEE init error\n");

    return TEE_SUCCESS;
}

static void perm_thread_remove_channel(cref_t channel)
{
    msg_pid_t pid;

    pid = get_selfpid();
    if (pid == SRE_PID_ERR) {
        tloge("get self pid error\n");
        return;
    }

    if (hm_remove_ipc_channel(pid, PERMSRV_SAVE_FILE, 0, channel) != 0)
        tloge("remove the file channel failed\n");

    register_self_to_ssa(pid, TEE_TASK_UNREGISTER_TA);
}

static void perm_thread_check_native_channel(msginfo_t info, cref_t msghdl, perm_srv_req_msg_t req_msg)
{
    uint32_t sender = 0;
    perm_srv_reply_msg_t rsp;
    TEE_Result ret;
    uint32_t self_pid;

    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
    if (!check_native_channel_perm(&info, &sender)) {
        if (info.msg_type == HM_MSG_TYPE_CALL) {
            rsp.reply.ret = TEE_ERROR_ACCESS_DENIED;
            (void)hm_msg_reply(msghdl, &rsp, sizeof(rsp));
        }
        return;
    }

    self_pid = get_selfpid();
    if (self_pid == SRE_PID_ERR) {
        tloge("get self pid error\n");
        if (info.msg_type == HM_MSG_TYPE_CALL) {
            rsp.reply.ret = TEE_ERROR_GENERIC;
            (void)hm_msg_reply(msghdl, &rsp, sizeof(rsp));
        }
        return;
    }

    ret = handle_cmd_native_channel(&req_msg, msghdl, sender, info.msg_type, self_pid);
    if (ret != TEE_SUCCESS)
        tloge("handle cmd is fail");
}

void *perm_thread_init_file(void *data)
{
    int32_t rc;
    perm_srv_req_msg_t req_msg;
    cref_t native_channel = 0;
    cref_t file_channel;
    msginfo_t info = { 0 };
    cref_t msghdl;
    struct channel_ipc_args ipc_args = { 0 };

    (void)data;
    (void)memset_s(&req_msg, sizeof(req_msg), 0, sizeof(req_msg));
    rc = (int32_t)perm_get_channel(&msghdl, &native_channel, &file_channel);
    if (rc != 0)
        goto exit;

    ipc_args.channel = native_channel;
    ipc_args.recv_buf = &req_msg;
    ipc_args.recv_len = sizeof(req_msg);
    while (true) {
        rc = hm_msg_receive(&ipc_args, msghdl, &info, 0, -1);
        if (rc < 0) {
            tloge("%s: message receive failed, %llx, %s\n", LOG_TAG, rc, hmapi_strerror(rc));
            continue;
        }
        perm_thread_check_native_channel(info, msghdl, req_msg);
    }

    perm_thread_remove_channel(file_channel);

exit:
    hm_msg_delete_hdl(hm_get_mycnode(), msghdl);
    return NULL;
}

#define THREAD_STACK (16 * 4096)

TEE_Result perm_srv_create_rw_thread(void *(*thread_entry)(void *), const char *file, const char *buff,
    size_t buff_size)
{
    pthread_t thread = NULL;
    pthread_attr_t attr = { 0 };
    const uint32_t stack_size = THREAD_STACK;
    int32_t rc;

    tlogd("perm srv create write thread: pid is 0x%x\n", get_selfpid());
    (void)file;
    (void)buff_size;
    (void)buff;
    /* Init pthread attr */
    if (pthread_attr_init(&attr) != 0) {
        tloge("pthread attr init failed\n");
        return TEE_ERROR_GENERIC;
    }

    /* Set stack size for new thread */
    if (pthread_attr_setstacksize(&attr, stack_size) != 0) {
        tloge("pthread set stack failed, size = 0x%x\n", stack_size);
        return TEE_ERROR_GENERIC;
    }

    rc = pthread_create(&thread, &attr, thread_entry, NULL);
    if (rc != 0) {
        tloge("create thread error 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

static TEE_Result query_ta2ta_perm(const perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp, uint32_t sndr)
{
    TEE_Result ret;
    struct config_info config;
    TEE_UUID uuid = { 0, 0, 0, { 0 } };
    errno_t rc;

    perm_init_config_info(&config);
    ret = get_config_by_taskid(sndr, &config);
    if (ret != TEE_SUCCESS) {
        tloge("get config fail\n");
        rsp->reply.ret = ret;
        return ret;
    }
    rc = memcpy_s(&uuid, sizeof(uuid), &msg->req_msg.query_ta2ta_perm.uuid,
                  sizeof(msg->req_msg.query_ta2ta_perm.uuid));
    if (rc != EOK)
        return TEE_ERROR_SECURITY;

    ret =
        query_ta2ta_perm_by_uuid(&uuid, &config.uuid, msg->req_msg.query_ta2ta_perm.cmd);
    if (ret != TEE_SUCCESS)
        tloge("query ta2ta fail\n");

    rsp->reply.ret = ret;

    return ret;
}

static TEE_Result handle_query_perms(const perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp, uint32_t sndr)
{
    TEE_Result ret;

    ret = query_perms(msg, rsp, sndr);
    if (ret != TEE_SUCCESS)
        tlogd("query permissions error, 0x%x\n", ret);

    return ret;
}

static TEE_Result handle_register_ta(const perm_srv_req_msg_t *msg, uint32_t sndr)
{
    TEE_Result ret;

    if (sndr != GLOBAL_HANDLE)
        return TEE_ERROR_ACCESS_DENIED;

    ret = register_ta_pid(msg->req_msg.reg_ta.uuid, msg->req_msg.reg_ta.taskid, msg->req_msg.reg_ta.userid);
    if (ret != TEE_SUCCESS)
        tloge("register ta error, 0x%x\n", ret);

    return ret;
}

static TEE_Result handle_unregister_ta(const perm_srv_req_msg_t *msg, uint32_t sndr)
{
    TEE_Result ret;

    if (sndr != GLOBAL_HANDLE)
        return TEE_ERROR_ACCESS_DENIED;

    ret = unregister_ta_pid(msg->req_msg.reg_ta.taskid);
    if (ret != TEE_SUCCESS)
        tloge("unregister ta error, 0x%x\n", ret);

    return ret;
}

static void handle_cmd(const perm_srv_req_msg_t *msg, cref_t msghdl, uint32_t sndr, uint16_t msg_type)
{
    TEE_Result ret = TEE_ERROR_GENERIC;
    uint32_t cmd_id;
    perm_srv_reply_msg_t rsp;

    (void)memset_s(&rsp, sizeof(rsp), 0, sizeof(rsp));
    if (msg == NULL) {
        tloge("%s: handle cmd bad parameter\n", LOG_TAG);
        return;
    }

    cmd_id = msg->header.send.msg_id;

    tlogd("cmd is 0x%x\n", cmd_id);
    switch (cmd_id) {
    case QUERY_PERMS_CMD:
        ret = handle_query_perms(msg, &rsp, sndr);
        break;
    case TEE_TASK_REGISTER_TA:
        ret = handle_register_ta(msg, sndr);
        break;
    case TEE_TASK_UNREGISTER_TA:
        ret = handle_unregister_ta(msg, sndr);
        break;
    case TEE_TASK_TA_RELEASE:
        ret = notify_unload_ta(msg, sndr);
        break;
    case QUER_TA2TA_PERM_CMD:
        ret = query_ta2ta_perm(msg, &rsp, sndr);
        break;
    default:
        tlogd("not support the cmd id 0x%x\n", cmd_id);
        break;
    }
    if (ret != TEE_SUCCESS)
        tlogd("handle cmd fail 0x%x", ret);

    if (msg_type == HM_MSG_TYPE_CALL) {
        if (hm_msg_reply(msghdl, &rsp, sizeof(rsp)) != 0) {
            tloge("reply error\n");
            return;
        }
    }
}
#define HM_TASK_EXIT   (-1)
#define HM_MSG_TIMEOUT (-1)

__attribute__((visibility("default"))) void tee_task_entry(int32_t init_build)
{
    perm_srv_req_msg_t req_msg;
    uint32_t sender;
    int32_t ret;
    struct channel_ipc_args ipc_args = { 0 };
    (void)init_build;

    (void)memset_s(&req_msg, sizeof(req_msg), 0, sizeof(req_msg));
    cref_t ch = 0;
    msginfo_t info = { 0 };
    cref_t msghdl;

    msghdl = get_mymsghdl();
    if (is_ref_err(msghdl)) {
        tloge("Cannot create msg_hdl, %s\n", hmapi_strerror((int32_t)msghdl));
        hm_exit((int32_t)msghdl);
    }

    if (hm_create_ipc_native(CERT_PATH, &ch) != 0) {
        tloge("create main thread native channel failed\n");
        hm_exit(HM_TASK_EXIT);
    }

    if (ac_init_simple() != 0) {
        tloge("ac init error\n");
        hm_exit(HM_TASK_EXIT);
    }

    if (perm_srv_create_rw_thread(perm_thread_init_file, NULL, NULL, 0) != TEE_SUCCESS) {
        tloge("thread created fail\n");
        hm_exit(HM_TASK_EXIT);
    }

    ipc_args.channel = ch;
    ipc_args.recv_buf = &req_msg;
    ipc_args.recv_len = sizeof(req_msg);
    while (1) {
        ret = hm_msg_receive(&ipc_args, msghdl, &info, 0, HM_MSG_TIMEOUT);
        if (ret < 0) {
            tloge("%s: message receive failed, %llx, %s\n", LOG_TAG, ret, hmapi_strerror(ret));
            continue;
        }

        /* get sender pid for rtosck */
        if (info.src_cred.pid == 0)
            sender = GLOBAL_HANDLE;
        else
            sender = (uint32_t)hmpid_to_pid(TCBCREF2TID(info.src_tcb_cref), info.src_cred.pid);

        if (hm_getuuid(info.src_cred.pid, &g_sender_uuid) != 0)
            tloge("get uuid failed\n");

        handle_cmd(&req_msg, msghdl, sender, info.msg_type);
    }
    tloge("permission service abort\n");
}
