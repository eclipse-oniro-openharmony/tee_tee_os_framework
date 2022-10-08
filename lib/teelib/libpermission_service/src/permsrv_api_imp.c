/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: permission service implementation
 * Author: Dizhe Mao maodizhe1@huawei.com
 * Create: 2018-05-18
 */
#include <pthread.h>
#include <mem_ops_ext.h>
#include "tee_defines.h"
#include "ta_framework.h"
#include "tee_log.h"
#include "securec.h"
#include <sys/usrsyscall_new.h>
#include <sys/syscalls.h>
#include "ipclib.h"
#include "permsrv_api_imp.h"
#include "tee_internal_task_pub.h"
#include "tee_inner_uuid.h"

#define PERM_PATH        "permservice"
static uint32_t g_init_state = INIT_STATE_NOT_READY;
static pthread_mutex_t g_msg_call_mutex = PTHREAD_ROBUST_MUTEX_INITIALIZER;
static TEE_UUID g_permsrv_uuid = TEE_SERVICE_PERM;

int perm_srv_msg_call(const char *path, perm_srv_req_msg_t *msg, perm_srv_reply_msg_t *rsp)
{
    errno_t rc;
    cref_t rslot = 0;

    if (path == NULL || msg == NULL) {
        tloge("path or msg is null\n");
        return -1;
    }

    if (pthread_mutex_lock(&g_msg_call_mutex) != 0) {
        tloge("perm msg call mutex lock failed\n");
        return -1;
    }
    rc = hm_ipc_get_ch_from_path(path, &rslot);
    if (rc == -1) {
        tloge("permsrv: get channel from pathmgr failed\n");
        (void)pthread_mutex_unlock(&g_msg_call_mutex);
        return rc;
    }

    if (rsp == NULL)
        rc = hm_msg_notification(rslot, msg, sizeof(*msg));
    else
        rc = hm_msg_call(rslot, msg, sizeof(*msg), rsp, sizeof(*rsp), 0, -1);
    if (rc < 0)
        tloge("msg send 0x%llx failed: 0x%x\n", rslot, rc);

    (void)hm_ipc_release_path(path, rslot);
    (void)pthread_mutex_unlock(&g_msg_call_mutex);
    return rc;
}

void tee_perm_init_msg(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg)
{
    if (req_msg != NULL)
        (void)memset_s(req_msg, sizeof(*req_msg), 0, sizeof(*req_msg));

    if (reply_msg != NULL)
        (void)memset_s(reply_msg, sizeof(*reply_msg), 0, sizeof(*reply_msg));
}

void permsrv_registerta(const TEE_UUID *uuid, uint32_t task_id, uint32_t user_id, uint32_t opt_type)
{
    perm_srv_req_msg_t req_msg;

    tee_perm_init_msg(&req_msg, NULL);
    if (uuid == NULL) {
        tloge("register TA with NULL uuid\n");
        return;
    }

    if (opt_type == REGISTER_TA) {
        req_msg.header.send.msg_id = TEE_TASK_REGISTER_TA;
    } else if (opt_type == UNREGISTER_TA) {
        req_msg.header.send.msg_id = TEE_TASK_UNREGISTER_TA;
    } else {
        tloge("perm srv not support operation type!\n");
        return;
    }

    req_msg.req_msg.reg_ta.uuid   = *uuid;
    req_msg.req_msg.reg_ta.taskid = task_id;
    req_msg.req_msg.reg_ta.userid = user_id;

    if (perm_srv_msg_call(PERM_PATH, &req_msg, NULL) < 0)
        tloge("register ta msg send failed!\n");
}

void permsrv_notify_unload_ta(const TEE_UUID *uuid)
{
    perm_srv_req_msg_t req_msg;

    tee_perm_init_msg(&req_msg, NULL);
    if (uuid == NULL) {
        tloge("uuid is NULL\n");
        return;
    }

    req_msg.header.send.msg_id     = TEE_TASK_TA_RELEASE;
    req_msg.req_msg.ta_unload.uuid = *uuid;

    if (perm_srv_msg_call(PERM_PATH, &req_msg, NULL) < 0)
        tloge("ta unload msg send failed!\n");
}

TEE_Result get_permission_by_type(const TEE_UUID *uuid, uint32_t taskid, uint32_t checkby, uint32_t type,
                                  perm_srv_permsrsp_t *result)
{
    perm_srv_req_msg_t req_msg;
    perm_srv_reply_msg_t reply_msg;

    TEE_Result ret;

    tee_perm_init_msg(&req_msg, &reply_msg);
    if (result == NULL) {
        tloge("query bad parameter for points\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    req_msg.header.send.msg_id = QUERY_PERMS_CMD;
    if (checkby == CHECK_BY_UUID) {
        if (uuid == NULL)
            return TEE_ERROR_BAD_PARAMETERS;
        req_msg.req_msg.query_perms.uuid    = *uuid;
        req_msg.req_msg.query_perms.checkby = CHECK_BY_UUID;
    } else if (checkby == CHECK_BY_TASKID) {
        req_msg.req_msg.query_perms.taskid  = taskid;
        req_msg.req_msg.query_perms.checkby = CHECK_BY_TASKID;
    } else {
        tloge("get permission bad checkby parameter!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    req_msg.req_msg.query_perms.perm_type = type;
    reply_msg.reply.ret                   = TEE_ERROR_GENERIC;

    if (perm_srv_msg_call(PERM_PATH, &req_msg, &reply_msg) < 0) {
        tloge("query msg send failed!\n");
        return TEE_ERROR_GENERIC;
    }

    ret = reply_msg.reply.ret;
    if (ret == TEE_SUCCESS)
        *result = reply_msg.reply.permsrsp;

    return ret;
}

TEE_Result rslot_file_msg_call(perm_srv_req_msg_t *req_msg, perm_srv_reply_msg_t *reply_msg)
{
    if (req_msg == NULL || reply_msg == NULL) {
        tloge("req_msg or reply_msg is null!\n");
        return TEE_ERROR_GENERIC;
    }

    if (perm_srv_msg_call(PERMSRV_FILE_OPT, req_msg, reply_msg) < 0) {
        tloge("msg send failed!\n");
        return TEE_ERROR_GENERIC;
    }

    tlogd("msg call ret is 0x%x\n", reply_msg->reply.ret);
    return reply_msg->reply.ret;
}

TEE_Result tee_ta_ctrl_list_process(const uint8_t *ctrl_list, uint32_t ctrl_list_size)
{
    perm_srv_req_msg_t req_msg;
    perm_srv_reply_msg_t reply_msg;

    uint8_t *ctrl_shared = NULL;
    uint32_t ctrl_size;

    tee_perm_init_msg(&req_msg, &reply_msg);
    errno_t rc;
    TEE_Result ret = TEE_ERROR_GENERIC;

    if (ctrl_list == NULL) {
        tloge("bad parameter for points\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    if (ctrl_list_size == 0 || ctrl_list_size > MAX_PERM_SRV_BUFF_SIZE) {
        tloge("bad parameter for size!\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    ctrl_size   = ctrl_list_size;
    ctrl_shared = tee_alloc_sharemem_aux(&g_permsrv_uuid, ctrl_size);
    if (ctrl_shared == NULL) {
        tloge("malloc sharedBuff failed, size=0x%x\n", ctrl_size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    rc = memmove_s(ctrl_shared, ctrl_size, ctrl_list, ctrl_list_size);
    if (rc != EOK) {
        tloge("copy the conf error, rc = 0x%x", rc);
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    req_msg.header.send.msg_id               = SET_TA_CTRL_LIST_CMD;
    req_msg.req_msg.ctrl_list.ctrl_list_buff = (uintptr_t)ctrl_shared;
    req_msg.req_msg.ctrl_list.ctrl_list_size = ctrl_size;
    reply_msg.reply.ret                      = TEE_ERROR_GENERIC;

    ret = rslot_file_msg_call(&req_msg, &reply_msg);

clean:
    if (ctrl_shared != NULL)
        (void)tee_free_sharemem(ctrl_shared, ctrl_size);
    return ret;
}

void permsrv_load_file()
{
    perm_srv_req_msg_t req_msg;

    tee_perm_init_msg(&req_msg, NULL);
    req_msg.header.send.msg_id = PERMSRV_LOAD_FILE_CMD;

    if (g_init_state == INIT_STATE_READY)
        return;

    if (perm_srv_msg_call(PERMSRV_FILE_OPT, &req_msg, NULL) < 0) {
        tloge("register ta msg failed!\n");
        return;
    }

    g_init_state = INIT_STATE_READY;
}

TEE_Result check_ta2ta_caller_permission(const TEE_UUID *uuid, uint32_t cmd)
{
    if (uuid == NULL) {
        tloge("invalid uuid\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }
    perm_srv_req_msg_t req_msg;
    perm_srv_reply_msg_t reply_msg;

    tee_perm_init_msg(&req_msg, &reply_msg);
    req_msg.header.send.msg_id            = QUER_TA2TA_PERM_CMD;
    req_msg.req_msg.query_ta2ta_perm.uuid = *uuid;
    req_msg.req_msg.query_ta2ta_perm.cmd  = cmd;

    if (perm_srv_msg_call(PERM_PATH, &req_msg, &reply_msg) < 0) {
        tloge("check ta2ta caller permission msg send failed!\n");
        return TEE_ERROR_GENERIC;
    }

    /* return TEE_ERROR_ACCESS_DENIED  in case: */
    /* communication with permission service is OK but ret value is not TEE_SUCCESS */
    if (reply_msg.reply.ret != TEE_SUCCESS)
        return TEE_ERROR_ACCESS_DENIED;

    return TEE_SUCCESS;
}

TEE_Result permsrv_elf_verify(const void *verify_req, uint32_t len)
{
    errno_t rc;
    perm_srv_req_msg_t req_msg;

    if (verify_req == NULL) {
        tloge("elf verify req is null\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    if (len != sizeof(req_msg.req_msg.verify_req)) {
        tloge("elf verify req len %u is invalid\n", len);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    tee_perm_init_msg(&req_msg, NULL);
    req_msg.header.send.msg_id = ELF_VERIFY_CMD;
    req_msg.header.send.msg_size = len;

    rc = memcpy_s(&(req_msg.req_msg.verify_req), sizeof(req_msg.req_msg.verify_req), verify_req, len);
    if (rc != EOK) {
        tloge("copy verify req msg failed: 0x%x\n", rc);
        return TEE_ERROR_GENERIC;
    }

    if (perm_srv_msg_call(PERMSRV_FILE_OPT, &req_msg, NULL) < 0) {
        tloge("elf verify msg failed!\n");
        return TEE_ERROR_GENERIC;
    }

    return TEE_SUCCESS;
}

TEE_Result permsrv_ca_hashfile_verfiy(const uint8_t *buf, uint32_t size)
{
    if (buf == NULL || size == 0 || size > HASH_FILE_MAX_SIZE) {
        tloge("invaild params\n");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    TEE_Result ret = TEE_SUCCESS;
    perm_srv_req_msg_t req_msg;
    perm_srv_reply_msg_t reply_msg;

    uint8_t *share_addr = tee_alloc_sharemem_aux(&g_permsrv_uuid, size);
    if (share_addr == NULL) {
        tloge("malloc share mem failed, size %u\n", size);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    if (memcpy_s(share_addr, size, buf, size) != 0) {
        tloge("copy buf fail\n");
        ret = TEE_ERROR_SECURITY;
        goto clean;
    }

    tee_perm_init_msg(&req_msg, &reply_msg);
    req_msg.header.send.msg_id        = CA_HASHFILE_VERIFY_CMD;
    req_msg.req_msg.ca_hashfile_verify.buffer = (uintptr_t)share_addr;
    req_msg.req_msg.ca_hashfile_verify.size   = size;
    reply_msg.reply.ret               = TEE_ERROR_GENERIC;

    if (perm_srv_msg_call(PERMSRV_FILE_OPT, &req_msg, &reply_msg) < 0) {
        tloge("msg send fail\n");
        ret = reply_msg.reply.ret;
    }

clean:
    if (share_addr != NULL)
        (void)tee_free_sharemem(share_addr, size);
    return ret;
}
