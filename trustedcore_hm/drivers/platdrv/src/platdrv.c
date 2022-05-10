/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Init function in platdrv
 * Create: 2020-02-20
 */
#include "platdrv.h"
#include <errno.h>
#include <cs.h>
#include <kernel/cspace.h>
#include <sys/usrsyscall_ext.h>
#include <sys/usrsyscall_new_ext.h>
#include <ac.h>
#include <ipclib.h>
#include <pm_msgtype.h>
#include <tee_log.h>
#include <hmlog.h>
#include <securec.h>
#include <ta_permission.h>
#include <libdrv_frame.h>
#include <timer.h>
#include <drv_mod.h>
#include <drv_pm_check.h>
#include "tc_drv.h"
#include "drv_pal.h"
#include "drv_param_type.h"
#include "drv_thread.h"
#include "platdrv_hash.h"

#define DEVIATION 8U

int32_t get_drv_params(struct drv_param *params, const struct hm_drv_req_msg_t *msg,
                       const struct hmcap_message_info *info)
{
    pid_t pid;
    uid_t uid;
    int32_t ret;
    if (params == NULL || msg == NULL || info == NULL) {
        hm_error("invalid parameters\n");
        return DRV_CALL_ERROR;
    }

    uint32_t cnode_idx = info->src_cnode_idx;
    if ((cnode_idx == 0) || (info->msg_size < sizeof(struct hm_drv_req_msg_t))) {
        hm_error("invalid cnode or invalid msg size\n");
        return DRV_CALL_ERROR;
    }

    ret = ac_get_uid(cnode_idx, &uid);
    if (ret != 0) {
        hm_error("get  uid failed for cnode %u: uid is %d\n", cnode_idx, ret);
        return DRV_CALL_ERROR;
    }

    ret = ac_get_pid(cnode_idx, &pid);
    if (ret != 0) {
        hm_error("get pid failed for cnode %u: ret is %d\n", cnode_idx, ret);
        return DRV_CALL_ERROR;
    }

    params->pid = (uint32_t)pid;
    params->uid = uid;
    params->job_handler = msg->job_handler;
    params->args = (uintptr_t)msg->args;
    params->data = (uintptr_t)msg->data;
    params->caller_pid = hmpid_to_pid(TCBCREF2TID(info->src_tcb_cref), pid);

    return DRV_CALL_OK;
}

static int32_t platdrv_syscall(const struct hm_drv_req_msg_t *msg, const struct hmcap_message_info *info,
                               struct hm_drv_reply_msg_t *rmsg, size_t *rdata_len, uint64_t **ret_args)
{
    int32_t ret;
    tid_t tid;
    struct drv_param params = { 0 };
    uint64_t permissions = ULL_PERMISSIONS;
    int32_t swi_id = msg->header.send.msg_id;
    uint8_t multi_flag = msg->header.send.msg_flags;

    ret = get_drv_params(&params, msg, info);
    if (ret != 0) {
        hm_error("get driver parameters failed\n");
        *rdata_len = 0;
        return DRV_CALL_ERROR;
    }
    params.rdata = (uintptr_t)rmsg->rdata;
    params.rdata_len = *rdata_len;

    ret = (int32_t)get_ta_permission_wrapper(params.uid, &permissions);
    if (ret != 0) {
        hm_error("get ta permission failed %d\n", ret);
        *rdata_len = 0;
        return DRV_CALL_ERROR;
    }

    ret = hm_gettid(&tid);
    if (ret != 0) {
        hm_error("failed to get tid\n");
        return DRV_CALL_ERROR;
    }

    update_caller_info_by_tid(tid, params.caller_pid, params.job_handler);

    if (multi_flag != 1) {
        ret = tc_drv_syscall(swi_id, &params, permissions);
    } else {
        tlogd("swi_id:0x%x multi_flag:%d\n", swi_id, (uint32_t)multi_flag);
        ret = DRV_CALL_ERROR;
        tc_drv_syscall_t drv_syscall = find_drv_syscall_by_id(swi_id);
        if (drv_syscall != NULL)
            ret = drv_syscall(swi_id, &params, permissions);
        else
            ret = vendor_drv_syscall(swi_id, &params, permissions);
    }

    update_caller_info_by_tid(tid, INVALID_CALLER_PID, 0);
    if (ret != 0)
        hm_error("handle swi 0x%x failed\n", swi_id);

    *rdata_len = (size_t)params.rdata_len;
    *ret_args = (uint64_t *)(uintptr_t)params.args;

    return ret;
}

static int32_t platdrv_handle_message(struct hm_drv_req_msg_t *msg, struct hmcap_message_info *info,
                                      struct hm_drv_reply_msg_t *rmsg, size_t *rdata_len, cref_t *msg_hdl)
{
    uint64_t *ret_args = NULL;
    int32_t ret;

    ret = platdrv_syscall(msg, info, rmsg, rdata_len, &ret_args);
    if (ret != 0)
        hm_error("hanle platdrv syscall failed\n");

    rmsg->header.reply.ret_val = (ret == 0) ? (int64_t)ret_args[0] : (int64_t)ret;
    ret = hm_msg_reply(*msg_hdl, rmsg, sizeof(struct hm_drv_reply_msg_t) + *rdata_len);
    if (ret)
        hm_error("hm msg reply failed\n");

    return ret;
}

intptr_t message_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    char *reply_raw_buf = NULL;
    struct hm_drv_reply_msg_t *rbuf = NULL;
    size_t rdata_len;
    int32_t ret;

    reply_raw_buf = malloc(REPLY_BUF_LEN);
    if (reply_raw_buf == NULL)
        return DRV_CALL_ERROR;

    rdata_len = REPLY_BUF_LEN - sizeof(*rbuf);
    rbuf = (struct hm_drv_reply_msg_t *)reply_raw_buf;
    (void)memset_s(rbuf, REPLY_BUF_LEN, 0, REPLY_BUF_LEN);

    if ((p_msg_hdl == NULL) || (info == NULL) || (msg == NULL)) {
        free(reply_raw_buf);
        return DRV_CALL_ERROR;
    }

    ret = platdrv_handle_message((struct hm_drv_req_msg_t *)msg, info, rbuf, &rdata_len, p_msg_hdl);
    if (ret != 0)
        hm_error("platdrv handle message failed\n");

    (void)memset_s(reply_raw_buf, REPLY_BUF_LEN, 0, REPLY_BUF_LEN);
    free(reply_raw_buf);
    return ret;
}

intptr_t driver_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    struct hm_drv_req_msg_t *req = msg;
    if (req == NULL)
        return DRV_CALL_ERROR;
    req->header.send.msg_flags = 1; /* flag 1 for multi driver */
    return message_dispatch(msg, p_msg_hdl, info);
}

intptr_t single_thread_driver_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    struct hm_drv_req_msg_t *req = msg;
    if (req == NULL)
        return DRV_CALL_ERROR;
    req->header.send.msg_flags = 0;
    return message_dispatch(msg, p_msg_hdl, info);
}

static int32_t pm_forward_to_drv_timer(const uint16_t msg_id)
{
#ifndef CONFIG_OFF_DRV_TIMER
    static cref_t timer_cref = 0;
    int32_t ret = pm_forward_msg_to_other_drv(msg_id, TIMER_PATH, &timer_cref);
    if (ret != 0)
        hm_error("pm forward msg to drv timer failed 0x%x\n", ret);
    return ret;
#else
    (void)msg_id;
    return DRV_CALL_OK;
#endif
}

static int32_t pm_forward_to_drv_server(const uint16_t msg_id)
{
#if defined(TEE_SUPPORT_DRV_SERVER_64BIT) || defined(TEE_SUPPORT_DRV_SERVER_32BIT)
    /*
     * smcmgr will send suspend/resume cmd to platdrv when both platdrv and tee_drv_server exist
     * in this case, platdrv should send suspend/resume cmd to tee_drv_server
     */
    static cref_t tee_drv_cref = 0;
    int32_t ret = pm_forward_msg_to_other_drv(msg_id, "tee_drv_server", &tee_drv_cref);
    if (ret != 0)
        hm_error("pm forward msg to tee drv server failed 0x%x\n", ret);
    return ret;
#else
    (void)msg_id;
    return DRV_CALL_OK;
#endif
}


static int32_t hm_platdrv_pm_forward_msg(const uint16_t msg_id)
{
    int32_t ret = pm_forward_to_drv_timer(msg_id);
    if (pm_forward_to_drv_server(msg_id) != DRV_CALL_OK)
        ret = DRV_CALL_ERROR;
    return ret;
}

static void hm_platdrv_pm_handle_drv(const uint16_t msg_id)
{
    switch (msg_id) {
    case HM_MSG_ID_DRV_PWRMGR_SUSPEND_CPU:
        tc_drv_sp();
        break;
    case HM_MSG_ID_DRV_PWRMGR_SUSPEND_S4:
        tc_drv_sp_s4();
        break;
    case HM_MSG_ID_DRV_PWRMGR_RESUME_CPU:
        tc_drv_sr();
        break;
    case HM_MSG_ID_DRV_PWRMGR_RESUME_S4:
        tc_drv_sr_s4();
        break;
    default:
        tloge("invalid msg id\n");
    }
}

intptr_t hm_platdrv_pm_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    int32_t ret;
    uint16_t msg_id;
    cref_t msg_hdl;

    if (msg == NULL || info == NULL || p_msg_hdl == NULL)
        return -EINVAL;

    msg_hdl = *p_msg_hdl;

    msg_id = ((hm_msg_header *)msg)->send.msg_id;

    ret = pm_msg_param_check(msg_id, msg_hdl, msg, info, SMCMGR_PID);
    if (ret != 0) {
        hm_error("pm msg check failed\n");
        goto return_ree;
    }

    ret = hm_platdrv_pm_forward_msg(msg_id);
    if (ret != 0) {
        hm_error("platdrv forward pm msg failed\n");
        goto return_ree;
    }

    hm_platdrv_pm_handle_drv(msg_id);

return_ree:
    ret = hm_driver_pm_return_to_ree(msg_id);
    if (ret != 0)
        return DRV_CALL_ERROR;

    return DRV_CALL_OK;
}
