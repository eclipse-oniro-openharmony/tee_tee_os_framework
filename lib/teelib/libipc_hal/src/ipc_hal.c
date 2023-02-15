/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */
#include <ipclib.h>
#include <ipclib_hal.h>

struct msg_st {
    uint32_t msg_id;
    char payload[MSG_MAX_LEN];
} __attribute__((__packed__));

struct msgsent_st {
    cref_t dst_ch;
    uint32_t uw_msg_id;
    msg_pid_t uw_dst_pid;
    const void *msgp;
    uint16_t size;
} __attribute__((__packed__));

struct msgrcv_st {
    cref_t ch;
    cref_t timer;
    int32_t timeout;
    uint32_t *puw_msg_id;
    void *msgp;
    uint16_t size;
    msg_pid_t *puw_sender_pid;
} __attribute__((__packed__));

struct notify_st {
    uint32_t msg_id;
    char payload[NOTIFY_MAX_LEN];
} __attribute__((__packed__));

struct reply_msg_st {
    uint32_t status;
} __attribute__((__packed__));

/*
 * CODEREVIEW CHECKLIST
 * ARG: all would be checked in ipc_create_channel
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
int32_t ipc_create_single_channel(const char *name, cref_t *pch, bool reg_pid, bool reg_name, bool reg_tamgr)
{
    struct reg_items_st reg_items;
    reg_items.reg_pid   = reg_pid;
    reg_items.reg_name  = reg_name;
    reg_items.reg_tamgr = reg_tamgr;
    return ipc_create_channel(name, 1, &pch, reg_items);
}

/*
 * CODEREVIEW CHECKLIST
 * ARG: all would be checked in ipc_create_channel
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
int32_t ipc_create_channel_native(const char *name, cref_t *pch)
{
    return ipc_create_single_channel(name, pch, false, true, false);
}

/*
 * CODEREVIEW CHECKLIST
 * ARG: Private API. uwMsgHandle, msgp, size checked, other need not checked
 * BUFOVF: payload checked
 * RET: memcpy_s ipc_msg_notification, ipc_msg_call, channel_of_id, ipc_msg_notification checked
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
static uint32_t ipc_msgsnd_core(struct msgsent_st msgsent, msg_handle_t uw_msg_handle, msg_pid_t cid)
{
    int32_t rc    = 0;
    struct msg_st hm_msg = { 0 };

    hm_msg.msg_id = msgsent.uw_msg_id;

    if (uw_msg_handle != 0) {
        msg_handle_t *msg_handle = (msg_handle_t *)(&hm_msg.payload[0]);
        *msg_handle              = uw_msg_handle;
    }

    if (msgsent.msgp != NULL) {
        if (memcpy_s(hm_msg.payload, sizeof(hm_msg.payload), msgsent.msgp, msgsent.size) != 0)
            return SRE_IPC_ERR;
    }

    if (msgsent.size <= NOTIFY_MAX_LEN) {
        struct notify_st *hm_ntf_p = (struct notify_st *)&hm_msg;
        rc                         = ipc_msg_notification(msgsent.dst_ch, hm_ntf_p, sizeof(struct notify_st));
        if (rc != 0) {
            hm_error("Notify failed to 0x%x size = %u\n", msgsent.uw_dst_pid, msgsent.size);
            rc = E_EX_AGAIN; /* notify failed, force to do ipc_msg_call */
        }
    } else {
        hm_error("msg_call failed, not support big msg in ipc_msg_snd/ipc_msg_qsnd, size = %u\n", msgsent.size);
        return SRE_IPC_ERR;
    }

    if (rc == E_EX_AGAIN) {
        /* if returns E_EX_AGAIN, we try to update local cache and re-send */
        channel_remove_id(cid);
        msgsent.dst_ch = channel_of_id(cid);
        if ((msgsent.dst_ch != 0) && !is_ref_err(msgsent.dst_ch)) {
            struct notify_st *hm_ntf_p = (struct notify_st *)&hm_msg;
            rc                         = ipc_msg_notification(msgsent.dst_ch, hm_ntf_p, sizeof(struct notify_st));
        }
    }

    if (rc != 0) {
        hm_error("notify failed to 0x%x, size=%u, ret=%d\n", hm_msg.msg_id, msgsent.size, rc);
        return SRE_IPC_ERR;
    }

    return HM_OK;
}

static uint32_t ipc_msgsnd_core_sync(struct msgsent_st msgsent, msg_handle_t uw_msg_handle, msg_pid_t cid)
{
    int32_t rc;
    struct msg_st hm_msg     = { 0 };
    struct reply_msg_st rmsg = { 0 };

    hm_msg.msg_id = msgsent.uw_msg_id;

    if (uw_msg_handle != 0) {
        msg_handle_t *msg_handle = (msg_handle_t *)(&hm_msg.payload[0]);
        *msg_handle              = uw_msg_handle;
    }

    if (msgsent.msgp != NULL) {
        if (memcpy_s(hm_msg.payload, sizeof(hm_msg.payload), msgsent.msgp, msgsent.size) != 0)
            return SRE_IPC_ERR;
    }

    rc = ipc_msg_call(msgsent.dst_ch, &hm_msg, sizeof(hm_msg), &rmsg, sizeof(rmsg), -1);
    /* between two send times, receiver may restart, so need to update channel */
    if (rc != 0) {
        /* if returns E_EX_AGAIN, we try to update local cache and re-send */
        channel_remove_id(cid);
        msgsent.dst_ch = channel_of_id(cid);
        if ((msgsent.dst_ch != 0) && !is_ref_err(msgsent.dst_ch))
            rc = ipc_msg_call(msgsent.dst_ch, &hm_msg, sizeof(hm_msg), &rmsg, sizeof(rmsg), -1);
    }
    if (rc != 0) {
        hm_error("msg_call to 0x%x failed, rc = %d\n", msgsent.uw_dst_pid, rc);
        return SRE_IPC_ERR;
    }

    return HM_OK;
}

/*
 * CODEREVIEW CHECKLIST
 * Copy message from user space specified by @msgp and send it to the process indicated by @uw_dst_pid
 * ARG: uwDstPID is checked with dst_ch, size is checked, others checked in ipc_msgsnd_core
 * RET: cid_to_hm_ch checked
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
uint32_t ipc_msg_snd(uint32_t uw_msg_id, msg_pid_t uw_dst_pid, const void *msgp, uint16_t size)
{
    cref_t dst_ch;
    msg_pid_t cid;
    struct msgsent_st msgsent;
    hm_debug("MsgSend Start to 0x%x msgid = 0x%lx size = %u\n", uw_dst_pid, uw_msg_id, size);

    if (size > MSG_MAX_LEN) {
        hm_error("msg too long!\n");
        return SRE_IPC_ERR;
    }

    cid = pid_to_cid(uw_dst_pid, 0);
    dst_ch = cid_to_hm_ch(cid);
    if (dst_ch == 0) {
        hm_error("Cannot get dest channel, MsgSnd abort to 0x%x\n", uw_dst_pid);
        return SRE_IPC_ERR;
    }

    msgsent.dst_ch     = dst_ch;
    msgsent.uw_msg_id  = uw_msg_id;
    msgsent.uw_dst_pid = uw_dst_pid;
    msgsent.msgp       = msgp;
    msgsent.size       = size;
    return ipc_msgsnd_core(msgsent, 0, cid);
}

uint32_t hm_ipc_send_msg_sync(uint32_t msg_id, msg_pid_t dest_pid, const void *msgp, uint32_t size)
{
    cref_t dst_ch;
    uint32_t cid;
    struct msgsent_st msgsent;

    cid = pid_to_cid(dest_pid, 0);
    dst_ch = cid_to_hm_ch(cid);
    if (dst_ch == 0) {
        hm_error("Cannot get dest channel of pid(0x%x)\n", dest_pid);
        return SRE_IPC_ERR;
    }

    msgsent.dst_ch     = dst_ch;
    msgsent.uw_msg_id  = msg_id;
    msgsent.uw_dst_pid = dest_pid;
    msgsent.msgp       = msgp;
    msgsent.size       = size;
    return ipc_msgsnd_core_sync(msgsent, 0, cid);
}

/*
 * CODEREVIEW CHECKLIST
 * Receive message and copy it to user space indicated by @msgp
 * ARG: all args would be checked in ipc_msg_rcv_a
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
uint32_t ipc_msg_rcv(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size)
{
    msg_pid_t sender_pid;
    return ipc_msg_rcv_a(uw_timeout, puw_msg_id, msgp, size, &sender_pid);
}

/*
 * Receive message from sender specified by wait_sender
 * CODEREVIEW CHECKLIST
 * ARG: all args would be checked in ipc_msg_rcv_a
 * RET: ipc_msg_rcv_a is checked
 * RACING: No global variable
 * LEAK: No allocation
 * CODEREVIEW CHECKLIST by j00413728 <zhaoxuqiang@huawei.com>
 */
uint32_t ipc_msg_rcv_safe(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size, msg_pid_t wait_sender)
{
    msg_pid_t sender = SRE_PID_ERR;
    uint32_t ret     = HM_OK;

    while (wait_sender != sender) {
        ret = ipc_msg_rcv_a(uw_timeout, puw_msg_id, msgp, (uint16_t)(size), &sender);
        if (ret != HM_OK) {
            hm_error("ipc msg Rcv failed, ret = 0x%x\n", ret);
            return ret;
        }

        if (wait_sender != sender)
            hm_error("recv msg from wrong sender %u/%u\n", sender, wait_sender);
    }

    return ret;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG: all args would be checked in ipc_msg_q_recv
 * RET: ipc_msg_q_recv is checked
 * RACING: No global variable
 * LEAK: No allocation
 * CODEREVIEW CHECKLIST by j00413728 <zhaoxuqiang@huawei.com>
 */
uint32_t ipc_msg_qrecv_safe(msg_handle_t *puw_msg_handle, uint32_t *puw_msg_id, msg_pid_t wait_sender)
{
    msg_pid_t sender = SRE_PID_ERR;
    uint32_t ret     = HM_OK;

    while (wait_sender != sender) {
        ret = ipc_msg_q_recv(puw_msg_handle, puw_msg_id, &sender, 1, OS_WAIT_FOREVER);
        if (ret != HM_OK) {
            hm_error("ipc msg q recv failed, ret = 0x%x\n", ret);
            return ret;
        }

        if (wait_sender != sender)
            hm_error("Qrecv msg from wrong sender %u/%u\n", sender, wait_sender);
    }

    return ret;
}

int32_t ipc_msg_receive(cref_t channel, void *recv_buf, size_t recv_len, cref_t msg_hdl,
                        struct src_msginfo *info, int32_t timeout)
{
    struct channel_ipc_args ipc_args = { 0 };
    struct hmcap_message_info hm_info = { 0 };
    ipc_args.channel = channel;
    ipc_args.recv_buf = recv_buf;
    ipc_args.recv_len = recv_len;

    cref_t _message_hdl = msg_hdl;
    if (_message_hdl == 0 || info == NULL)
        return E_EX_INVAL;

    int32_t err = hmapi_recv_timeout(&ipc_args, &_message_hdl, 0, timeout, &hm_info);

    if (err != 0) {
        return E_EX_INVAL;
    }

    info -> src_pid = (uint32_t)hm_info.src_cred.pid;
    info -> src_tid = TCBCREF2TID(hm_info.src_tcb_cref);
    info -> msg_type = hm_info.msg_type;

    return HM_OK;
}

/*
 * CODEREVIEW CHECKLIST
 * ARG: ch is always valid, from this module. uw_timeout is always valid.
 * puw_msg_id, msgp, puw_msg_handle, size, puw_sender_pid are checked
 * BUFOVF: memcpy_s: size is check by caller, size <= MSG_MAX_LEN
 * RET: ipc_msg_receive, memcpy_s, ipc_msg_reply is checked
 *      ipc_msg_receive would handle wrong msg_hdl
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
static uint32_t ipc_msgrcv_core(struct msgrcv_st msgrcv, msg_handle_t *puw_msg_handle)
{
    struct msg_st msg;
    struct reply_msg_st rmsg;
    struct src_msginfo info = { 0 };
    int32_t msg_ret;

    /* ipc_msg_receive would handle wrong msg_hdl */
    cref_t msg_hdl = ipc_get_my_msghdl();

    msg_ret = ipc_msg_receive(msgrcv.ch, &msg, sizeof(msg), msg_hdl, &info, msgrcv.timeout);
    if (msg_ret < 0) {
        if (msg_ret != E_EX_TIMER_TIMEOUT || msg_ret == E_EX_CNODE_INVOKE_NOCAP)
            hm_error("receive msg failed: %s\n", hmapi_strerror(msg_ret));
        return msg_ret == E_EX_TIMER_TIMEOUT ? SRE_IPC_TIMEOUT_ERR : SRE_IPC_ERR;
    }

    if (msgrcv.puw_msg_id != NULL)
        *(msgrcv.puw_msg_id) = msg.msg_id;
    if (msgrcv.puw_sender_pid != NULL) {
        if (info.src_pid == GLOBAL_HANDLE)
            *(msgrcv.puw_sender_pid) = GLOBAL_HANDLE;
        else
            *(msgrcv.puw_sender_pid) = (uint32_t)hmpid_to_pid(info.src_tid, info.src_pid);
    }
    if (msgrcv.msgp != NULL) {
        if (memcpy_s(msgrcv.msgp, msgrcv.size, msg.payload,
                     msgrcv.size < MSG_MAX_LEN ? msgrcv.size : MSG_MAX_LEN) != EOK) {
            hm_error("memcpy_s failed\n");
            return SRE_IPC_ERR;
        }
    }
    if (puw_msg_handle != NULL)
        *puw_msg_handle = 0;

    if (info.msg_type == HM_MSG_TYPE_CALL) {
        rmsg.status = HM_IPC_OK; /* unused field */
        int32_t rc  = ipc_msg_reply(msg_hdl, &rmsg, sizeof(rmsg));
        if (rc < 0) {
            hm_error("reply msg error %d\n", rc);
            return SRE_IPC_ERR;
        }
    } else if (info.msg_type == HM_MSG_TYPE_NOTIF) {
        hm_debug("Notification received, DONOT need to reply ch = 0x%llx\n", msg_hdl);
    } else {
        hm_error("Unexpected msg_recv %u\n", info.msg_type);
        return SRE_IPC_ERR;
    }

    return HM_OK;
}

/*
 * CODEREVIEW CHECKLIST
 * Receive message and copy it to user space indicated by @msgp,
 * and put the ID of sender to the last parm @puwSenderPID.
 * It's the caller's responsibility to make sure it was not NULL, otherwise no sender ID will return.
 * ARG: size checked, other args would be checked in ipc_msgrcv_core
 * RET: get_mych checked, ipc_msgrcv_core returned
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
uint32_t ipc_msg_rcv_a(uint32_t uw_timeout, uint32_t *puw_msg_id, void *msgp, uint16_t size, msg_pid_t *puw_sender_pid)
{
    cref_t ch;
    cref_t ch_timer = 0;
    uint32_t ret;
    struct msgrcv_st msgrcv;
    if (size > MSG_MAX_LEN) {
        hm_error(" msg too long!\n");
        return SRE_IPC_ERR;
    }

    ch = get_mych(0);
    if (ch == 0) {
        hm_error("Cannot recv, channel haven't been created yet\n");
        return SRE_IPC_NO_CHANNEL_ERR;
    }

    if (uw_timeout != OS_NO_WAIT && uw_timeout != OS_WAIT_FOREVER) {
        ch_timer = create_ch_timer(0);
        if (ch_timer == 0) {
            hm_error("Cannot recv, channel timer create failed\n");
            return SRE_IPC_NO_CHANNEL_ERR;
        }
    }

    msgrcv.ch             = ch;
    msgrcv.timer          = ch_timer;
    msgrcv.timeout        = (int32_t)uw_timeout;
    msgrcv.puw_msg_id     = puw_msg_id;
    msgrcv.msgp           = msgp;
    msgrcv.size           = size;
    msgrcv.puw_sender_pid = puw_sender_pid;
    ret = ipc_msgrcv_core(msgrcv, NULL);

    hm_debug("MsgRcv OK: 0x%x <- 0x%x msgid = 0x%x, size = %u\n", get_self_taskid(), puw_sender_pid ? *puw_sender_pid : 0,
             puw_msg_id ? *puw_msg_id : DEAD_MSG_ID, (uint32_t)size);

    return ret;
}

/*
 * CODEREVIEW CHECKLIST
 * The msg_handle_t type in original function declaration is NOT compatible with 64bit
 * So we DONOT integrate it with MsgSnd()
 * ARG: ucDstQID checked, other args would be checked in ipc_msgsnd_core
 * RET: cid_to_hm_ch checked, ipc_msgsnd_core returned
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
uint32_t ipc_msg_qsend(msg_handle_t uw_msg_handle, uint32_t uw_msg_id, msg_pid_t uw_dst_pid, uint8_t uc_dst_qid)
{
    cref_t dst_ch;
    uint32_t cid;
    struct msgsent_st msgsent;
    hm_debug("MsgQSend to 0x%x ch = %u\n", uw_dst_pid, uc_dst_qid);

    if (uc_dst_qid >= CH_CNT_MAX) {
        hm_error("Send channel Number overflow: %u\n", uc_dst_qid);
        return SRE_IPC_ERR;
    }

    if (global_handle_check(&uw_dst_pid) != 0) {
        hm_error("check uwDstPID against global handle failed\n");
        return SRE_IPC_ERR;
    }

    cid = pid_to_cid(uw_dst_pid, uc_dst_qid);
    dst_ch = cid_to_hm_ch(cid);
    if (dst_ch == 0) {
        hm_error("Cannot get dest channel, MsgSnd abort to 0x%x\n", uw_dst_pid);
        return SRE_IPC_ERR;
    }
    msgsent.dst_ch     = dst_ch;
    msgsent.uw_msg_id  = uw_msg_id;
    msgsent.uw_dst_pid = uw_dst_pid;
    msgsent.msgp       = NULL;
    msgsent.size       = 0;
    return ipc_msgsnd_core(msgsent, uw_msg_handle, cid);
}

/* this function not support send by both sender and receiver, it may dead lock */
uint32_t ipc_msg_qsend_sync(msg_handle_t uw_msg_handle, uint32_t uw_msg_id, msg_pid_t uw_dst_pid, uint8_t uc_dst_qid)
{
    cref_t dst_ch;
    msg_pid_t cid;
    struct msgsent_st msgsent;

    hm_debug("MsgQSend to 0x%x ch = %u\n", uw_dst_pid, uc_dst_qid);

    if (uc_dst_qid >= CH_CNT_MAX) {
        hm_error("Send channel Number overflow: %u\n", uc_dst_qid);
        return SRE_IPC_ERR;
    }

    if (global_handle_check(&uw_dst_pid) != 0) {
        hm_error("check uwDstPID against global handle failed\n");
        return SRE_IPC_ERR;
    }

    cid = pid_to_cid(uw_dst_pid, uc_dst_qid);
    dst_ch = cid_to_hm_ch(cid);
    if (dst_ch == 0) {
        hm_error("Cannot get dest channel, MsgSnd abort to 0x%x\n", uw_dst_pid);
        return SRE_IPC_ERR;
    }
    msgsent.dst_ch     = dst_ch;
    msgsent.uw_msg_id  = uw_msg_id;
    msgsent.uw_dst_pid = uw_dst_pid;
    msgsent.msgp       = NULL;
    msgsent.size       = 0;
    return ipc_msgsnd_core_sync(msgsent, uw_msg_handle, cid);
}

/*
 * CODEREVIEW CHECKLIST
 * QRecv() in RTOSck set the *puwMsgHandle with a msg node in kernel. It cannot be integrated with RevA()
 * ARG: ucRecvQID checked, other args would be checked in ipc_msgrcv_core
 * RET: get_mych checked, ipc_msgrcv_core returned
 * CODEREVIEW CHECKLIST by z00415816 <zhaoxuqiang@huawei.com>
 */
uint32_t ipc_msg_q_recv(msg_handle_t *puw_msg_handle, uint32_t *puw_msg_id, msg_pid_t *puw_sender_pid,
                        uint8_t uc_recv_qid, uint32_t uw_timeout)
{
    cref_t ch;
    cref_t ch_timer = 0;
    uint32_t ret;
    struct msgrcv_st msgrcv;
    if (uc_recv_qid >= CH_CNT_MAX) {
        hm_error("Recv channel Number overflow: %d\n", uc_recv_qid);
        return SRE_IPC_ERR;
    }

    ch = get_mych(uc_recv_qid);
    if (ch == 0) {
        hm_error("Cannot recv, channel haven't been created yet\n");
        return SRE_IPC_NO_CHANNEL_ERR;
    }

    if (uw_timeout != OS_NO_WAIT && uw_timeout != OS_WAIT_FOREVER) {
        ch_timer = create_ch_timer(uc_recv_qid);
        if (ch_timer == 0) {
            hm_error("Cannot recv, channel timer create failed\n");
            return SRE_IPC_NO_CHANNEL_ERR;
        }
    }

    msgrcv.ch             = ch;
    msgrcv.timer          = ch_timer;
    msgrcv.timeout        = (int32_t)uw_timeout;
    msgrcv.puw_msg_id     = puw_msg_id;
    msgrcv.msgp           = NULL;
    msgrcv.size           = 0;
    msgrcv.puw_sender_pid = puw_sender_pid;
    ret = ipc_msgrcv_core(msgrcv, puw_msg_handle);

    hm_debug("MsgQRcv OK: 0x%x <- 0x%x msgid = 0x%x\n", get_self_taskid(), puw_sender_pid ? *puw_sender_pid : 0,
             puw_msg_id ? *puw_msg_id : DEAD_MSG_ID);

    return ret;
}
