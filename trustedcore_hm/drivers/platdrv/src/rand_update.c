/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: update random
 * Create: 2021-08
 */

#include "rand_update.h"

#include <securec.h>
#include <hmlog.h>
#include "tee_log.h"

#include <hm_msg_type.h>
#include <sys/usrsyscall_ext.h>
#include <sys/hmapi_ext.h>
#include <api/kcalls.h>
#include <ccmgr_hm.h>
#include "crypto_driver_adaptor.h"

#ifndef HM_NO_TIMEOUT
#define HM_NO_TIMEOUT (-1)
#endif

#define DEFAULT_MSG_FLAG 0
#define DEFAULT_MSG_ID   0

static uint32_t get_rnd_msg(struct push_rnd_msg *msg)
{
    int32_t ret = hw_generate_random(msg->rnd, sizeof(msg->rnd));
    if (ret != CRYPTO_SUCCESS) {
        hm_error("driver generate random failed!\n");
        return offsetof(struct push_rnd_msg, rnd);
    }

    return sizeof(*msg);
}

static int32_t unknown_service(cref_t msg_hdl)
{
    int32_t ret;
    struct rand_reply_msg rmsg = { {{ 0 }}, {{ }} };

    rmsg.header.reply.ret_val  = -ENOSYS;
    rmsg.header.reply.msg_size = sizeof(rmsg);
    ret = hm_msg_reply(msg_hdl, &rmsg, sizeof(rmsg));
    if (ret != 0)
        tloge("hm_msg_reply failed\n");

    return ret;
}

static int32_t push_random(const struct hmcap_message_info *info)
{
    if (info->msg_type != HM_MSG_TYPE_NOTIF)
        tlogw("unexpected message type\n");

    struct push_rnd_msg msg = { {{ 0 }}, { 0 } };
    struct push_rnd_reply rmsg;
    uint32_t msg_size;
    int32_t ret;
    cref_t sysmgrch;

    msg_size = get_rnd_msg(&msg);
    sysmgrch = hmapi_get_sysmgrch();
    if (is_ref_err(sysmgrch) != 0)
        tloge("get_sysmgrch failed\n");

    msg.header.send.msg_class = HM_MSG_HEADER_CLASS_RECV_RND;
    msg.header.send.msg_flags = DEFAULT_MSG_FLAG;
    msg.header.send.msg_id = DEFAULT_MSG_ID;
    msg.header.send.msg_size  = msg_size;
    ret = hm_msg_call(sysmgrch, &msg, msg_size, &rmsg, sizeof(rmsg), 0, HM_NO_TIMEOUT);
    if (ret != 0) {
        tloge("hm msg call failed\n");
        return ret;
    }

    return (int32_t)rmsg.header.reply.ret_val;
}

intptr_t rand_update(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    int32_t ret;

    if (p_msg_hdl == NULL || msg == NULL || info == NULL)
        return -1;

    cref_t msg_hdl = *p_msg_hdl;
    hm_msg_header *msg_hdr = (hm_msg_header *)msg;

    switch (msg_hdr->send.msg_id) {
    case HM_MSG_ID_DRV_PUSHED_RANDOM:
        ret = push_random(info);
        break;
    default:
        ret = unknown_service(msg_hdl);
        break;
    }

    return ret;
}
