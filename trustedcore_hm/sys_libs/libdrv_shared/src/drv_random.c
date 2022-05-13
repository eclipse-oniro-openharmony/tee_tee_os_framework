/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * Description: implament sysmgr get random
 * Create: 2022-01-01
 */
#include "drv_random.h"
#include <rnd_seed.h>
#include <sys/hmapi_ext.h>
#include <sys/hm_priorities.h>
#include <sys/fileio.h>
#include <sys/usrsyscall_ext.h>
#include <ac.h>
#include "tee_log.h"

static crypto_drv_init g_rand = 0;
static void *g_crypto_ops = NULL;

void register_crypto_rand_driver(crypto_drv_init fun, void *ops)
{
    g_rand = fun;
    g_crypto_ops = ops;
}

static int32_t drv_push_random(struct hmcap_message_info *info)
{
    int32_t ret;
    uint64_t rnd[PUSHED_RND_64_NUM] = { 0 };

    if (info == NULL || g_rand == 0 || g_crypto_ops == NULL) {
        tloge("invalid args or fun is not register\n");
        return -1;
    }

    ret = g_rand(g_crypto_ops, rnd, sizeof(rnd));
    if (ret != 0) {
        tloge("gen random failed\n");
        return ret;
    }

    return push_random(info, rnd, sizeof(rnd));
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
        ret = drv_push_random(info);
        break;
    default:
        ret = reply_invalid_rand_request(msg_hdl);
        break;
    }

    return (intptr_t)ret;
}
