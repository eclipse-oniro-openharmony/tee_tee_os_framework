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
#include <rnd_seed.h>
#include "crypto_driver_adaptor.h"

intptr_t rand_update(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info)
{
    int32_t ret;
    uint64_t rnd[PUSHED_RND_64_NUM] = { 0 };

    if (p_msg_hdl == NULL || msg == NULL || info == NULL)
        return -1;

    cref_t msg_hdl = *p_msg_hdl;
    hm_msg_header *msg_hdr = (hm_msg_header *)msg;

    switch (msg_hdr->send.msg_id) {
    case HM_MSG_ID_DRV_PUSHED_RANDOM:
        ret = hw_generate_random(rnd, sizeof(rnd));
        if (ret != CRYPTO_SUCCESS) {
            hm_error("generate random failed\n");
            return (intptr_t)ret;
        }
        ret = push_random(info, rnd, sizeof(rnd));
        break;
    default:
        ret = reply_invalid_rand_request(msg_hdl);
        break;
    }

    return (intptr_t)ret;
}
