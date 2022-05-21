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

#include <stdio.h>
#include <securec.h>
#include "teesmcmgr.h"

#define GTASK_MSG_ID 0xDEADBEEF
#define RECV_BUF_SIZE 32

struct gtask_msg {
    uint32_t msg_id;
    char payload[PAY_LOAD_SIZE];
} __attribute__((packed));

static bool g_tz_started;

static void starttz_core(void)
{
    int32_t err;
    errno_t ret_s;
    struct gtask_msg gtask_msg;
    static const char magic_msg[] = MAGIC_MSG;
    char recv_buf[RECV_BUF_SIZE] = {0};
    gtask_msg.msg_id = GTASK_MSG_ID;
    ret_s = memcpy_s(gtask_msg.payload, sizeof(gtask_msg.payload), magic_msg, sizeof(magic_msg));
    if (ret_s != EOK)
        fatal("memory copy failed\n");

    debug("the tee smc hdlr = %llx\n", get_teesmc_hdlr());
    g_tz_started = true;
    err = hmex_teesmc_switch_req(get_teesmc_hdlr(), CAP_TEESMC_REQ_STARTTZ);
    if (err < 0)
        fatal("starttz failed: %s\n", hmapi_strerror(err));
    /*
     * Why we need this hmex_channel_call?
     * As smcmgr send notification to gtask after check smc.ops is valid,
     * but the first normal request 'set smc buffer' is send by raw_smc_send
     * that smc.ops is set to be smc buffer's physical addr.
     */
    err = hmex_channel_call(get_gtask_channel_hdlr(), &gtask_msg, sizeof(struct gtask_msg), recv_buf, sizeof(recv_buf));
    if (err < 0)
        panic("failed to send magic to gtask: %s\n", hmapi_strerror(err));
    debug("GT return %d\n", err);
}

static void judge_ondone(void)
{
    int32_t err;
    err = hmex_teesmc_switch_req(get_teesmc_hdlr(), CAP_TEESMC_REQ_ONDONE);
    if (err < 0)
        fatal("ondone failed: %s\n", hmapi_strerror(err));
}

__attribute__((noreturn)) void *tee_idle_thread(void *arg)
{
    int32_t err;
    if (arg == NULL)
        fatal("wrong param: arg is null\n");

    uint32_t startup_core = ((struct idle_thread_params *)arg)->startup_core;
    uint32_t core = ((struct idle_thread_params *)arg)->idle_core;

    info("Start tee idle for core %u with startup %u\n", core, startup_core);

    err = hmapi_set_priority(HM_PRIO_TEE_SMCMGR_IDLE);
    if (err < 0)
        fatal("hmapi set priority failed: %s\n", hmapi_strerror(err));
    struct aff_bits_t aff = {0};
    hmapi_set_affinity_bits(core, &aff);
    err = hmapi_set_affinity(&aff);
    if (err < 0)
        fatal("hmapi set priority failed: %s\n", hmapi_strerror(err));
    hmapi_yield();

    if (core == startup_core) {
        starttz_core();
        debug("StartTZ done on core %u\n", core);
    } else {
        debug("Core %u CPU on done, trigger switching\n", core);
        while (!g_tz_started)
            hmapi_yield();
        judge_ondone();
        debug("Ondone end on CPU %u\n", core);
    }

    while (1) {
        debug("calling hmex teesmc switch req %" PRIx64 ", core %u\n", get_teesmc_hdlr(), core);
        err = hmex_teesmc_switch_req(get_teesmc_hdlr(), CAP_TEESMC_REQ_IDLE);
        debug("hmex teesmc switch req return %" PRIx64 ", core %u, err=%d %s\n", get_teesmc_hdlr(), core, err,
              hmapi_strerror(err));
    }
}
