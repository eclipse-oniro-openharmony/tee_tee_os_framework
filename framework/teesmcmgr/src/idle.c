/*$$$!!Warning: Huawei key information asset. No spread without permission.$$$*/
/*CODEMARK:mJSkoqPZ5FEeD8fzH9bAQfhyPrkcI5cbzjotjI99J9PTkCMNHMtR+8Ejd3mKEkWbMFYmuIhV
lw/je6uplRzXM4SMvhun8vRGD9mNqO2kY4/aQFDUiG2CG+z+BR1XavYOLbgQ6mxl4mdMDMUc
pTTvsgNnGY+uGDhrcSrYT/yiWUcPU+7hHj/1z+1w4sei8NKrE5YtD4ycmPizGfaNhWQY5YvG
yUQ4I+iaikKhay3gs3gbvr2F/fo9kmuK6WNlljMWqZQckvm//k0TiyJFZq4NZA==#*/
/*$$$!!Warning: Deleting or modifying the preceding information is prohibited.$$$*/
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: idle thread functions
 * Create: 2020-05-12
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
static bool g_send_to_gtask = false;

static void send_to_gtask()
{
    if (g_send_to_gtask)
        return;

    int32_t err;
    struct gtask_msg gtask_msg;
    static const char magic_msg[] = MAGIC_MSG;
    char recv_buf[RECV_BUF_SIZE] = {0};
    gtask_msg.msg_id = GTASK_MSG_ID;
    errno_t ret_s = memcpy_s(gtask_msg.payload, sizeof(gtask_msg.payload), magic_msg, sizeof(magic_msg));
    if (ret_s != EOK)
        fatal("memory copy failed\n");

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

    g_send_to_gtask = true;
}

static void starttz_core(void)
{
    g_tz_started = true;
    int32_t err = hmex_teesmc_switch_req(get_teesmc_hdlr(), CAP_TEESMC_REQ_STARTTZ);
    if (err < 0)
        fatal("starttz failed: %s\n", hmapi_strerror(err));

    send_to_gtask();
}

__attribute__((noreturn)) void *tee_idle_thread(void *arg)
{
    (void)arg;

    int32_t err = hmapi_set_priority(HM_PRIO_TEE_SMCMGR_IDLE);
    if (err < 0)
        fatal("hmapi set priority failed: %s\n", hmapi_strerror(err));
    hmapi_yield();

    starttz_core();
    error("StartTZ done\n");

    while (1) {
        debug("calling hmex teesmc switch req\n");
        err = hmex_teesmc_switch_req(get_teesmc_hdlr(), CAP_TEESMC_REQ_IDLE);
        debug("hmex teesmc switch req return err=%d %s\n", err, hmapi_strerror(err));
        if (err != 0)
            fatal("something wrong");
    }
}
