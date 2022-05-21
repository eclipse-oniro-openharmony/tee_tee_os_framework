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
#include <inttypes.h>
#include <hm_msg_type.h>
#include <pathmgr.h>
#include <securec.h>
#include "teesmcmgr.h"

#define NORMAL_MSG_ID 0xDEADBEEF
#define SMC_BUF_OPS (-1ULL)

struct gtask_msg {
    uint32_t msg_id;
    union {
        char payload[PAY_LOAD_SIZE];
        uint64_t kill_ca;
    };
} __attribute__((packed));

static unsigned short tee_smc_pm_ret_to_msg_id(enum cap_teesmc_ret ret)
{
    unsigned short msg_id;
    switch (ret) {
    case CAP_TEESMC_RET_CPU_SUSPEND:
        msg_id = HM_MSG_ID_DRV_PWRMGR_SUSPEND_CPU;
        break;
    case CAP_TEESMC_RET_CPU_RESUME:
        msg_id = HM_MSG_ID_DRV_PWRMGR_RESUME_CPU;
        break;
    case CAP_TEESMC_RET_S4_SUSPEND:
        msg_id = HM_MSG_ID_DRV_PWRMGR_SUSPEND_S4;
        break;
    case CAP_TEESMC_RET_S4_RESUME:
        msg_id = HM_MSG_ID_DRV_PWRMGR_RESUME_S4;
        break;
    default:
        msg_id = HM_MSG_ID_INVALID;
        break;
    }
    return msg_id;
}

static void tee_smc_pm_fallback_for_error(enum cap_teesmc_ret ret)
{
    enum cap_teesmc_req req;
    int32_t err;

    switch (ret) {
    case CAP_TEESMC_RET_CPU_SUSPEND:
        req = CAP_TEESMC_REQ_CPU_SUSPEND;
        break;
    case CAP_TEESMC_RET_CPU_RESUME:
        req = CAP_TEESMC_REQ_CPU_RESUME;
        break;
    case CAP_TEESMC_RET_S4_SUSPEND:
        req = CAP_TEESMC_REQ_S4_SUSPEND_DONE;
        break;
    case CAP_TEESMC_RET_S4_RESUME:
        req = CAP_TEESMC_REQ_S4_RESUME_DONE;
        break;
    default:
        req = CAP_TEESMC_REQ_NR;
        break;
    }

    err = hmex_teesmc_switch_req(get_teesmc_hdlr(), req);
    if (!err)
        info("CPU-PM fallback done id %d\n", ret);
    else
        error("CPU-PM fallback error %d id %d\n", err, ret);
}

static int32_t get_drv_cref(cref_t *drv_cref)
{
    cref_t drv = 0;
    int32_t err = pathmgr_acquire("platdrv", &drv);
    if (!(err != EOK || is_ref_err(drv))) {
        info("found platdrv channel\n");
        *drv_cref = drv;
        return 0;
    }

    err = pathmgr_acquire("tee_drv_server", &drv);
    if (!(err != EOK || is_ref_err(drv))) {
        info("found tee driver server channel\n");
        *drv_cref = drv;
        return 0;
    }

    return -1;
}

static void tee_smc_notify_drv(int32_t cpu, enum cap_teesmc_ret ret)
{
    static cref_t drv = 0;
    hm_msg_header msg     = { { 0 } };
    int32_t err;

    if (is_ref_err(drv)) {
        err = get_drv_cref(&drv);
        if (err != 0) {
            error("CPU%d can NOT found driver channel, error %d\n", cpu, err);
            tee_smc_pm_fallback_for_error(ret);
            return;
        }
    }

    debug("CPU%d notify driver start id %u\n", cpu, ret);
    msg.send.msg_class = HM_MSG_HEADER_CLASS_DRV_PWRMGR;
    msg.send.msg_id = tee_smc_pm_ret_to_msg_id(ret);
    msg.send.msg_size = sizeof(msg);
    err = hmex_channel_msgnotify(drv, &msg, sizeof(msg));
    if (err == 0) {
        info("CPU%d notify driver done id %u\n", cpu, ret);
    } else {
        error("CPU%d fail to notify driver id %d, error %d\n", cpu, ret, err);
        tee_smc_pm_fallback_for_error(ret);
    }
}

static void hmapi_configure(int32_t core)
{
    int32_t err;

    err = hmapi_set_priority(HM_PRIO_TEE_SMCMGR);
    if (err < 0)
        fatal("hmapi set priority failed: %s\n", hmapi_strerror(err));
    struct aff_bits_t aff = {0};
    hmapi_set_affinity_bits((uint32_t)core, &aff);
    err = hmapi_set_affinity(&aff);
    if (err < 0)
        fatal("hmapi set affinity failed: %s\n", hmapi_strerror(err));
    err = hmex_disable_local_irq(get_sysctrl_hdlr(), hmapi_tcb_cref());
    if (err < 0)
        fatal("hmex disable local irq failed: %s\n", hmapi_strerror(err));
}

__attribute__((noreturn)) void *tee_smc_thread(void *arg)
{
    int32_t err;
    int32_t core = (int32_t)(uintptr_t)(arg);
    errno_t ret_s;
    struct hmcap_teesmc_smc_buf smc_buf = {0};
    struct gtask_msg normal_msg = {0};
    static const char magic_msg[] = MAGIC_MSG;

    normal_msg.msg_id = NORMAL_MSG_ID;
    ret_s = memcpy_s(normal_msg.payload, sizeof(normal_msg.payload), magic_msg, sizeof(magic_msg));
    if (ret_s != EOK)
        fatal("memory copy failed\n");

    info("Start teesmc for core %d\n", core);
    hmapi_configure(core);
    hmapi_yield();

    while (1) {
        debug("tee smc thread: wait for switch req\n");
        smc_buf.ops = SMC_BUF_OPS;
        err = hmex_teesmc_wait_switch_req(get_teesmc_hdlr(), &smc_buf);
        debug("tee smc thread: return from REE, err=%d, ops=%" PRIx64 "\n", err, smc_buf.ops);

        bool flag = (err == CAP_TEESMC_RET_CPU_SUSPEND) || (err == CAP_TEESMC_RET_CPU_RESUME) ||
                    (err == CAP_TEESMC_RET_S4_SUSPEND) || (err == CAP_TEESMC_RET_S4_RESUME);
        if (err == CAP_TEESMC_RET_NORMAL) {
            if (get_is_gtask_alive() == 0)
                continue;

            err = 0;
            if (smc_buf.ops == HMCAP_TEESMC_OPS_NORMAL ||
                smc_buf.ops == HMCAP_TEESMC_OPS_ABORT_TASK)
                err = hmapi_notify(get_gtask_channel_hdlr(), NULL, 0);
            if (err < 0)
                error("failed to notify gtask, err=0x%x\n", err);
        } else if (flag) {
            tee_smc_notify_drv(core, err);
        } else {
            error("unexpected err=%x\n", err);
        }
    }
}
