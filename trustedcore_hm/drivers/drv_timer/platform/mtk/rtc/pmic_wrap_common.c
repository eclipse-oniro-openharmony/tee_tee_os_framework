/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rtc timer pmic_wrap related functions defined in this file.
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-09-07
 */

#include "pmic_wrap_common.h"
#include <stdbool.h>
#include <hmlog.h>
#include <register_ops.h>
#include "timer_types.h"
#include "timer_sys.h"

uint32_t get_swinf_init_done(uint32_t x)
{
    return ((x >> REG_DATA_SHIFT_INIT) & REG_DATA_BASE_INIT);
}

static uint32_t get_swinf_fsm(uint32_t x)
{
    return ((x >> REG_DATA_SHIFT_FSM) & REG_DATA_BASE_FSM);
}

static uint64_t pwrap_get_current_time(void)
{
    return (uint64_t)timer_stamp_value_read();
}

static bool pwrap_timeout_ns(uint64_t start_time_ns, uint64_t timeout_time_ns)
{
    uint64_t cur_time;
    uint64_t elapse_time;

    /* get current tick */
    cur_time = pwrap_get_current_time();  /* ns */

    elapse_time = cur_time - start_time_ns;

    /* check if timeout */
    if (timeout_time_ns <= elapse_time) {
        hm_error("[PWRAP] Timeout start time: %lld\n", start_time_ns);
        hm_error("[PWRAP] Timeout cur time: %lld\n", cur_time);
        hm_error("[PWRAP] Timeout elapse time: %lld\n", elapse_time);
        hm_error("[PWRAP] Timeout set timeout: %lld\n", timeout_time_ns);
        return true;
    }

    return false;
}

static uint64_t pwrap_time2ns(uint64_t time_us)
{
    return time_us * NS_PER_US;
}

static inline bool wait_for_fsm_idle(uint32_t x)
{
    return get_swinf_fsm(x) != WACS_FSM_IDLE;
}

static inline bool wait_for_fsm_vldclr(uint32_t x)
{
    return get_swinf_fsm(x) != WACS_FSM_WFVLDCLR;
}

int32_t wait_for_state_idle(uint32_t timeout_us, uintptr_t wacs_register, uintptr_t wacs_vldclr_register)
{
    uint64_t start_time_ns;
    uint64_t timeout_ns;
    uint32_t reg_rdata;

    if (wacs_register == 0 || wacs_vldclr_register == 0) {
        hm_error("invalid addr\n");
        return -E_INVALID_ARG;
    }

    start_time_ns = pwrap_get_current_time();
    timeout_ns = pwrap_time2ns(timeout_us);

    do {
        if (pwrap_timeout_ns(start_time_ns, timeout_ns)) {
            hm_error("[PWRAP] state_idle timeout\n");
            return -E_WAIT_IDLE_TIMEOUT;
        }
        reg_rdata = read32(wacs_register);
        if (get_swinf_init_done(reg_rdata) != WACS_INIT_DONE) {
            hm_error("[PWRAP] init isn't finished\n");
            return -E_NOT_INIT_DONE;
        }

        switch (get_swinf_fsm(reg_rdata)) {
        case WACS_FSM_WFVLDCLR:
            write32(wacs_vldclr_register, 1);
            break;
        case WACS_FSM_WFDLE:
            break;
        case WACS_FSM_REQ:
            break;
        default:
            break;
        }
    } while (wait_for_fsm_idle(reg_rdata));

    return TMR_DRV_SUCCESS;
}

int32_t wait_for_state_ready(uint32_t timeout_us, uintptr_t wacs_register, uint32_t *read_reg)
{
    uint64_t start_time_ns;
    uint64_t timeout_ns;
    uint32_t reg_rdata;

    if (wacs_register == 0 || read_reg == NULL) {
        hm_error("invalid paramters\n");
        return -E_INVALID_ARG;
    }

    start_time_ns = pwrap_get_current_time();
    timeout_ns = pwrap_time2ns(timeout_us);

    do {
        if (pwrap_timeout_ns(start_time_ns, timeout_ns)) {
            hm_error("[PWRAP] state_ready timeout\n");
            return -E_WAIT_IDLE_TIMEOUT;
        }
        reg_rdata = read32(wacs_register);
        if (get_swinf_init_done(reg_rdata) != WACS_INIT_DONE) {
            hm_error("[PWRAP] init isn't finished\n");
            return -E_NOT_INIT_DONE;
        }
    } while (wait_for_fsm_vldclr(reg_rdata));
    if (read_reg != NULL)
        *read_reg = reg_rdata;

    return TMR_DRV_SUCCESS;
}
