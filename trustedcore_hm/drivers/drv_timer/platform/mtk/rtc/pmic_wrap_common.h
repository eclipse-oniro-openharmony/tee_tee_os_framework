/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: rtc timer pmic_wrap related functions defined in this file.
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-09-07
 */
#ifndef DRV_TIMER_PLATFORM_RTC_PMIC_WRAP_COMMON_H
#define DRV_TIMER_PLATFORM_RTC_PMIC_WRAP_COMMON_H

#include <stdint.h>
#include <timer_base_reg.h>

#define NS_PER_US     1000

#define REG_DATA_BASE_INIT  0x00000001U
#define REG_DATA_BASE_FSM   0x00000007U

/* external API */
uint32_t get_swinf_init_done(uint32_t x);
int32_t wait_for_state_idle(uint32_t timeout_us, uintptr_t wacs_register, uintptr_t wacs_vldclr_register);
int32_t wait_for_state_ready(uint32_t timeout_us, uintptr_t wacs_register, uint32_t *read_reg);

/* Error handle */
#define E_INVALID_ARG               1
#define E_INVALID_RW                2
#define E_INVALID_ADDR              3
#define E_INVALID_WDAT              4
#define E_INVALID_OP_MANUAL         5
#define E_NOT_IDLE_STATE            6
#define E_NOT_INIT_DONE             7
#define E_NOT_INIT_DONE_READ        8
#define E_WAIT_IDLE_TIMEOUT         9
#define E_WAIT_IDLE_TIMEOUT_READ    10
#define E_INIT_SIDLY_FAIL           11
#define E_RESET_TIMEOUT             12
#define E_TIMEOUT                   13
#define E_INVALID_SWINF             14
#define E_INVALID_CMD               15
#define E_INVALID_PMIFID            16
#define E_INVALID_SLVID             17
#define E_INVALID_BYTECNT           18
#define E_INIT_RESET_SPI            20
#define E_INIT_SIDLY                21
#define E_INIT_REG_CLOCK            22
#define E_INIT_ENABLE_PMIC          23
#define E_INIT_DIO                  24
#define E_INIT_CIPHER               25
#define E_INIT_WRITE_TEST           26
#define E_INIT_ENABLE_CRC           27
#define E_INIT_ENABLE_DEWRAP        28
#define E_READ_TEST_FAIL            30
#define E_WRITE_TEST_FAIL           31
#define E_SWITCH_DIO                32

#define DEFAULT_VALUE_READ_TEST         0x5aa5
#define PWRAP_WRITE_TEST_VALUE          0xa55a

/* timeout setting */
enum {
    TIMEOUT_RESET   = 0x2710, /* 10000us */
    TIMEOUT_READ    = 0x2710, /* 10000us */
    TIMEOUT_IDLE    = 0x2710  /* 10000us */
};

/* WACS_FSM */
enum {
    WACS_FSM_IDLE            = 0x00,
    WACS_INIT_DONE           = 0x01,
    WACS_FSM_REQ             = 0x02,
    WACS_FSM_WFDLE           = 0x04,
    WACS_FSM_WFVLDCLR        = 0x06
};

#endif
