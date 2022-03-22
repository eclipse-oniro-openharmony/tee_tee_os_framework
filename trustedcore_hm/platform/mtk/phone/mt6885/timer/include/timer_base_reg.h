/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: base_reg defines
 * Author: zhangdeyao zhangdeyao@huawei.com
 * Create: 2020-11-09
 */
#ifndef TIMER_BASE_REG_H
#define TIMER_BASE_REG_H

/* tick tiemr fiq numbler */
#define TICK_TIMER_FIQ_NUMBLER   262

/* rtc PMIC_WRAP BASE ADDR */
#define PMIF_SPI_BASE       0x10026000

/* rtc timer pmic_wrap_swinf_no */
#define PMIC_SWINF_NO       2

/* PMIC_WRAP check statue */
#define REG_DATA_SHIFT_INIT 15U
#define REG_DATA_SHIFT_FSM  1U

#endif
