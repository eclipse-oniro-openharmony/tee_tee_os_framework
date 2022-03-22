/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: This is internal header file for power contrl module.
 * Author: security-engine
 * Create: 2020-04-28
 */
#ifndef __MSPE_POWER_H__
#define __MSPE_POWER_H__
#include <hieps_power.h>
#include <common_define.h>

enum sec_bool_e mspe_sm9_is_inited(void);
uint32_t hieps_do_power_on(uint32_t id, uint32_t profile_id);
uint32_t hieps_do_power_off(uint32_t id, uint32_t profile_id);

/*
 * all ip initialize & self test for factory test
 */
err_bsp_t mspe_factory_test(void);

#endif /*  __MSPE_POWER_H__ */
