/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * Description: security engine utilities
 * Author     : m00475438
 * Create     : 2017/12/30
 */
#ifndef __SECENG_UTILS_H__
#define __SECENG_UTILS_H__
#include <common_define.h>
#include <common_engctrl.h>

u32 random_value(u32 min, u32 max);
err_bsp_t smx_check_support(u32 smx_e);

#endif /* end of __SECENG_UTILS_H__ */
