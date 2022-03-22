/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: seceng powertest entry.
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/08/25
 */
#ifndef __HAL_SECENG_POWERTEST_H__
#define __HAL_SECENG_POWERTEST_H__
#include <pal_types.h>

err_bsp_t hal_seceng_shell(const char *pcmd);
err_bsp_t hal_seceng_stresstest(u32 times);
err_bsp_t hal_seceng_powertest(u32 argc, const char *argv[]);

#endif /* __HAL_SECENG_POWERTEST_H__ */
