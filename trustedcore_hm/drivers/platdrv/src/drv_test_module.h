/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: platdrv vendor cmd handle test
 * Create: 2020-10-12
 */
#ifndef PLATDRV_DRV_TEST_MODULE_H
#define PLATDRV_DRV_TEST_MODULE_H
#include <stdint.h>

int32_t init_test(void *param);
int32_t invoke_test(uint32_t sid, uint32_t cmd, unsigned long args);
int32_t ree_test(uint32_t sid, unsigned long args);
int32_t open_test(uint32_t sid, unsigned long args);
int32_t close_test(uint32_t sid);

#endif
