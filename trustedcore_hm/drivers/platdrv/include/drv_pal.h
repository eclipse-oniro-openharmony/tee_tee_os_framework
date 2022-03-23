/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: Declare the function define in drv_pal.c
 * Create: 2019-12-10
 */
#ifndef PLATDRV_DRV_PAL_H
#define PLATDRV_DRV_PAL_H
#include <stdint.h>
#include <sre_typedef.h>
#include <sys/hm_types.h>
#include <cache_flush.h>

uint32_t task_caller(uint32_t *caller_id);
pid_t get_g_caller_pid(void);
void set_g_caller_pid(pid_t caller_pid);
#endif /* PLATDRV_DRV_PAL_H */
