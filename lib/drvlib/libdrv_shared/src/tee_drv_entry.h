/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: define drv main function
 * Create: 2021-07-23
 */
#ifndef LIBDRV_SHARED_SRC_TEE_DRV_ENTRY_H
#define LIBDRV_SHARED_SRC_TEE_DRV_ENTRY_H

#include <stdio.h>
#include <posix_types.h>
#include <msg_ops.h>
#include <spawn_init.h>
#include <tee_driver_module.h>

typedef void (*drv_entry_func)(const struct tee_driver_module *drv_func, const char *drv_name,
    cref_t channel, const struct env_param *param);

msg_pid_t get_drv_mgr_pid(void);
const struct tee_driver_module *get_drv_func(void);
uint32_t get_drv_index(void);

#endif
