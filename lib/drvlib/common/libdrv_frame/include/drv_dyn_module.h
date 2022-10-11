/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: dyn driver module init function and structure
 * Create: 2020-09-15
 */
#ifndef DRIVERS_DRV_DYN_MODULE_H
#define DRIVERS_DRV_DYN_MODULE_H
#include <stdint.h>
#include <drv_module.h>

typedef void (*tc_drv_exit_t)(void);

struct tc_drv_dyn_desc {
    uint8_t reserve1;
    uint8_t reserve2;
    uint8_t reserve3;
    uint8_t priority;
    const char *name;
    tc_drv_init_t init;
    tc_drv_exit_t exit;
    tc_drv_handle_t handle;
    tc_drv_syscall_t syscall;
    tc_drv_sp_t suspend;
    tc_drv_sr_t resume;
};

#define DECLARE_TC_DYN_DRV\
(_name, _reserve1, _reserve2, _reserve3, _priority, _setup, _exit, _smch, _syscall, _suspend, _resume) \
    const struct tc_drv_dyn_desc __drv_desc_##_name = \
    { _reserve1, _reserve2, _reserve3, _priority, #_name, _setup, _exit, _smch, _syscall, _suspend, _resume }

#define DECLARE_TC_DYN_DRV_MULTI\
(_name, _reserve1, _reserve2, _reserve3, _priority, _setup, _exit, _smch, _syscall, _suspend, _resume) \
    const struct tc_drv_dyn_desc __drv_desc_multi_##_name = \
    { _reserve1, _reserve2, _reserve3, _priority, #_name, _setup, _exit, _smch, _syscall, _suspend, _resume }

#endif
