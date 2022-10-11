/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: moved from teeos, driver module init function and structure
 * Create: 2019-11-08
 */
#ifndef DRIVERS_DRV_MODULE_H
#define DRIVERS_DRV_MODULE_H
#include <stdint.h>
#include "sre_typedef.h"
#include "drv_param_type.h"

/* parameter type between platdrv and drivers */
typedef struct tagTskRegs {
    uint32_t r0;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint32_t r4;
    uint32_t r5;
    uint32_t r6;
    uint32_t r7;
    uint32_t r8;
    uint32_t r9;
    uint32_t r10;
    uint32_t r11;
    uint32_t r12;
    uint32_t usr_sp;
    uint32_t usr_lr;
    uint32_t svc_sp;
    uint32_t svc_lr;
    uint32_t pc;
    uint32_t cpsr;
    uint64_t job_handler;
} TSK_REGS_S;

enum TC_DRV_Priority {
    TC_DRV_EARLY_INIT  = 0, /* In the begining of main function, before RTOSck init */
    TC_DRV_ARCH_INIT   = 1, /* After mmu and platform init */
    TC_DRV_MODULE_INIT = 2, /* After RTOSck Init */
    TC_DRV_LATE_INIT   = 3  /* After globaltask create */
};

typedef int32_t (*tc_drv_init_t)(void);

typedef uint64_t (*tc_drv_handle_t)(uint32_t x0, uint32_t x1, uint32_t x2, uint32_t x3,
                                    uint32_t x4, void *y1, void *y2, uint32_t z1);

typedef int32_t (*tc_drv_syscall_t)(int swi_id, struct drv_param *params, uint64_t permissions);
typedef int32_t (*tc_drv_sp_t)(void);
typedef int32_t (*tc_drv_sr_t)(void);

typedef int32_t (*tc_drv_sp_timer)(uint32_t flag);
typedef int32_t (*tc_drv_sr_timer)(uint32_t flag);

#ifndef TEE_SUPPORT_M_DRIVER
struct tc_drv_desc {
    uint8_t reserve1;
    tc_drv_sp_t suspend_s4;
    tc_drv_sr_t resume_s4;
    uint8_t priority;
    const char *name;
    tc_drv_init_t init;
    tc_drv_handle_t handle;
    tc_drv_syscall_t syscall;
    tc_drv_sp_t suspend;
    tc_drv_sr_t resume;
};

#define DECLARE_TC_DRV(_name, _reserve1, _suspend_s4, _resume_s4, _priority, _setup, \
                       _smch, _syscall, _suspend, _resume) \
    const struct tc_drv_desc __drv_desc_##_name __attribute__((section(".tc_drv_descs"), used)) = \
    { _reserve1, _suspend_s4, _resume_s4, _priority, #_name, _setup, _smch, _syscall,  _suspend, _resume }

#define DECLARE_TC_DRV_MULTI(_name, _reserve1, _suspend_s4, _resume_s4, _priority, _setup, \
                             _smch, _syscall, _suspend, _resume) \
    const struct tc_drv_desc __drv_desc_multi_##_name __attribute__((section(".tc_drv_descs_multi"), used)) = \
    { _reserve1, _suspend_s4, _resume_s4, _priority, #_name, _setup, _smch, _syscall,  _suspend, _resume }

#define DECLARE_TC_DRV_SELF_MULTI(_name, _reserve1, _suspend_s4, _resume_s4, _priority, _setup, _smch, \
                                 _syscall, _suspend, _resume) \
const struct tc_drv_desc __drv_desc_self_multi_##_name __attribute__((section(".tc_drv_descs_self_multi"), used)) = \
    { _reserve1, _suspend_s4, _resume_s4, _priority, #_name, _setup, _smch, _syscall,  _suspend, _resume }

#else

typedef int32_t (*invoke_cmd_func)(uint32_t sid, uint32_t cmd, unsigned long args);
typedef int32_t (*open_func)(uint32_t sid, unsigned long args);
typedef int32_t (*close_func)(uint32_t sid);
typedef int32_t (*ree_cmd_func)(uint32_t sid, unsigned long args);

struct syscall_entry {
    int32_t drv_id;
    open_func open_fn;
    invoke_cmd_func invoke_fn;
    close_func close_fn;
    ree_cmd_func ree_fn;
};

typedef int32_t (*vendor_drv_init)(void *);
typedef int32_t (*vendor_syscall)(const struct syscall_entry *fn_entry, int32_t swi_id,
    struct drv_param *params, uint64_t permissions);
int32_t vendor_syscall_fn(const struct syscall_entry *fn_entry, int32_t swi_id,
    struct drv_param *params, uint64_t permissions);

struct tc_drv_desc {
    uint8_t reserve1;
    uint8_t reserve2;
    uint8_t reserve3;
    uint8_t priority;
    const char *name;
    tc_drv_init_t init;
    tc_drv_handle_t handle;
    tc_drv_syscall_t syscall;
    tc_drv_sp_t suspend;
    tc_drv_sr_t resume;
    vendor_drv_init vendor_init;
    vendor_syscall vendor_call;
    struct syscall_entry fn_entry;
};

#define DECLARE_TC_DRV(_name, _reserve1, _reserve2, _reserve3, _priority, _setup, _smch, _syscall, _suspend, _resume) \
    const struct tc_drv_desc __drv_desc_##_name __attribute__((section(".tc_drv_descs"), used)) = \
    { _reserve1, _reserve2, _reserve3, _priority, #_name, _setup, _smch, _syscall,  _suspend, _resume, \
      0, 0, { 0, 0, 0, 0, 0 } }

#define DECLARE_TC_DRV_MULTI(_name, _reserve1, _reserve2, _reserve3, _priority, \
                             _setup, _smch, _syscall, _suspend, _resume) \
    const struct tc_drv_desc __drv_desc_multi_##_name __attribute__((section(".tc_drv_descs_multi"), used)) = \
    { _reserve1, _reserve2, _reserve3, _priority, #_name, _setup, _smch, _syscall,  _suspend, _resume, \
      0, 0, { 0, 0, 0, 0, 0 } }

#define DECLARE_TC_DRV_SELF_MULTI(_name, _reserve1, _reserve2, _reserve3, _priority, \
                                  _setup, _smch, _syscall, _suspend, _resume) \
const struct tc_drv_desc __drv_desc_self_multi_##_name __attribute__((section(".tc_drv_descs_self_multi"), used)) = \
    { _reserve1, _reserve2, _reserve3, _priority, #_name, _setup, _smch, _syscall,  _suspend, _resume, \
      0, 0, { 0, 0, 0, 0, 0 } }

#define DECLARE_DRIVER_MODULE(_name, _drv_id, _init_fn, _invoke_cmd_fn, _ree_cmd_fn, _open_fn, _cloe_fn) \
    const struct tc_drv_desc __drv_desc_##_name __attribute__((section(".tc_drv_descs"), used)) = \
    { 0, 0, 0, TC_DRV_MODULE_INIT, #_name, 0, 0, 0, 0, 0, \
      _init_fn, vendor_syscall_fn, { _drv_id, _open_fn, _invoke_cmd_fn, _cloe_fn, _ree_cmd_fn } }
#endif

struct tc_drv_desc_timer {
    uint8_t reserve1;
    uint8_t reserve2;
    uint8_t reserve3;
    uint8_t priority;
    const char *name;
    tc_drv_init_t init;
    tc_drv_handle_t handle;
    tc_drv_syscall_t syscall;
    tc_drv_sp_timer suspend;
    tc_drv_sr_timer resume;
};

#define DECLARE_TC_TIMER(_name, _reserve1, _reserve2, _reserve3, _priority, \
                         _setup, _smch, _syscall, _suspend, _resume) \
    const struct tc_drv_desc_timer __drv_desc_##_name __attribute__((section(".tc_drv_descs"), used)) = \
    { _reserve1, _reserve2, _reserve3, _priority, #_name, _setup, _smch, _syscall,  _suspend, _resume }

#endif /* DRIVERS_DRV_MODULE_H */
