/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: define macro and declare interface related driver hash.
 * Create: 2020-06-24
 */
#ifndef PLATDRV_DRV_HASH_H
#define PLATDRV_DRV_HASH_H
#include <stdint.h>
#include <drv_module.h>
#include <cs.h>

#define DRV_MOUDLE_MAX 64
#define ID_MAX         0x100
#define MAP_ID_MAX     (8 * ID_MAX)
extern uint32_t g_tc_drv_descs_start;
extern uint32_t g_tc_drv_descs_end;
#define TC_DRV_DESCS_START ((uintptr_t)(&g_tc_drv_descs_start))
#define TC_DRV_DESCS_END   ((uintptr_t)(&g_tc_drv_descs_end))

extern uint32_t g_tc_drv_descs_multi_start;
extern uint32_t g_tc_drv_descs_multi_end;
#define TC_DRV_DESCS_MULTI_START      ((uintptr_t)(&g_tc_drv_descs_multi_start))
#define TC_DRV_DESCS_MULTI_END        ((uintptr_t)(&g_tc_drv_descs_multi_end))

extern uint32_t g_tc_drv_descs_self_multi_start;
extern uint32_t g_tc_drv_descs_self_multi_end;
#define TC_DRV_DESCS_SELF_MULTI_START      ((uintptr_t)(&g_tc_drv_descs_self_multi_start))
#define TC_DRV_DESCS_SELF_MULTI_END        ((uintptr_t)(&g_tc_drv_descs_self_multi_end))


#define register_drv_module(na)                                                                  \
    do {                                                                                         \
        if (g_drv_module_size < DRV_MOUDLE_MAX) {                                                \
            init_info[g_drv_module_size].name = ""#na"";                                         \
            init_info[g_drv_module_size].syscall_list = g_##na##_id;                             \
            init_info[g_drv_module_size++].syscall_num = sizeof(g_##na##_id) / sizeof(uint16_t); \
        }                                                                                        \
    } while (0);

enum module_thread_flag {
    MODULE_SINGLE_THREAD_FLAG = 0,
    MODULE_MULTI_THREAD_FLAG,
    MODULE_SELF_MULTI_THREAD_FLAG,
    INVALID_MODULE_THREAD_FLAG,
};

struct module_info {
    char *name;
    uint16_t *syscall_list;
    uint16_t syscall_num;
    tc_drv_syscall_t syscall;
    enum module_thread_flag multi_flag;
};

struct drv_map_id_info {
    uint16_t id;
    char *name;
};

void drv_hash_map(void);
void drv_module_init(void);
uint32_t get_drv_module_size(void);
struct module_info *get_g_module_info(void);
struct module_info *find_drv_module(int32_t swi_id);
tc_drv_syscall_t find_drv_syscall_by_id(int32_t swi_id);
intptr_t single_thread_driver_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);
#endif
