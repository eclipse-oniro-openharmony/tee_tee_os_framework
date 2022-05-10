/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: driver module manage function and structure
 * Create: 2020-08-31
 */
#ifndef DRIVERS_DRV_MOD_H
#define DRIVERS_DRV_MOD_H

#include <stdint.h>
#include <drv_dyn_module.h>
#include <dlist.h>
#include <uidgid.h>

#define DRV_MOD_NAME_LEN   32
#define FUNC_NAME_SIZE 64

struct drv_module_info {
    struct dlist_node list;
    char name[DRV_MOD_NAME_LEN];
    uid_t uid;
    struct tc_drv_dyn_desc *mod_entry;
    struct tc_drv_dyn_desc *mod_multi_entry;
    uint32_t refcnt;
    void *lib_handle;
};

#ifdef CONFIG_DRIVER_DYN_MOD
int mod_drv_syscall(int32_t swi_id, struct drv_param *params, uint64_t perm, bool multi);

#else
static inline int mod_drv_syscall(int32_t swi_id, struct drv_param *params, uint64_t perm, bool multi)
{
    (void)swi_id;
    (void)params;
    (void)perm;
    (void)multi;
    return -1;
}

#endif

#endif
