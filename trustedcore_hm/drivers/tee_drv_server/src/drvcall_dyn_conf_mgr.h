/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 * Description: handle drvcall dyn perm info
 * Create: 2021-02-03
 */

#ifndef TEE_DRV_SERVER_DRVCALL_DYN_CONF_MGR_H
#define TEE_DRV_SERVER_DRVCALL_DYN_CONF_MGR_H

#include <stdint.h>
#include <pthread.h>
#include <list.h>
#include <tee_defines.h>
#include <tee_driver_module.h>
#include "drv_dispatch.h"
#include "dyn_conf_common.h"

#define DRVCALL_DEC_CNT_INCLUDE_REGISTER_ONE 2U

struct drvcall_conf_t {
    struct tee_uuid uuid;
    struct drvcall_perm_apply_t drvcall_perm_apply;
};

struct fd_node {
    struct list_head data_list;
    int64_t fd;
    struct task_node *drv;
    bool close_flag;
};

void dump_all_drvcall_conf(void);

int32_t receive_perm_apply_list(struct drvcall_perm_apply_t *drvcall_perm_apply);

#endif
