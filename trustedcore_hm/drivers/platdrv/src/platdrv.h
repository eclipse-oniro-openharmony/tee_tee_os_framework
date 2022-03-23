/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: Init function in platdrv
 * Create: 2020-02-20
 */
#ifndef PLATDRV_PLATDRV_H
#define PLATDRV_PLATDRV_H

#include <types.h>
#include <hm_msg_type.h>
#include <hm_mman_ext.h>
#include <sys/hm_syscall.h>
#include <hmdrv.h>
#include "drv_module.h"
#include "drv_thread.h"

pid_t git_caller_pid(void);
struct hmcap_message_info;
int32_t get_drv_params(struct drv_param *params, const struct hm_drv_req_msg_t *msg,
                       const struct hmcap_message_info *info);

extern uintptr_t __stack_chk_guard;
intptr_t hm_platdrv_pm_dispatch(void *msg, cref_t *p_msg_hdl, struct hmcap_message_info *info);

struct ioaddr_t {
    paddr_t base;
    uint32_t size;
};

#endif
