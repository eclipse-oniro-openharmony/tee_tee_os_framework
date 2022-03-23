/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: tc driver include file
 * Create: 2019-09-18
 */

#ifndef LIBDRV_FRAME_TC_DRV_H
#define LIBDRV_FRAME_TC_DRV_H
#include <stdint.h>
#include "drv_module.h"

int32_t tc_drv_init(void);
int32_t tc_drv_syscall(int32_t swi_id, struct drv_param *params, uint64_t perm);
void tc_drv_sp(void);
void tc_drv_sr(void);
void tc_drv_sp_s4(void);
void tc_drv_sr_s4(void);

int32_t vendor_drv_syscall(int32_t swi_id, struct drv_param *params, uint64_t perm);
#endif
