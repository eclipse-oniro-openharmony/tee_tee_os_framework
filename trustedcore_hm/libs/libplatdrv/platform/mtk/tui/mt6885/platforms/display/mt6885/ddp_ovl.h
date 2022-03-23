/*
 * Copyright (C) 2015 MediaTek Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef _DDP_OVL_H_
#define _DDP_OVL_H_

#include "ddp_hal.h"
#include "ddp_info.h"
#include "ddp_rdma.h"

#define OVL_MAX_WIDTH  (4095)
#define OVL_MAX_HEIGHT (4095)

#define TOTAL_REAL_OVL_LAYER_NUM (4+3+2+3)
#define OVL_NUM			(3)

void ovl_dump_analysis(enum DISP_MODULE_ENUM module);
void ovl_dump_reg(enum DISP_MODULE_ENUM module);
unsigned long ovl_base_addr(enum DISP_MODULE_ENUM module);
int ovl_config_l(enum DISP_MODULE_ENUM module, struct disp_ddp_path_config *pConfig, void *handle);
unsigned int ovl_disable_irq_backup(enum DISP_MODULE_ENUM module, void *handle);
int ovl_irq_restore(enum DISP_MODULE_ENUM module, void *handle, unsigned int irq_val);

#endif
