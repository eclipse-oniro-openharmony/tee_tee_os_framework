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

#ifndef __DDP_DRV_H__
#define __DDP_DRV_H__

#include "ddp_path.h"
#include "ddp_dsi.h"
#include "ddp_log.h"
#include "ddp_rdma.h"
#include "ddp_hal.h"
#include "ddp_info.h"

extern volatile unsigned long dispsys_reg[DISP_REG_NUM];
extern unsigned long ddp_reg_pa_base[DISP_REG_NUM];
extern volatile unsigned long mipi_tx_reg;
extern volatile unsigned long dsi_reg_va;

int disp_reg_init(void);
int disp_get_version(void);
#endif
