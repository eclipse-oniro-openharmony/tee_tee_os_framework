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

#ifndef __DDP_PATH_H__
#define __DDP_PATH_H__

#include "ddp_info.h"
#include "cmdq_sec_record.h"

#define DDP_OVL_LAYER_MUN 4


enum DDP_MODE {
	DDP_VIDEO_MODE = 0,
	DDP_CMD_MODE,
};

enum CLK_MODE {
	LP_MODE = 0,
	HS_MODE,
};


enum DDP_SCENARIO_ENUM {
	DDP_SCENARIO_PRIMARY_DISP = 0, /* main path */
	DDP_SCENARIO_PRIMARY_BYPASS_PQ_DISP,	/* bypass pq module */
	DDP_SCENARIO_PRIMARY_RDMA0_COLOR0_DISP, /* by pass ovl */
	DDP_SCENARIO_PRIMARY_RDMA0_DISP, /* debug */
	DDP_SCENARIO_PRIMARY_OVL_MEMOUT, /* dc */
	DDP_SCENARIO_PRIMARY_ALL, /* main 1to2 */
#if 0 /* not for secure path */
	DDP_SCENARIO_SUB_DISP,
	DDP_SCENARIO_SUB_RDMA1_DISP,
	DDP_SCENARIO_SUB_OVL_MEMOUT,
	DDP_SCENARIO_SUB_ALL,
#endif
	DDP_SCENARIO_MAX
};

int ddp_get_module_num(enum DDP_SCENARIO_ENUM scenario);

void ddp_check_path(enum DDP_SCENARIO_ENUM scenario);
int ddp_check_path_strict(enum DDP_SCENARIO_ENUM scenario);

/*int ddp_mutex_set(int mutex_id, DDP_SCENARIO_ENUM scenario, DDP_MODE mode, void *handle);*/
int ddp_mutex_enable(int mutex_id, enum DDP_SCENARIO_ENUM scenario, void *handle);
int ddp_mutex_disable(int mutex_id, enum DDP_SCENARIO_ENUM scenario, void *handle);
void ddp_check_mutex(int mutex_id, enum DDP_SCENARIO_ENUM scenario, enum DDP_MODE mode);

int ddp_is_moudule_in_mutex(int mutex_id, enum DISP_MODULE_ENUM module);

enum DISP_MODULE_ENUM ddp_get_dst_module(enum DDP_SCENARIO_ENUM scenario);
int ddp_set_dst_module(enum DDP_SCENARIO_ENUM scenario, enum DISP_MODULE_ENUM dst_module);

int *ddp_get_scenario_list(enum DDP_SCENARIO_ENUM ddp_scenario);

char *ddp_get_scenario_name(enum DDP_SCENARIO_ENUM scenario);

int disp_get_dst_module(enum DDP_SCENARIO_ENUM scenario);
int ddp_is_module_in_scenario(enum DDP_SCENARIO_ENUM ddp_scenario, enum DISP_MODULE_ENUM module);
char *ddp_get_mutex_sof_name(unsigned int regval);
int ddp_path_init(void);

int ddp_mutex_enable_l(int mutex_idx, void *handle);
int ddp_mutex_reg_backup(int mutex_id);


#endif
