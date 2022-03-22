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

#ifndef _DDP_RDMA_API_H_
#define _DDP_RDMA_API_H_

#include "DpDataType.h"
#include "ddp_hal.h"
#include "ddp_dsi.h"


#define RDMA_INSTANCES  2
#define RDMA_MAX_WIDTH  4095
#define RDMA_MAX_HEIGHT 4095

enum RDMA_OUTPUT_FORMAT {
	RDMA_OUTPUT_FORMAT_ARGB = 0,
	RDMA_OUTPUT_FORMAT_YUV444 = 1,
};

enum RDMA_MODE {
	RDMA_MODE_DIRECT_LINK = 0,
	RDMA_MODE_MEMORY = 1,
};

void rdma_dump_reg(enum DISP_MODULE_ENUM module);
void rdma_dump_analysis(enum DISP_MODULE_ENUM module);

int rdma_reg_backup(enum DISP_MODULE_ENUM module);

int rdma_config(enum DISP_MODULE_ENUM module,
		       enum RDMA_MODE mode,
		       unsigned long address,
		       enum UNIFIED_COLOR_FMT inFormat,
		       unsigned pitch,
		       unsigned width,
		       unsigned height,
		       unsigned ufoe_enable,
		       enum DISP_BUFFER_TYPE sec,
		       unsigned int yuv_range, struct rdma_bg_ctrl_t *bg_ctrl, void *handle,
		       struct golden_setting_context *p_golden_setting, unsigned int bpp);


//int rdma_enable_irq(DISP_MODULE_ENUM module, void *handle, DDP_IRQ_LEVEL irq_level);

unsigned int rdma_disable_irq_backup(enum DISP_MODULE_ENUM module, void *handle);
int rdma_irq_restore(enum DISP_MODULE_ENUM module, void *handle, unsigned int irq_val);

#if 0
int rdma_config_input_mode(DISP_MODULE_ENUM module,
                    enum RDMA_MODE mode,
                    void * handle);

int rdma_config_mem(DISP_MODULE_ENUM module,
                    unsigned long address,
                    DpColorFormat inFormat,
                    unsigned pitch,
                    void * handle);
#endif

int rdma_irq_attach(enum DISP_MODULE_ENUM module);
int rdma_irq_dettach(enum DISP_MODULE_ENUM module);
int rdma_wait_frame_done_by_polling(enum DISP_MODULE_ENUM module);
int rdma_wait_frame_done_by_interrupt(enum DISP_MODULE_ENUM module);
int rdma_wait_frame_done_by_cmdq(enum DISP_MODULE_ENUM module, cmdqRecHandle cmdq_handle,
			int clear_before_wait, int clear_after_wait);

CMDQ_EVENT_ENUM rdma_get_EOF_cmdq_event(enum DISP_MODULE_ENUM module);

int rdma_is_mem_mode(enum DISP_MODULE_ENUM module);
unsigned long rdma_base_addr(enum DISP_MODULE_ENUM module);

#if 0


typedef struct _rdma_color_matrix {
	UINT32 C00;
	UINT32 C01;
	UINT32 C02;
	UINT32 C10;
	UINT32 C11;
	UINT32 C12;
	UINT32 C20;
	UINT32 C21;
	UINT32 C22;
} rdma_color_matrix;

typedef struct _rdma_color_pre {
	UINT32 ADD0;
	UINT32 ADD1;
	UINT32 ADD2;
} rdma_color_pre;


typedef struct _rdma_color_post {
	UINT32 ADD0;
	UINT32 ADD1;
	UINT32 ADD2;
} rdma_color_post;

#endif


#endif
