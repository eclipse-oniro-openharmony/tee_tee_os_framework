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

#ifndef __DISPLAY_TUI_H__
#define __DISPLAY_TUI_H__

#include "drTuiHal.h"
#include "ddp_log.h"
#include "display_tui_hal.h"

/*****
	#include "ddp_log.h"
	int disp_tui_dump_backup_regs();
	int disp_tui_init_backup_regs();
*****/

#define DISP_TUI_OPTION_LCM_BUSY_POLLING
#define DISP_RDMA_INTERRUPT_ENABLE 0
#define X_RES 1080
#define Y_RES 1920 /* This definition is for secure display user */

int disp_tui_reg_backup(void* addr);

int disp_tui_poll(void* addr, unsigned int mask, unsigned int value, long timeout);
static inline int disp_tui_poll_nz(void* addr, unsigned int mask, long timeout);

int disp_tui_init();
int disp_tui_enter();
int disp_tui_leave();

int disp_tui_pan_display(const dss_layer_t *layer);
int32_t get_disp_tui_get_free_flag(void);
int32_t get_disp_tui_set_disp_flag(void);
void set_tui_free_flag(int32_t val);
void set_tui_disp_flag(int32_t val);
int32_t get_free_buffer(uint32_t addr, uint32_t size);
/*int disp_tui_draw_buffer(uint8_t *va, int w, int h, int pitch, int Bpp);*/


#endif
