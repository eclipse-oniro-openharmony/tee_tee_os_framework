
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

#ifndef __DISPLAY_TUI_HAL_H__
#define __DISPLAY_TUI_HAL_H__

#include "stdint.h"

struct panel_info {
    uint32_t type;
	uint32_t xres;
    uint32_t yres;
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t fps;
    uint32_t orientation;
};

typedef struct dss_rect {
	uint32_t x;
	uint32_t y;
	uint32_t w;
	uint32_t h;
} dss_rect_t;

typedef struct dss_img {
	uint32_t format;
	uint32_t width;
	uint32_t height;
	uint32_t bpp; /* bytes per pixel */
	uint32_t buf_size;
	uint32_t stride;
	uint32_t stride_plane1;
	uint32_t stride_plane2;
	uint32_t phy_addr;
	uint32_t vir_addr;
	uint32_t offset_plane1;
	uint32_t offset_plane2;

	uint32_t afbc_header_addr;
	uint32_t afbc_payload_addr;
	uint32_t afbc_header_stride;
	uint32_t afbc_payload_stride;
	uint32_t afbc_scramble_mode;
	uint32_t mmbuf_base;
	uint32_t mmbuf_size;

	uint32_t mmu_enable;
	uint32_t csc_mode;
	uint32_t secure_mode;
	int32_t shared_fd;
	uint32_t reserved0;
} dss_img_t;

typedef struct dss_layer {
	dss_img_t img;
	dss_rect_t src_rect;
	dss_rect_t src_rect_mask;
	dss_rect_t dst_rect;
	uint32_t transform;
	int32_t blending;
	uint32_t glb_alpha;
	uint32_t color; /* background color or dim color */
	int32_t layer_idx;
	int32_t chn_idx;
	uint32_t need_cap;
	int32_t acquire_fence;
} dss_layer_t;

int32_t wait_release_flag(void);
int32_t wait_vactive_flag(void);
int32_t get_disp_info(struct panel_info *pinfo);
int32_t pan_display_sec(dss_layer_t *layer);
int32_t fb_cfg_sec(int32_t value);
#endif
