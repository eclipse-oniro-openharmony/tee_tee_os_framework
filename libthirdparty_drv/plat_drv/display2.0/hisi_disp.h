/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display interfaces with secure_os
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#ifndef HISI_DISP_H
#define HISI_DISP_H
#include <sre_typedef.h>
#include <register_ops.h>
#include <sre_sys.h>
#include <tee_defines.h>
#include "stdint.h"
#include "mem_page_ops.h"
#include "libhwsecurec/securec.h"

#include "hisi_dss.h"

#define TUI_FOLD_PANEL_XRES1           2480
#define TUI_FOLD_PANEL_XRES2           2160
#define TUI_FOLD_PANEL_YRES1           2200
#define TUI_FOLD_PANEL_YRES2           1916

struct hisi_panel_info {
	uint32_t type;
	uint32_t xres;
	uint32_t yres;
	uint32_t width; // mm
	uint32_t height; // mm
	uint32_t bpp;
	uint32_t fps;
	uint32_t orientation;
};

struct hisifb_data_type {
	uint32_t index;

	uint32_t dss_base;
	uint32_t peri_crg_base;
	uint32_t sctrl_base;
	uint32_t pctrl_base;
	uint32_t mmbuf_crg_base;
	uint32_t noc_dss_base;
	uint32_t mipi_dsi0_base;
	uint32_t mipi_dsi1_base;
	uint32_t pmc_base;
	uint32_t media1_crg_base;

	uint32_t mctrl_sys_base;
	uint32_t rdma_base;
	uint32_t ovl_base;
	uint32_t mctl_base;
	uint32_t rdfc_base;
	uint32_t mif_ch_base;
	uint32_t smmu_base;

	uint32_t dpe_sec_irq;
	uint32_t sec_rch_idx;
	uint32_t sec_mctl_idx;
	uint32_t mode_cfg;
	uint32_t xres;
	uint32_t yres;
	uint32_t frame_count;

	int secure_status;              //   0:unsecure; 1:secure
	int vactive_start_flag;         //   wait until vactive_flag becomes 1
	int frame_end_flag;
	tee_mutex_handle disp_lock;
	int first_frame;
	int disp_debug_dump;
	int alpha_enable;

	dss_layer_t layer;
	dss_layer_t layer_prev;

	/* function entry chain */
	int (*fb_cfg_sec)(struct hisifb_data_type *hisifd, int sec_value);
	int (*wait_vactive_flag)(struct hisifb_data_type *hisifd);
	int (*wait_release_flag)(struct hisifb_data_type *hisifd);
	int (*get_disp_info)(struct hisifb_data_type *hisifd, struct hisi_panel_info *pinfo);
	int (*pan_display_sec)(struct hisifb_data_type *hisifd, dss_layer_t *layer);
	void (*set_reg)(uint32_t addr, uint32_t val, unsigned char bw, unsigned char bs);
	int (*panel_power_on)(struct hisifb_data_type *hisifd);
};

int hisi_fb_cfg_sec(int value);
int hisi_pan_display_sec(dss_layer_t *layer);
int hisi_wait_vactive_flag(void);
int hisi_wait_release_flag(void);
int hisi_get_disp_info(struct hisi_panel_info *pinfo);
int hisi_fb_alpha_set(int value);
#endif
