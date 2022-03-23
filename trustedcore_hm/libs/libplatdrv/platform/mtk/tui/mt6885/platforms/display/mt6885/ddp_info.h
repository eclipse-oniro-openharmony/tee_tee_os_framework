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

#ifndef _H_DDP_INFO
#define _H_DDP_INFO

#include "stdbool.h"
#include "ddp_hal.h"
#include "lcm_drv.h"
#include "disp_session.h"
#include "cmdq_sec_record.h"
#include "ddp_color_format.h"

struct disp_rect {
	int x;
	int y;
	int width;
	int height;
	int is_dual;
};

struct OVL_CONFIG_STRUCT {
	unsigned int ovl_index;
	unsigned int layer;
	unsigned int layer_en;
	enum OVL_LAYER_SOURCE source;
	enum UNIFIED_COLOR_FMT fmt;
	unsigned long addr;
	unsigned long real_addr;
	unsigned long vaddr;
	unsigned int src_x;
	unsigned int src_y;
	unsigned int src_w;
	unsigned int src_h;
	unsigned int src_pitch;
	unsigned int dst_x;
	unsigned int dst_y;
	unsigned int dst_w;
	unsigned int dst_h;
	unsigned int keyEn;
	unsigned int key;
	unsigned int aen;
	unsigned char alpha;

	unsigned int sur_aen;
	unsigned int src_alpha;
	unsigned int dst_alpha;

	unsigned int isTdshp;
	unsigned int isDirty;

	unsigned int buff_idx;
	unsigned int identity;
	unsigned int connected_type;
	enum DISP_BUFFER_TYPE security;
	unsigned int yuv_range;
	int is_configured;	/* is this layer configured to OVL HW, for multiply OVL sync */
	int const_bld;
	int ext_sel_layer;
	int ext_layer;
	int phy_layer;
};

struct OVL_BASIC_STRUCT {
	unsigned int layer;
	unsigned int layer_en;
	enum UNIFIED_COLOR_FMT fmt;
	unsigned long addr;
	unsigned int src_w;
	unsigned int src_h;
	unsigned int src_pitch;
	unsigned int bpp;
	unsigned int gpu_mode;
	unsigned int adobe_mode;
	unsigned int ovl_gamma_out;
	unsigned int alpha;
};

enum RSZ_COLOR_FORMAT {
	ARGB8101010,
	RGB999,
	RGB888,
	UNKNOWN_RSZ_CFMT,
};

struct rsz_tile_params {
	unsigned int step;
	unsigned int int_offset;
	unsigned int sub_offset;
	unsigned int in_len;
	unsigned int out_len;
};

struct RSZ_CONFIG_STRUCT {
	struct rsz_tile_params tw[2];
	struct rsz_tile_params th;
	enum RSZ_COLOR_FORMAT fmt;
	unsigned int frm_in_w;
	unsigned int frm_in_h;
	unsigned int frm_out_w;
	unsigned int frm_out_h;
	unsigned int ratio;
};

struct RDMA_BASIC_STRUCT {
	unsigned long addr;
	unsigned int src_w;
	unsigned int src_h;
	unsigned int bpp;
};

struct rdma_bg_ctrl_t {
	unsigned int left;
	unsigned int right;
	unsigned int top;
	unsigned int bottom;
};

struct RDMA_CONFIG_STRUCT {
	unsigned int idx;		/* instance index */
	enum UNIFIED_COLOR_FMT inputFormat;
	unsigned long address;
	unsigned int pitch;
	unsigned int width;
	unsigned int height;
	unsigned int dst_w;
	unsigned int dst_h;
	unsigned int dst_x;
	unsigned int dst_y;
	enum DISP_BUFFER_TYPE security;
	unsigned int yuv_range;
	struct rdma_bg_ctrl_t bg_ctrl;
};

struct WDMA_CONFIG_STRUCT {
	unsigned int idx;		/* instance index */
	unsigned int srcWidth;
	unsigned int srcHeight;	/* input */
	unsigned int clipX;
	unsigned int clipY;
	unsigned int clipWidth;
	unsigned int clipHeight;	/* clip */
	enum UNIFIED_COLOR_FMT outputFormat;
	unsigned long dstAddress;
	unsigned int dstPitch;	/* output */
	unsigned int useSpecifiedAlpha;
	unsigned char alpha;
	enum DISP_BUFFER_TYPE security;
};

#define TOTAL_OVL_LAYER_NUM		(6)

typedef struct {
	/* for ovl */
	bool ovl_dirty;
	bool rdma_dirty;
	bool dst_dirty;
	int ovl_layer_scanned;	/*each bit reprsent one layer, used for ovl engines */
	struct OVL_CONFIG_STRUCT ovl_config[TOTAL_OVL_LAYER_NUM];
	struct RDMA_CONFIG_STRUCT rdma_config;
	unsigned int dst_w;
	unsigned int dst_h;
} disp_ddp_path_config;

struct golden_setting_context {
	unsigned int fifo_mode;
	unsigned int is_wrot_sram;
	unsigned int is_rsz_sram;
	unsigned int mmsys_clk;
	unsigned int hrt_num;
	unsigned int ext_hrt_num;
	unsigned int is_display_idle;
	unsigned int is_dc;
	unsigned int hrt_magicnum; /* by resolution */
	unsigned int ext_hrt_magicnum; /* by resolution */
	unsigned int dst_width;
	unsigned int dst_height;
	unsigned int ext_dst_width;
	unsigned int ext_dst_height;
	unsigned int fps;
	unsigned int is_one_layer;
	unsigned int rdma_width;
	unsigned int rdma_height;
	unsigned int is_dual_pipe;
};

struct disp_ddp_path_config {
	/* for ovl */
	bool ovl_dirty;
	bool ovl_partial_dirty;
	bool rdma_dirty;
	bool wdma_dirty;
	bool dst_dirty;
	int ovl_layer_dirty;	/*each bit represent one layer */
	int ovl_layer_scanned;	/*each bit reprsent one layer, used for ovl engines */
	int overlap_layer_num;
	struct OVL_CONFIG_STRUCT ovl_config[TOTAL_OVL_LAYER_NUM];
	struct disp_rect ovl_partial_roi;
	struct RSZ_CONFIG_STRUCT rsz_config;
	struct RDMA_CONFIG_STRUCT rdma_config;
	struct WDMA_CONFIG_STRUCT wdma_config;
	LCM_PARAMS dispif_config;
	unsigned int lcm_bpp;
	unsigned int dst_w;
	unsigned int dst_h;
	unsigned int fps;
	struct golden_setting_context *p_golden_setting_context;
	void *path_handle;
	bool rsz_enable;
	int hrt_path;
	int hrt_scale;
	int sbch_enable;
};

/* dpmgr_ioctl cmd definition */
enum DDP_IOCTL_NAME {
/* DSI operation */
	DDP_SWITCH_DSI_MODE = 0,
	DDP_STOP_VIDEO_MODE = 1,
	DDP_BACK_LIGHT = 2,
	DDP_SWITCH_LCM_MODE = 3,
	DDP_DPI_FACTORY_TEST = 4,
	DDP_DSI_IDLE_CLK_CLOSED = 5,
	DDP_DSI_IDLE_CLK_OPEN = 6,
	DDP_DSI_PORCH_CHANGE = 7,
	DDP_PHY_CLK_CHANGE = 8,
	DDP_ENTER_ULPS = 9,
	DDP_EXIT_ULPS = 10,
	DDP_RDMA_GOLDEN_SETTING = 11,
	DDP_OVL_GOLDEN_SETTING,
	DDP_PARTIAL_UPDATE,
	DDP_UPDATE_PLL_CLK_ONLY,
	DDP_DPI_FACTORY_RESET,
	DDP_DSI_PORCH_ADDR,
	DDP_DSI_SW_INIT,
	DDP_DSI_MIPI_POWER_ON,
	DDP_OVL_MVA_REPLACEMENT,
	DDP_DSI_ENABLE_TE,
};

struct ddp_io_golden_setting_arg {
	enum dst_module_type dst_mod_type;
	int is_decouple_mode;
	unsigned int dst_w;
	unsigned int dst_h;
};

typedef int (*ddp_module_notify)(enum DISP_MODULE_ENUM, enum DISP_PATH_EVENT);

struct DDP_MODULE_DRIVER {
	enum DISP_MODULE_ENUM module;
	int (*init)(enum DISP_MODULE_ENUM module, void *handle);
	int (*deinit)(enum DISP_MODULE_ENUM module, void *handle);
	int (*config)(enum DISP_MODULE_ENUM module,
		struct disp_ddp_path_config *config, void *handle);
	int (*start)(enum DISP_MODULE_ENUM module, void *handle);
	int (*trigger)(enum DISP_MODULE_ENUM module, void *handle);
	int (*stop)(enum DISP_MODULE_ENUM module, void *handle);
	int (*reset)(enum DISP_MODULE_ENUM module, void *handle);
	int (*power_on)(enum DISP_MODULE_ENUM module, void *handle);
	int (*power_off)(enum DISP_MODULE_ENUM module, void *handle);
	int (*suspend)(enum DISP_MODULE_ENUM module, void *handle);
	int (*resume)(enum DISP_MODULE_ENUM module, void *handle);
	int (*is_idle)(enum DISP_MODULE_ENUM module);
	int (*is_busy)(enum DISP_MODULE_ENUM module);
	int (*dump_info)(enum DISP_MODULE_ENUM module, int level);
	int (*bypass)(enum DISP_MODULE_ENUM module, int bypass);
	int (*build_cmdq)(enum DISP_MODULE_ENUM module, void *cmdq_handle,
		enum CMDQ_STATE state);
	int (*set_lcm_utils)(enum DISP_MODULE_ENUM module,
		struct LCM_DRIVER *lcm_drv);
	int (*set_listener)(enum DISP_MODULE_ENUM module,
		ddp_module_notify notify);
	int (*cmd)(enum DISP_MODULE_ENUM module, unsigned int msg,
			unsigned long arg, void *handle);
	int (*ioctl)(enum DISP_MODULE_ENUM module, void *handle,
		enum DDP_IOCTL_NAME ioctl_cmd, void *params);
	int (*enable_irq)(enum DISP_MODULE_ENUM module, void *handle,
		enum DDP_IRQ_LEVEL irq_level);
	int (*connect)(enum DISP_MODULE_ENUM module,
		enum DISP_MODULE_ENUM prev, enum DISP_MODULE_ENUM next,
		int connect, void *handle);
	int (*switch_to_nonsec)(enum DISP_MODULE_ENUM module, void *handle);
};


struct ddp_reg {
	const char *reg_dt_name;
	unsigned long reg_pa_check;
	unsigned int reg_irq_check;
	unsigned int irq_max_bit;

	/* get info for DT */
	unsigned long reg_va;
	unsigned int reg_irq;
};

struct ddp_module {
	/* sw info */
	enum DISP_MODULE_ENUM module_id;
	enum DISP_MODULE_TYPE_ENUM module_type;
	const char *module_name;
	unsigned int can_connect; /* module can be connect if 1 */
	struct DDP_MODULE_DRIVER *module_driver;

	/* hw info */
	struct ddp_reg reg_info;
};

enum DISP_TUI_VERSION
{
	SINGLE_WINDOWS_TUI = 0,
	MULTI_WINDOWS_TUI,
};

char *ddp_get_module_name(enum DISP_MODULE_ENUM module);
char *ddp_get_reg_module_name(enum DISP_REG_ENUM reg_module);
unsigned int _can_connect(enum DISP_MODULE_ENUM module);

enum DISP_MODULE_ENUM ddp_get_reg_module(enum DISP_REG_ENUM reg_module);

#endif
