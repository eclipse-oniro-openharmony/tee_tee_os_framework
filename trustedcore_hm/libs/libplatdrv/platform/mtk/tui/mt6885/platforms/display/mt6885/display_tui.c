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

#define TAG "[DISP_TUI]"

#include "drStd.h"
#include "dr_api/dr_api.h"
#include "drError.h"
#include "drTuiCommon.h"
#include "mt_typedefs.h"

#include "cmdq_sec_record.h"
#include "ddp_hal.h"
#include "ddp_rdma.h"
#include "DpDataType.h"

#include "ddp_reg.h"
#include "lcm_drv.h"
#include "ddp_dsi.h"
#include "ddp_path.h"
#include "ddp_ovl.h"
#include "ddp_info.h"
#include "ddp_color_format.h"

#include "log.h"
#include "ddp_drv.h"

#include "display_tui.h"
#include "tui_m4u.h"
#include "tlApisec.h"
#include "devapc_tui_impl.h"
#include "mem_ops.h"

/* For DEVAPC used */
//#include "devapc_tui_impl.h"

/* Define platform m4u port for different TUI mode */
#define M4U_PORT_DISPLAY_MULTI M4U_PORT_L0_OVL_RDMA0
#define M4U_PORT_DISPLAY_SINGLE M4U_PORT_L0_DISP_RDMA0
static int32_t g_buf_free_flag;
static int32_t g_set_disp_flag;
static int32_t g_X_RES;
static int32_t g_Y_RES;

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

static int32_t g_count;
int32_t get_disp_tui_get_free_flag(void)
{
    return g_buf_free_flag;
}

int32_t get_disp_tui_set_disp_flag(void)
{
    return g_set_disp_flag;
}

void set_tui_free_flag(int32_t val)
{
    g_buf_free_flag = val;
}

void set_tui_disp_flag(int32_t val)
{
    g_set_disp_flag = val;
}

void set_x_res(int32_t val)
{
    g_X_RES = val;
}

void set_y_res(int32_t val)
{
    g_Y_RES = val;
}

int32_t get_x_res(void)
{
    return g_X_RES;
}

int32_t get_y_res(void)
{
    return g_Y_RES;
}

struct _reg_backup {
	void * va;
	unsigned int val;
};

static struct _reg_backup regs_backup[30];
static enum DISP_TUI_VERSION gDisp_version;
static unsigned long last_addr;

int disp_tui_dump_backup_regs()
{
	return 0;
}

int disp_tui_init_backup_regs()
{
	int i;

	for(i=0; i<ARRAY_SIZE(regs_backup); i++) {
		regs_backup[i].va = NULL;
		regs_backup[i].val = 0;
	}
	return 0;
}

int disp_tui_reg_backup(void* addr)
{
	int i, backup = -1;

	for (i = 0; i < ARRAY_SIZE(regs_backup); i++) {
		if ((regs_backup[i].va == 0) && (backup == -1))
			backup = i;

		if(regs_backup[i].va == addr) {
			DDPAEE("reg backup again! reg=0x%x\n", addr);
			return -1;
		}
	}

	if(backup == -1) {
		DDPAEE("reg backup mem is full!\n");
		disp_tui_dump_backup_regs();
	}
	regs_backup[backup].va = addr;
	regs_backup[backup].val = DISP_REG_GET(addr);
	return 0;
}

int disp_tui_reg_restore(cmdqRecHandle cmdq_handle)
{
	int i;

	DDPMSG("begin to restore disp regs ===========>\n");
	for (i = 0; i < ARRAY_SIZE(regs_backup); i++) {
		if (regs_backup[i].va){
			DDPMSG("0x%x = 0x%x\n", disp_addr_convert((unsigned long)regs_backup[i].va),
									regs_backup[i].val);
			DISP_REG_SET(cmdq_handle, regs_backup[i].va, regs_backup[i].val);
			regs_backup[i].va = NULL;
			regs_backup[i].val = 0;
		}
	}
	DDPMSG("restore disp regs done ===========<\n");

	return 0;
}

#define SMI_LARB_SEC_CON_OFFSET(port) (0xf80 + (((port))*4))

/*=======================================================*/



#define USE_M4U_FLOW
#ifdef M4U_PORT_DISPLAY_MAX
#undef M4U_PORT_DISPLAY_MAX
#define M4U_PORT_DISPLAY_MAX M4U_PORT_L0_OVL_RDMA0
#endif
#ifdef Y_RES
#undef Y_RES
#define Y_RES 2280
#endif

#ifndef USE_M4U_FLOW
static void* larb0_base = NULL;
static void* larb1_base = NULL;
#endif

int disp_m4u_init()
{
	drApiResult_t ret;

#ifdef USE_M4U_FLOW
	tui_m4u_Init();
#else
	if(larb0_base) {
		DDPMSG("disp m4u has been inited\n");
		return 0;
	}

    ret = dr_api_map_io(DDP_REG_BASE_SMI_LARB0, 0x1000,
                        MAP_HARDWARE, &larb0_base);

	if(ret != DRAPI_OK)
		DDPAEE("%s fail: pa=0x%x, size=0x%x, flag=0x%x, ret=%d(0x%x)\n",
			__func__, DDP_REG_BASE_SMI_LARB0, 0x1000, MAP_HARDWARE, ret, ret);

	if(larb1_base) {
		DDPMSG("disp m4u has been inited\n");
		return 0;
	}

    ret = dr_api_map_io(DDP_REG_BASE_SMI_LARB1, 0x1000,
                        MAP_HARDWARE, &larb1_base);

	if(ret != DRAPI_OK)
		DDPAEE("%s fail: pa=0x%x, size=0x%x, flag=0x%x, ret=%d(0x%x)\n",
			__func__, DDP_REG_BASE_SMI_LARB1, 0x1000, MAP_HARDWARE, ret, ret);

    DDPMSG("M4U reg_map, map_addr=%p,reg_pa=0x%x\n", larb1_base, DDP_REG_BASE_SMI_LARB1);
#endif
	return 0;
}

int disp_m4u_config_port(cmdqRecHandle cmdq_handle, int port, int mmu_en, int sec)
{
	unsigned int regval, offset;
	if (gDisp_version == SINGLE_WINDOWS_TUI) {
#ifdef USE_M4U_FLOW
		tui_m4u_config_port_sec(cmdq_handle, port, mmu_en, sec);
#else
		offset = SMI_LARB_SEC_CON_OFFSET(port);
		DISP_REG_MASK_EXT(cmdq_handle, larb0_base + offset,
			DDP_REG_BASE_SMI_LARB0 + offset, mmu_en, 0x1);
		DISP_REG_MASK_EXT(cmdq_handle, larb0_base + offset,
			DDP_REG_BASE_SMI_LARB0 + offset, sec << 1, 0x2);
		DDPMSG("%s: port=%d, mmu_en=%d, sec=%d, reg=0x%x, regval=0x%x\n",
			__func__, port, mmu_en, sec, (larb0_base + offset), DISP_REG_GET(larb0_base + offset));
#endif

	} else if (gDisp_version == MULTI_WINDOWS_TUI) {
#ifdef USE_M4U_FLOW
		tui_m4u_config_port_sec(cmdq_handle, port, mmu_en, sec);
#else

		offset = SMI_LARB_SEC_CON_OFFSET(port);
		DISP_REG_MASK_EXT(cmdq_handle, larb0_base + offset,
			DDP_REG_BASE_SMI_LARB0+ offset, mmu_en, 0x1);
		DISP_REG_MASK_EXT(cmdq_handle, larb0_base + offset,
			DDP_REG_BASE_SMI_LARB0 + offset, sec << 1, 0x2);
		DDPMSG("%s: port=%d, mmu_en=%d, sec=%d, reg=0x%x, regval=0x%x\n",
			__func__, port, mmu_en, sec, (DDP_REG_BASE_SMI_LARB0 + offset), DISP_REG_GET(DDP_REG_BASE_SMI_LARB0 + offset));
#endif

	}
	return 0;
}

/*====================================================================*/
static int disp_tui_cmdq_reset(cmdqRecHandle cmdq_handle)
{
	/*DDPMSG("%s, cmdq_handle =%d\n", (__func__), cmdq_handle);*/
	if(cmdq_handle)
		return cmdqRecReset(cmdq_handle);

	return 0;
}

static int disp_tui_cmdq_flush(cmdqRecHandle cmdq_handle)
{
	int ret;

	/* DDPMSG("%s, dxs start!\n", __func__); */
	if(!cmdq_handle)
		return 0;

#if 0
	DDPMSG("===== dump cmd before flush ======>\n");
	cmdqRecDumpCommand(cmdq_handle);
	DDPMSG("===== dump cmd done ======>\n");
#endif

	ret = cmdqRecFlush(cmdq_handle);
	if(ret)
		DDPMSG("error to flush cmdq handle\n");

	disp_tui_cmdq_reset(cmdq_handle);
	/*DDPMSG("%s, done!\n", (__func__));*/

	return 0;
}

/*====================================================================*/

static int gMutex_id = 0;
static int gScenario = DDP_SCENARIO_PRIMARY_DISP;
static int gDisp_module = DISP_MODULE_OVL0;

/* inited in disp_tui_init() */
static int gDsi_module = DISP_MODULE_DSI0;
static enum DDP_MODE gDdp_mode = DDP_CMD_MODE;

static cmdqRecHandle gCmdq_handle;
#define DISP_TUI_ENABLE_CMDQ

int disp_tui_analyse()
{
	int i;
    int * modules = ddp_get_scenario_list(gScenario);
    int module_num = ddp_get_module_num(gScenario);

	DDPDBG("%s start!\n", __func__);
    DISP_LOG_I("check status on scenario %s\n",
                ddp_get_scenario_name(gScenario));

    ddp_check_path(gScenario);
    ddp_check_mutex(gMutex_id, gScenario, gDdp_mode);
#if 0
	for (i = 0; i < module_num; i++) {
		int module_name;

        module_name = modules[i];

       ddp_dump_analysis(module_name);
       ddp_dump_reg(module_name);
    }
    ddp_dump_analysis(DISP_MODULE_CONFIG);
    ddp_dump_reg(DISP_MODULE_CONFIG);

    ddp_dump_analysis(DISP_MODULE_MUTEX);
    ddp_dump_reg(DISP_MODULE_MUTEX);
#endif

	DDPDBG("%s done!\n", __func__);

	return 0;
}

static int update_intferface_module(enum DISP_MODULE_ENUM dsi_module)
{
	/* update interface module, it may be: dsi0/dsi1/dsi_dual */
	ddp_set_dst_module(DDP_SCENARIO_PRIMARY_DISP, dsi_module);
	ddp_set_dst_module(DDP_SCENARIO_PRIMARY_RDMA0_COLOR0_DISP, dsi_module);
	ddp_set_dst_module(DDP_SCENARIO_PRIMARY_RDMA0_DISP, dsi_module);

	ddp_set_dst_module(DDP_SCENARIO_PRIMARY_ALL, dsi_module);

	return 0;
}

int _disp_tui_trigger(cmdqRecHandle cmdq_handle, int mutex_id,
		      enum DDP_MODE mode, enum DISP_MODULE_ENUM dsi_module)
{
	/*DDPMSG("%s, start!\n", (__func__));*/

	/*ddp_mutex_enable_l(mutex_id, cmdq_handle);*/
	ddp_mutex_enable(mutex_id, gScenario, cmdq_handle);
	ddp_dsi_trigger(dsi_module, cmdq_handle);
	return 0;
}

int disp_tui_trigger(cmdqRecHandle cmdq_handle)
{
	/*DDPMSG("%s, start!\n", (__func__));*/

	if(gDdp_mode == DDP_VIDEO_MODE && ddp_dsi_is_busy(gDsi_module))
		return 0;

	_disp_tui_trigger(cmdq_handle, gMutex_id, gDdp_mode, gDsi_module);
	/*DDPMSG("%s, done!\n", (__func__));*/

    return 0;
}


/* cmdq event usage:
 * for cmd mode, we use RDMA_EOF event to indicate frame done
 * basically, RDMA_EOF should be set when RDMA is not running, so:
 * 1. set EOF when enter tui (for init)
 * 2. wait frame done uses cmdqRecWaitNoClear() (and don't clear it before wait)
 * 3. clear RDMA_EOF before trigger (it will be set automatically when rdma done)
 *
 * for video mode, it's simple because RDMA_EOF happens every frame.
 * we have to clear it before wait for next frame done (clear_before_wait)
 */
int disp_tui_wait_frame_done(cmdqRecHandle cmdq_handle)
{
	/*DDPMSG("%s, dxs cmdq_handle =%d\n", (__func__), cmdq_handle);*/

	if (cmdq_handle) {
		int clear_before_wait = (gDdp_mode == DDP_CMD_MODE) ? 0 : 1;
		rdma_wait_frame_done_by_cmdq(DISP_MODULE_RDMA0, cmdq_handle, clear_before_wait, 1);
	} else {
		if (gDdp_mode == DDP_CMD_MODE) {
			DSI_WaitForNotBusy(gDsi_module, NULL);
		} else {
			#if DISP_RDMA_INTERRUPT_ENABLE
			rdma_wait_frame_done_by_interrupt(DISP_MODULE_RDMA0);
			#else
			rdma_wait_frame_done_by_polling(DISP_MODULE_RDMA0);
			#endif
		}
	}

	return 0;
}

#if 0
enum UNIFIED_COLOR_FMT disp_tui_get_color_fmt(tuiFbPixelType_t type)
{
	/*DDPMSG("%s, start0!\n", (__func__));*/

	switch (type) {
	case TUI_HAL_FB_TYPE_RGB:
		return UFMT_RGB888;
	case TUI_HAL_FB_TYPE_BGR:
		return UFMT_BGR888;
	case TUI_HAL_FB_TYPE_RGBA:
		return UFMT_RGBA8888;
    case TUI_HAL_FB_TYPE_BGRA:
		return UFMT_BGRA8888;
	default:
		DDPAEE("invalid fb type 0x%x\n", type);
		return 0;
	}
	return 0;
}
#endif

//extern void ovl_dump_reg(enum DISP_MODULE_ENUM module);
extern void dump_mva_graph(void);
extern void dump_pagetable_in_use(void);

void disp_tui_delay(unsigned int cnt)
{
	volatile unsigned int i = 0, k;

	DDPMSG("begin delay %u\n", cnt);
	for(i=0; i<cnt; i++){
		k = i;
    }
	DDPMSG("finish delay %u\n", cnt);
}

static int _disp_tui_pan_disp_single(const dss_layer_t *pFbInfo)
{
	cmdqRecHandle cmdq_handle = gCmdq_handle;
	struct rdma_bg_ctrl_t rdma_bg_ctrl;
	unsigned int bpp= 0;
	unsigned long mva = 0;
	unsigned long phy_addr = 0;

	disp_tui_cmdq_reset(cmdq_handle);
	//disp_tui_delay(30000);
	tui_m4u_switch_to_sec();

	if (gDdp_mode == DDP_CMD_MODE) /* need to clear rdma eof*/
		cmdqRecClearEventToken(cmdq_handle, rdma_get_EOF_cmdq_event(gDisp_module));

	rdma_bg_ctrl.left = 0;
	rdma_bg_ctrl.top  = 0;
	rdma_bg_ctrl.right= 0;
	rdma_bg_ctrl.bottom= 0;
	// bpp = UFMT_GET_bpp( disp_tui_get_color_fmt(pFbInfo->type) ) / 8;
	bpp = pFbInfo->img.bpp;

	phy_addr = virt_mem_to_phys(pFbInfo->img.vir_addr);
	mva = tui_m4u_alloc_mva(M4U_PORT_DISPLAY_SINGLE, phy_addr,
		pFbInfo->img.stride * pFbInfo->img.height);
	rdma_config(gDisp_module,
		RDMA_MODE_MEMORY,
		mva,
		pFbInfo->img.format,
		pFbInfo->img.stride,
		pFbInfo->img.width,
		pFbInfo->img.height,
		0,	0, 0, &rdma_bg_ctrl, cmdq_handle, NULL ,bpp);

	disp_m4u_config_port(NULL, M4U_PORT_DISPLAY_SINGLE, 0, 1);
	//dump_mva_graph();
	//dump_pagetable_in_use();  //bit 9

	cmdqRecSetEventToken(cmdq_handle, CMDQ_SYNC_TOKEN_CONFIG_DIRTY);
	disp_tui_cmdq_flush(cmdq_handle);
	disp_tui_cmdq_reset(cmdq_handle);
	disp_tui_wait_frame_done(cmdq_handle);
	disp_tui_cmdq_flush(cmdq_handle);

	if (last_addr)
		tui_m4u_free(last_addr, pFbInfo->img.stride * pFbInfo->img.height);
	last_addr = mva;

	return 0;
}

static int is_pConfig_inited;
struct disp_ddp_path_config *pConfig = NULL;

static int _convert_disp_input_to_ovl(struct OVL_CONFIG_STRUCT *ovl_cfg, const dss_layer_t *pFbInfo)
{
	int ret = 0;
	unsigned long mva = 0;
	unsigned long long phy_addr = 0;

	DDPDBG("%s, start!\n", (__func__));
	ovl_cfg->layer = 0;
	ovl_cfg->isDirty = 1;
	ovl_cfg->buff_idx = -1;
	ovl_cfg->layer_en = 1;

	/* if layer is disable, we just needs config above params. */
	if (!ovl_cfg->layer_en)
		return 0;

   DDPERR("333333_display_params var is 0x%x\n", pFbInfo->img.vir_addr);
   phy_addr = virt_mem_to_phys(pFbInfo->img.vir_addr);
   mva = tui_m4u_alloc_mva(M4U_PORT_DISPLAY_MULTI, phy_addr,
		pFbInfo->img.stride * pFbInfo->src_rect.h);
   DDPERR("44444isplay_params phy_addr is 0x%x %d\n", phy_addr, pFbInfo->img.stride);
	ovl_cfg->fmt = UFMT_BGRA8888;
	ovl_cfg->addr = mva;
	ovl_cfg->vaddr = 0; //NULL; /* dont need to set value */
	ovl_cfg->src_x = 0;
	ovl_cfg->src_y = 0;
	ovl_cfg->src_w = pFbInfo->src_rect.w;
	ovl_cfg->src_h = pFbInfo->src_rect.h;
	ovl_cfg->src_pitch = pFbInfo->img.stride * 4;
	ovl_cfg->dst_x = pFbInfo->dst_rect.x;
	ovl_cfg->dst_y = pFbInfo->dst_rect.y;

	/* dst W/H should <= src W/H */
	ovl_cfg->dst_w = pFbInfo->dst_rect.w;
	ovl_cfg->dst_h = pFbInfo->dst_rect.h;
	ovl_cfg->keyEn = 0;
	ovl_cfg->key = 0;
	ovl_cfg->aen = 0;
	ovl_cfg->sur_aen = 0;
	ovl_cfg->alpha = 0xFF;
	ovl_cfg->src_alpha = 0;
	ovl_cfg->dst_alpha = 0;
	ovl_cfg->yuv_range = 0;
	ovl_cfg->security = DISP_SECURE_BUFFER;
	ovl_cfg->source = OVL_LAYER_SOURCE_MEM;
	ovl_cfg->ext_sel_layer = -1;
	/*DDPDBG("%s, done!\n", (__func__));*/

	return ret;
}

void _cmdq_insert_wait_frame_done_token_mira(void *handle)
{
	if(gDdp_mode == DDP_VIDEO_MODE)
		cmdqRecWaitNoClear(handle, CMDQ_EVENT_MUTEX0_STREAM_EOF);
	else
		cmdqRecWaitNoClear(handle, CMDQ_SYNC_TOKEN_STREAM_EOF);
}

static int _disp_tui_pan_disp_multi(const dss_layer_t *pFbInfo)
{
	cmdqRecHandle cmdq_handle = gCmdq_handle;
	struct OVL_CONFIG_STRUCT *ovl_cfg;

	DDPMSG("%s+\n", __func__);
	disp_tui_cmdq_reset(cmdq_handle);
	if(cmdq_handle) {
		/* see notes before disp_tui_wait_frame_done() */
		_cmdq_insert_wait_frame_done_token_mira(cmdq_handle);
	}
	tui_m4u_switch_to_sec();

	if (!is_pConfig_inited) {
		/*Allocate a block of memory from the heap for the pConfig struct.*/
		pConfig = malloc(sizeof(*pConfig));
		memset(pConfig, 0, sizeof(*pConfig));
		if (pConfig == NULL) {
			DDPERR("pConfig allocated FAILED!!\n");
			ASSERT(0);
			return -1;
		}
		is_pConfig_inited = 1;
	}

	ovl_cfg = &(pConfig->ovl_config[0]);
	_convert_disp_input_to_ovl(ovl_cfg, pFbInfo);

	pConfig->dst_w = g_X_RES;
	pConfig->dst_h = g_Y_RES;
	pConfig->dst_dirty = 1;
	pConfig->ovl_dirty = 1;
	pConfig->ovl_layer_scanned = 0;
	ovl_config_l(DISP_MODULE_OVL0, pConfig, cmdq_handle);

	disp_m4u_config_port(cmdq_handle, M4U_PORT_DISPLAY_MULTI, 0, 1);
	/* Dump M4U pagetable */
	/* dump_mva_graph(); */
	/* dump_pagetable_in_use(); */

	cmdqRecSetEventToken(cmdq_handle, CMDQ_SYNC_TOKEN_CONFIG_DIRTY);
	disp_tui_cmdq_flush(cmdq_handle);

	//if (last_addr) {
	//	tui_m4u_free(last_addr, pFbInfo->img.stride * pFbInfo->img.height);
		g_buf_free_flag = 1;
//	}
	//last_addr = ovl_cfg->addr;
    g_set_disp_flag = 1;
	DDPMSG("%s-\n", __func__);
}

int disp_tui_pan_display(const dss_layer_t *pFbInfo)
{
	if (gDisp_version == SINGLE_WINDOWS_TUI)
		return _disp_tui_pan_disp_single(pFbInfo);
	else
		return _disp_tui_pan_disp_multi(pFbInfo);
}

unsigned int irq_backup;

int disp_tui_dsi_get_module(void)
{
#if 0
	int ufoe_mout = DISP_REG_GET(DISP_REG_CONFIG_DISP_UFOE_MOUT_EN);
	int dsi0_selin = DISP_REG_GET(DISP_REG_CONFIG_DISP_DSI0_SEL_IN);

	if (((ufoe_mout & 0x2) == 0x2) && (dsi0_selin == 0x1))
		return DISP_MODULE_DSIDUAL;
	else
#endif
		return DISP_MODULE_DSI0;
}

int disp_tui_init()
{
	static int is_inited = 0;
	int ret;

	if (is_inited) {
		disp_m4u_init();
		DDPMSG("%s has inited\n", __func__);
		return 0;
	}
	is_inited = 1;

	disp_reg_init();
	gDisp_version = disp_get_version();
	cmdqRecInitialize();
	disp_m4u_init();

    if (gDisp_version == SINGLE_WINDOWS_TUI)
		gDisp_module = DISP_MODULE_RDMA0;
	else if (gDisp_version == MULTI_WINDOWS_TUI)
		gDisp_module = DISP_MODULE_OVL0;

	gDsi_module = disp_tui_dsi_get_module();
	update_intferface_module(gDsi_module);

	gDdp_mode = ddp_dsi_get_mode(gDsi_module);

	DDPMSG("%s: dsi_module=%s, mode=%s\n", __func__, ddp_get_module_name(gDsi_module),
		gDdp_mode==DDP_CMD_MODE ? "cmd" : "vdo");

	/*DISP_REG_CMDQ_POLLING(cmdq, &DSI_REG[module_idx]->DSI_STATE_DBG0, 0x00010000, 0x00010000);*/

#ifdef DISP_TUI_ENABLE_CMDQ
	ret = cmdqRecCreate(CMDQ_SCENARIO_PRIMARY_DISP, &gCmdq_handle);
	if(ret)
		//DDPAEE("error to create cmdq handle! ret=%d\n", ret);
#endif
	//last_addr = 0;

	/*disp_tui_init_fb_contex();*/

	return ret;
}

static int protect_display_engines(int window)
{
    int ret = tui_set_devapc_protect(DEVAPC_MODULE_REQ_DISP,
			DEVAPC_PROTECT_ENABLE, window);
	if (ret) {
		DDPERR("%s failed, ret=0x%x!\n", __func__, ret);
	} else {
		DDPDBG("%s done!\n", __func__);
	}

	return ret;
}

static int unprotect_display_engines(int window)
{
	int ret = tui_set_devapc_protect(DEVAPC_MODULE_REQ_DISP,
			DEVAPC_PROTECT_DISABLE, window);
	if (ret) {
		DDPERR("%s failed, ret=0x%x!\n", __func__, ret);
	} else {
		DDPDBG("%s done!\n", __func__);
	}

	return ret;
}

int disp_tui_enter()
{
	int ret = 0;

	DDPMSG("%s+\n", __func__);

	if (gDisp_version == SINGLE_WINDOWS_TUI) {
		/*disable rdma irq before protect it */
		irq_backup = rdma_disable_irq_backup(gDisp_module, NULL);

#if DISP_RDMA_INTERRUPT_ENABLE
		rdma_irq_attach(gDisp_module);
#endif

		gScenario = DDP_SCENARIO_PRIMARY_RDMA0_COLOR0_DISP;
		ret = protect_display_engines(0);
	} else {
		irq_backup = ovl_disable_irq_backup(gDisp_module, NULL);
		gScenario = DDP_SCENARIO_PRIMARY_DISP;
		ret = protect_display_engines(1);
	}

	/* check path */
	ret = ddp_check_path_strict(gScenario);
	if(ret) {
		DDPERR("error to enter tui because path is incorrect!!\n");
		disp_tui_analyse();
		//goto err1;
	}

	if (gDisp_version == SINGLE_WINDOWS_TUI) {
		/* check path can't covor rdma mode */
		ret = rdma_is_mem_mode(gDisp_module);
		if (!ret) {
			DDPERR("error to enter tui because %s is not mem mode\n",
				ddp_get_module_name(gDisp_module));
			goto err1;
		}

		/* protect port config registers */
		rdma_reg_backup(gDisp_module);
		/* ddp_mutex_reg_backup(0); */
	}

	if (gDdp_mode == DDP_CMD_MODE && gCmdq_handle) {
		/* see notes before disp_tui_wait_frame_done() */
		DSI_WaitForNotBusy(gDsi_module, NULL);
	}

	disp_tui_analyse();
    ddp_get_ds0_size();
	DDPMSG("%s-\n", __func__);

    g_buf_free_flag = 1;
    g_set_disp_flag = 1; /* set the init value */
	return 0;

err1:
	if (gDisp_version == SINGLE_WINDOWS_TUI) {
		unprotect_display_engines(0);
#if DISP_RDMA_INTERRUPT_ENABLE
		rdma_irq_dettach(gDisp_module);
#endif
		rdma_irq_restore(gDisp_module, NULL, irq_backup);
	} else {
		unprotect_display_engines(1);
		ovl_irq_restore(gDisp_module, NULL, irq_backup);
	}

	return -1;
}

static int remove_tui_layer(void)
{
	cmdqRecHandle cmdq_handle = gCmdq_handle;
	struct OVL_CONFIG_STRUCT *ovl_cfg;

	/*DDPMSG("%s, start!\n", (__func__));*/
	disp_tui_cmdq_reset(cmdq_handle);
	if(cmdq_handle) {
		/* see notes before disp_tui_wait_frame_done() */
		_cmdq_insert_wait_frame_done_token_mira(cmdq_handle);
	}

	if (!is_pConfig_inited) {
		/*Allocate a block of memory from the heap for the pConfig struct.*/
		pConfig = malloc(sizeof(*pConfig));
		if (pConfig == NULL) {
			DDPERR("pConfig allocated FAILED!!\n");
			ASSERT(0);
			return -1;
		}
		is_pConfig_inited = 1;
	}

	ovl_cfg = &(pConfig->ovl_config[0]);
	ovl_cfg->layer = 0;
	ovl_cfg->isDirty = 1;
	ovl_cfg->buff_idx = -1;
	ovl_cfg->layer_en = 0;
	pConfig->dst_w = g_X_RES;
	pConfig->dst_h = g_Y_RES;
	pConfig->dst_dirty = 1;
	pConfig->ovl_dirty = 1;
	pConfig->ovl_layer_scanned = 0;
	ovl_config_l(DISP_MODULE_OVL0, pConfig, cmdq_handle);

	disp_m4u_config_port(cmdq_handle, M4U_PORT_DISPLAY_MULTI, 0, 1);

	cmdqRecSetEventToken(cmdq_handle, CMDQ_SYNC_TOKEN_CONFIG_DIRTY);
	disp_tui_cmdq_flush(cmdq_handle);

	DDPMSG("%s, done!\n", __func__);
}

int disp_tui_leave()
{
	cmdqRecHandle cmdq_handle = gCmdq_handle;

	DDPMSG("%s start\n", __func__);

	disp_tui_cmdq_reset(cmdq_handle);

	if (gDisp_version == SINGLE_WINDOWS_TUI &&
		gDdp_mode == DDP_VIDEO_MODE) {
		/* clear fb and trigger black screen Robin*/
		disp_tui_wait_frame_done(cmdq_handle);
		//disp_tui_delay(800);
	} else if (gDisp_version == MULTI_WINDOWS_TUI) {
		remove_tui_layer();
		_cmdq_insert_wait_frame_done_token_mira(cmdq_handle);
	}
	/*restore display registers*/
	disp_tui_reg_restore(cmdq_handle);

	if (gDisp_version == SINGLE_WINDOWS_TUI) {
		/* config rdma port */
		disp_m4u_config_port(cmdq_handle, M4U_PORT_DISPLAY_SINGLE, 0, 0);
	} else if (gDisp_version == MULTI_WINDOWS_TUI) {
		disp_m4u_config_port(cmdq_handle, M4U_PORT_DISPLAY_MULTI, 0, 0);
	}

	DDPMSG("rdma_eof is %d\n",
		cmdqTzCoreGetEvent(rdma_get_EOF_cmdq_event(DISP_MODULE_RDMA0)));

	disp_tui_cmdq_flush(cmdq_handle);


	DDPMSG("%s wait cmdq done\n", __func__);

	if (gDisp_version == SINGLE_WINDOWS_TUI) {
		unprotect_display_engines(0);
#if DISP_RDMA_INTERRUPT_ENABLE
		rdma_irq_dettach(gDisp_module);
#endif
		/* restore rdma irq */
		rdma_irq_restore(gDisp_module, NULL, irq_backup);
	} else if (gDisp_version == MULTI_WINDOWS_TUI) {
		unprotect_display_engines(1);
		if (is_pConfig_inited && pConfig!=NULL) {
			/*Free the memory block allocated for pConfig struct*/
			free(pConfig);
			pConfig = NULL;
			is_pConfig_inited = 0;
			DDPMSG("%s drApiFree pConfig done, pConfig=0x%x\n", __func__, pConfig);
		}
		ovl_irq_restore(gDisp_module, NULL, irq_backup);
	}

	//if (last_addr)
	//	tui_m4u_free(last_addr, g_X_RES * g_Y_RES * 4);
	//last_addr = 0;
	tui_m4u_deinit();

	DDPMSG("%s done\n", __func__);
	return 0;
}

int disp_tui_poll(void* addr, unsigned int mask, unsigned int value, long timeout)
{
	volatile long i = 0;
	volatile unsigned int reg_val;
	int ret = 0;

	while(1) {
		reg_val = DISP_REG_GET(addr);

		/*DDPMSG("poll%d 0x%p = 0x%x, msk=0x%x, val=0x%x\n", i, addr, reg_val, mask, value);*/

		if ((reg_val & mask) == value) {
			ret = 0;
			break;
		}
		if (timeout != -1 && i > timeout) {
			ret = -1;
			break;
		}

		i++;
	}
	return ret;
}

static inline int disp_tui_poll_nz(void* addr, unsigned int mask, long timeout)
{
	volatile long i = 0;
	volatile unsigned int reg_val;
	int ret = 0;

	while (1) {
		reg_val = DISP_REG_GET(addr);

		/*DDPMSG("poll%d 0x%p = 0x%x, msk=0x%x, val=0x%x\n", i, addr, reg_val, mask, value);*/

		if ((reg_val & mask)) {
			ret = 0;
			break;
		}
		if (timeout != -1 && i > timeout) {
			ret = -1;
			break;
		}

		i++;
	}
	return ret;
}

uint32_t *g_fb_addr = NULL;
int32_t get_free_buffer(uint32_t addr, uint32_t size)
{
    uint32_t attr = MAP_READABLE | MAP_WRITABLE | MAP_UNCACHED;
    void *vaddr = NULL;

    DDPERR("0000test_display_params var is 0x%x\n", addr);
    (void)dr_api_map_physical_buffer((uint64_t)addr, (size_t)0x1400000, attr, (void **)&vaddr);
    g_fb_addr = vaddr;
    memset(g_fb_addr, 3, size);
    DDPERR("0000test_display_params var is 0x%x\n", g_fb_addr);
    return 0;
}

static void test_display_params(dss_layer_t *layer)
{
    layer->img.vir_addr = g_fb_addr;
    layer->img.buf_size = 0x0a00000;
    layer->img.bpp = 4; /* BPP */
    layer->img.stride = 1080;
    layer->img.width = 1080;
    layer->img.height = 2376;

   DDPERR("111111test_display_params var is 0x%x\n", g_fb_addr);
    layer->src_rect.x = 0;
    layer->src_rect.y = 0;
    layer->src_rect.w = 1080;
    layer->src_rect.h = 2376;
    layer->dst_rect = layer->src_rect;
}

static int32_t g_count;
void test_display(void)
{
    dss_layer_t layer = { 0 };
	DDPMSG("test_display+");
	disp_tui_init();
	DDPMSG("tui reg init done\n");

	disp_tui_enter();

	disp_tui_analyse();

    test_display_params(&layer);
    //dump_pagetable_in_use();
    while (g_count <= 50) {
    int ret = disp_tui_pan_display(&layer);
    if (ret != 0)
        DDPMSG("test_display-----");

    tloge("disp_tui_pan_display count %d", disp_tui_pan_display);
    g_count++;
    }

	disp_tui_leave();
	DDPMSG("test_display-");
}
