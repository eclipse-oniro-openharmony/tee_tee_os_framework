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

#ifndef __DSI_DRV_H__
#define __DSI_DRV_H__

#include "lcm_drv.h"
#include "ddp_hal.h"
#include "cmdq_sec_record.h"
#include "ddp_path.h"
#include "sre_typedef.h"
#ifdef __cplusplus
extern "C" {
#endif
/* ------------------------------------------------------------------------- */

#define DSI_CHECK_RET(expr)             \
	do {                                \
		enum DSI_STATUS ret = (expr);        \
		ASSERT(ret == DSI_STATUS_OK);   \
	} while (0)

/* --------------------------------------------------------------------------- */

#define		DSI_DCS_SHORT_PACKET_ID_0			0x05
#define		DSI_DCS_SHORT_PACKET_ID_1			0x15
#define		DSI_DCS_LONG_PACKET_ID				0x39
#define		DSI_DCS_READ_PACKET_ID				0x06

#define		DSI_GERNERIC_SHORT_PACKET_ID_1		0x13
#define		DSI_GERNERIC_SHORT_PACKET_ID_2		0x23
#define		DSI_GERNERIC_LONG_PACKET_ID			0x29
#define		DSI_GERNERIC_READ_LONG_PACKET_ID	0x14


#define		DSI_WMEM_CONTI						(0x3C)
#define		DSI_RMEM_CONTI						(0x3E)

/* ESD recovery method for video mode LCM */
#define		METHOD_NONCONTINUOUS_CLK			(0x1)
#define		METHOD_BUS_TURN_AROUND				(0x2)

/* State of DSI engine */
#define		DSI_VDO_VSA_VS_STATE				(0x008)
#define		DSI_VDO_VSA_HS_STATE				(0x010)
#define		DSI_VDO_VSA_VE_STATE				(0x020)
#define		DSI_VDO_VBP_STATE					(0x040)
#define		DSI_VDO_VACT_STATE					(0x080)
#define		DSI_VDO_VFP_STATE					(0x100)

/* --------------------------------------------------------------------------- */
enum DSI_STATUS {
	DSI_STATUS_OK = 0,
	DSI_STATUS_ERROR,
};

enum DSI_INS_TYPE {
	SHORT_PACKET_RW = 0,
	FB_WRITE = 1,
	LONG_PACKET_W = 2,
	FB_READ = 3,
};

enum DSI_CMDQ_BTA {
	DISABLE_BTA = 0,
	ENABLE_BTA = 1,
};

enum DSI_CMDQ_HS {
	LOW_POWER = 0,
	HIGH_SPEED = 1,
};

enum DSI_CMDQ_CL {
	CL_8BITS = 0,
	CL_16BITS = 1,
};

enum DSI_CMDQ_TE {
	DISABLE_TE = 0,
	ENABLE_TE = 1,
};

enum DSI_CMDQ_RPT {
	DISABLE_RPT = 0,
	ENABLE_RPT = 1,
};


struct DSI_CMDQ_CONFG {
	unsigned type:2;
	unsigned BTA:1;
	unsigned HS:1;
	unsigned CL:1;
	unsigned TE:1;
	unsigned Rsv:1;
	unsigned RPT:1;
};


struct DSI_T0_INS {
	unsigned CONFG:8;
	unsigned Data_ID:8;
	unsigned Data0:8;
	unsigned Data1:8;
};

struct DSI_T1_INS {
	unsigned CONFG:8;
	unsigned Data_ID:8;
	unsigned mem_start0:8;
	unsigned mem_start1:8;
};

struct DSI_T2_INS {
	unsigned CONFG:8;
	unsigned Data_ID:8;
	unsigned WC16:16;
	unsigned int *pdata;
};

struct DSI_T3_INS {
	unsigned CONFG:8;
	unsigned Data_ID:8;
	unsigned mem_start0:8;
	unsigned mem_start1:8;
};

struct DSI_PLL_CONFIG {
	UINT8 TXDIV0;
	UINT8 TXDIV1;
	UINT32 SDM_PCW;
	UINT8 SSC_PH_INIT;
	UINT16 SSC_PRD;
	UINT16 SSC_DELTA1;
	UINT16 SSC_DELTA;
};

enum DSI_INTERFACE_ID {
	DSI_INTERFACE_0 = 0,
	DSI_INTERFACE_1,
	DSI_INTERFACE_DUAL,
	DSI_INTERFACE_NUM,
};

enum DSI_PORCH_TYPE {
	DSI_VFP = 0,
	DSI_VSA,
	DSI_VBP,
	DSI_VACT,
	DSI_HFP,
	DSI_HSA,
	DSI_HBP,
	DSI_BLLP,
	DSI_PORCH_NUM,
};

int ddp_dsi_trigger(enum DISP_MODULE_ENUM module, cmdqRecHandle cmdq);

int ddp_dsi_reg_init(void);

void dsi_analysis(enum DISP_MODULE_ENUM module);

void DSI_WaitForNotBusy(enum DISP_MODULE_ENUM module, cmdqRecHandle cmdq);
enum DSI_STATUS DSI_DumpRegisters(enum DISP_MODULE_ENUM module, int level);

enum DISP_MODULE_ENUM ddp_dsi_get_module();
enum DDP_MODE ddp_dsi_get_mode(enum DISP_MODULE_ENUM module);
int ddp_dsi_is_busy(enum DISP_MODULE_ENUM module);

void DSI_manual_enter_HS(cmdqRecHandle cmdq);
void DSI_sw_clk_trail_cmdq(int module_idx,cmdqRecHandle cmdq);
enum CLK_MODE ddp_dsi_get_clk_lane_mode(void);
const char *_dsi_vdo_mode_parse_state(unsigned int state);
void ddp_get_ds0_size(void);
#ifdef __cplusplus
}
#endif
#endif				/* __DPI_DRV_H__ */
