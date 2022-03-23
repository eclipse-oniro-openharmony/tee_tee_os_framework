/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display channel data array
 * Author: Hisilicon DSS
 * Create: 2019-10-14
 */

#include "channel_data/hisi_dss_channel_data.h"

/* dss_chn_idx
 * DSS_RCHN_D0 = 0, DSS_RCHN_D1, DSS_RCHN_V0, DSS_RCHN_G0, DSS_RCHN_V1,
 * DSS_RCHN_G1, DSS_RCHN_D2, DSS_RCHN_D3, DSS_WCHN_W0, DSS_WCHN_W1,
 * DSS_RCHN_V2, DSS_WCHN_W2,
 */
uint32_t g_dss_module_base[DSS_CHN_MAX_DEFINE][MODULE_CHN_MAX] = {
	/* D0 D1 V0 G0 V1 G1 D2 */
	{ 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 },

	/* D3 */
	{
		MIF_CH7_OFFSET,   //MODULE_MIF_CHN
		AIF0_CH7_OFFSET,  //MODULE_AIF0_CHN
		AIF1_CH7_OFFSET,  //MODULE_AIF1_CHN
		MCTL_CTL_MUTEX_RCH7,  //MODULE_MCTL_CHN_MUTEX
		DSS_MCTRL_SYS_OFFSET + MCTL_RCH7_FLUSH_EN,  //MODULE_MCTL_CHN_FLUSH_EN
		DSS_MCTRL_SYS_OFFSET + MCTL_RCH7_OV_OEN,  //MODULE_MCTL_CHN_OV_OEN
		DSS_MCTRL_SYS_OFFSET + MCTL_RCH7_STARTY,  //MODULE_MCTL_CHN_STARTY
		DSS_MCTRL_SYS_OFFSET + MCTL_MOD7_DBG,  //MODULE_MCTL_CHN_MOD_DBG
		DSS_RCH_D3_DMA_OFFSET,  //MODULE_DMA
		DSS_RCH_D3_DFC_OFFSET,  //MODULE_DFC
		0,  //MODULE_SCL
		0,  //MODULE_SCL_LUT
		0,  //MODULE_ARSR2P
		0,  //MODULE_ARSR2P_LUT
		0,  //MODULE_POST_CLIP
		0,  //MODULE_PCSC
		DSS_RCH_D3_CSC_OFFSET,  //MODULE_CSC
	},

	/* W0 W1 V2 W2 */
	{ 0 }, { 0 }, { 0 }, { 0 },
};

uint32_t g_dss_module_ovl_base[DSS_MCTL_IDX_MAX][MODULE_OVL_MAX] = {
	{0,
		0},

	{0,
		0},

	{0,
		0},

	{0,
		0},

	{DSS_OVL0_OFFSET,
		DSS_MCTRL_CTL4_OFFSET},

	{0,
		0},
};

/* number of smrx idx for each channel */
uint32_t g_dss_chn_sid_num[DSS_CHN_MAX_DEFINE] = {
	4, 1, 4, 4, 4, 4, 1, 1, 3, 4, 3, 3
};

/* start idx of each channel */
/* smrx_idx = g_dss_smmu_smrx_idx[chn_idx] + (0 ~ g_dss_chn_sid_num[chn_idx]) */
uint32_t g_dss_smmu_smrx_idx[DSS_CHN_MAX_DEFINE] = {
	0, 4, 5, 9, 13, 17, 21, 22, 26, 29, 23, 36
};

