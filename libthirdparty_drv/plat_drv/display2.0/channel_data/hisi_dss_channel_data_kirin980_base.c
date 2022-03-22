/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display channel data array
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "channel_data/hisi_dss_channel_data.h"

/* dss_chn_idx
 * DSS_RCHN_D0 = 0, DSS_RCHN_D1, DSS_RCHN_V0, DSS_RCHN_G0, DSS_RCHN_V1,
 * DSS_RCHN_G1, DSS_RCHN_D2, DSS_RCHN_D3, DSS_WCHN_W0, DSS_WCHN_W1,
 * DSS_RCHN_V2, DSS_WCHN_W2,
 */
uint32_t g_dss_module_base[DSS_CHN_MAX_DEFINE][MODULE_CHN_MAX] = {
	/* D0   D1 */
	{ 0 }, { 0 },

	/* V0 */
	{
		MIF_CH2_OFFSET,   // MODULE_MIF_CHN
		AIF0_CH2_OFFSET,  // MODULE_AIF0_CHN
		AIF1_CH2_OFFSET,  // MODULE_AIF1_CHN
		MCTL_CTL_MUTEX_RCH2,  // MODULE_MCTL_CHN_MUTEX
		DSS_MCTRL_SYS_OFFSET + MCTL_RCH2_FLUSH_EN,  // MODULE_MCTL_CHN_FLUSH_EN
		DSS_MCTRL_SYS_OFFSET + MCTL_RCH2_OV_OEN,  // MODULE_MCTL_CHN_OV_OEN
		DSS_MCTRL_SYS_OFFSET + MCTL_RCH2_STARTY,  // MODULE_MCTL_CHN_STARTY
		DSS_MCTRL_SYS_OFFSET + MCTL_MOD2_DBG,  // MODULE_MCTL_CHN_MOD_DBG
		DSS_RCH_VG0_DMA_OFFSET,  // MODULE_DMA
		DSS_RCH_VG0_DFC_OFFSET,  // MODULE_DFC
		DSS_RCH_VG0_SCL_OFFSET,  // MODULE_SCL
		DSS_RCH_VG0_SCL_LUT_OFFSET,  // MODULE_SCL_LUT
		DSS_RCH_VG0_ARSR_OFFSET,  // MODULE_ARSR2P
		DSS_RCH_VG0_ARSR_LUT_OFFSET,  // MODULE_ARSR2P_LUT
#if defined(CONFIG_DSS_TYPE_KIRIN970)
		0, // MODULE_POST_CLIP_ES
#endif
		DSS_RCH_VG0_POST_CLIP_OFFSET,  // MODULE_POST_CLIP
		DSS_RCH_VG0_PCSC_OFFSET,  // MODULE_PCSC
		DSS_RCH_VG0_CSC_OFFSET,  // MODULE_CSC
	},

	/* G0   V1    G1    D2    D3    W0     W1     V2     W2 */
	{ 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 }, { 0 },
};

uint32_t g_dss_module_ovl_base[DSS_MCTL_IDX_MAX][MODULE_OVL_MAX] = {
	{DSS_OVL0_OFFSET,
		DSS_MCTRL_CTL0_OFFSET},

	{DSS_OVL1_OFFSET,
		DSS_MCTRL_CTL1_OFFSET},

	{DSS_OVL2_OFFSET,
		DSS_MCTRL_CTL2_OFFSET},

	{DSS_OVL3_OFFSET,
		DSS_MCTRL_CTL3_OFFSET},

	{DSS_OVL0_OFFSET,
		DSS_MCTRL_CTL4_OFFSET},

	{0,
		DSS_MCTRL_CTL5_OFFSET},
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

