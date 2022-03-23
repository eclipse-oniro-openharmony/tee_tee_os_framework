/* Copyright (c) 2014-2015, Hisilicon Tech. Co., Ltd. All rights reserved.
 *
 */
#include "tee_mutex.h" /* tee_mutex_lock */
#include "sre_hwi.h" /* SRE_HwiDisable */
#include "hisi_disp.h"
#include "hisi_fb_sec.h"

#define MAX_UNDERFLOW_COUNT   (6)

/*dss_chn_idx
  DSS_RCHN_D2 = 0,	DSS_RCHN_D3,	DSS_RCHN_V0,	DSS_RCHN_G0,	DSS_RCHN_V1,
  DSS_RCHN_G1,	DSS_RCHN_D0,	DSS_RCHN_D1,	DSS_WCHN_W0,	DSS_WCHN_W1,
  DSS_RCHN_V2,   DSS_WCHN_W2,
  */
uint32_t g_dss_module_base[DSS_CHN_MAX_DEFINE][MODULE_CHN_MAX] = {
	// D0
	{
	MIF_CH0_OFFSET,   //MODULE_MIF_CHN
	AIF0_CH0_OFFSET,  //MODULE_AIF0_CHN
	AIF1_CH0_OFFSET,  //MODULE_AIF1_CHN
	MCTL_CTL_MUTEX_RCH0,  //MODULE_MCTL_CHN_MUTEX
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH0_FLUSH_EN,  //MODULE_MCTL_CHN_FLUSH_EN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH0_OV_OEN,  //MODULE_MCTL_CHN_OV_OEN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH0_STARTY,  //MODULE_MCTL_CHN_STARTY
	DSS_MCTRL_SYS_OFFSET + MCTL_MOD0_DBG,  //MODULE_MCTL_CHN_MOD_DBG
	DSS_RCH_D0_DMA_OFFSET,  //MODULE_DMA
	DSS_RCH_D0_DFC_OFFSET,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0, //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	DSS_RCH_D0_CSC_OFFSET,  //MODULE_CSC
	},

	// D1
	{
	MIF_CH1_OFFSET,   //MODULE_MIF_CHN
	AIF0_CH1_OFFSET,  //MODULE_AIF0_CHN
	AIF1_CH1_OFFSET,  //MODULE_AIF1_CHN
	MCTL_CTL_MUTEX_RCH1,  //MODULE_MCTL_CHN_MUTEX
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH1_FLUSH_EN,  //MODULE_MCTL_CHN_FLUSH_EN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH1_OV_OEN,  //MODULE_MCTL_CHN_OV_OEN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH1_STARTY,  //MODULE_MCTL_CHN_STARTY
	DSS_MCTRL_SYS_OFFSET + MCTL_MOD1_DBG,  //MODULE_MCTL_CHN_MOD_DBG
	DSS_RCH_D1_DMA_OFFSET,  //MODULE_DMA
	DSS_RCH_D1_DFC_OFFSET,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0, //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	DSS_RCH_D1_CSC_OFFSET,  //MODULE_CSC
	},

	// V0
	{
	0,   //MODULE_MIF_CHN
	0,  //MODULE_AIF0_CHN
	0,  //MODULE_AIF1_CHN
	0,  //MODULE_MCTL_CHN_MUTEX
	0 ,  //MODULE_MCTL_CHN_FLUSH_EN
	0,  //MODULE_MCTL_CHN_OV_OEN
	0,  //MODULE_MCTL_CHN_STARTY
	0,  //MODULE_MCTL_CHN_MOD_DBG
	0,  //MODULE_DMA
	0,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0,  //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	0,  //MODULE_CSC
	},

	// G0
	{
	0,   //MODULE_MIF_CHN
	0,  //MODULE_AIF0_CHN
	0,  //MODULE_AIF1_CHN
	0,  //MODULE_MCTL_CHN_MUTEX
	0,  //MODULE_MCTL_CHN_FLUSH_EN
	0,  //MODULE_MCTL_CHN_OV_OEN
	0,  //MODULE_MCTL_CHN_STARTY
	0,  //MODULE_MCTL_CHN_MOD_DBG
	0,  //MODULE_DMA
	0,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0,  //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	0,  //MODULE_CSC
	},

	// V1
	{
	MIF_CH4_OFFSET,   //MODULE_MIF_CHN
	AIF0_CH4_OFFSET,  //MODULE_AIF0_CHN
	AIF1_CH4_OFFSET,  //MODULE_AIF1_CHN
	MCTL_CTL_MUTEX_RCH4,  //MODULE_MCTL_CHN_MUTEX
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH4_FLUSH_EN,  //MODULE_MCTL_CHN_FLUSH_EN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH4_OV_OEN,  //MODULE_MCTL_CHN_OV_OEN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH4_STARTY,  //MODULE_MCTL_CHN_STARTY
	DSS_MCTRL_SYS_OFFSET + MCTL_MOD4_DBG,  //MODULE_MCTL_CHN_MOD_DBG
	DSS_RCH_VG1_DMA_OFFSET,  //MODULE_DMA
	DSS_RCH_VG1_DFC_OFFSET,  //MODULE_DFC
	DSS_RCH_VG1_SCL_OFFSET,  //MODULE_SCL
	DSS_RCH_VG1_SCL_LUT_OFFSET,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0,  //MODULE_POST_CLIP_ES
	DSS_RCH_VG1_POST_CLIP_OFFSET,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	DSS_RCH_VG1_CSC_OFFSET,  //MODULE_CSC
	},

	// G1
	{
	MIF_CH5_OFFSET,   //MODULE_MIF_CHN
	AIF0_CH5_OFFSET,  //MODULE_AIF0_CHN
	AIF1_CH5_OFFSET,  //MODULE_AIF1_CHN
	MCTL_CTL_MUTEX_RCH5,  //MODULE_MCTL_CHN_MUTEX
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH5_FLUSH_EN,  //MODULE_MCTL_CHN_FLUSH_EN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH5_OV_OEN,  //MODULE_MCTL_CHN_OV_OEN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH5_STARTY,  //MODULE_MCTL_CHN_STARTY
	DSS_MCTRL_SYS_OFFSET + MCTL_MOD5_DBG,  //MODULE_MCTL_CHN_MOD_DBG
	DSS_RCH_G1_DMA_OFFSET,  //MODULE_DMA
	DSS_RCH_G1_DFC_OFFSET,  //MODULE_DFC
	DSS_RCH_G1_SCL_OFFSET,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0,  //MODULE_POST_CLIP_ES
	DSS_RCH_G1_POST_CLIP_OFFSET,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	DSS_RCH_G1_CSC_OFFSET,  //MODULE_CSC
	},

	// D2
	{
	MIF_CH6_OFFSET,   //MODULE_MIF_CHN
	AIF0_CH6_OFFSET,  //MODULE_AIF0_CHN
	AIF1_CH6_OFFSET,  //MODULE_AIF1_CHN
	MCTL_CTL_MUTEX_RCH6,  //MODULE_MCTL_CHN_MUTEX
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH6_FLUSH_EN,  //MODULE_MCTL_CHN_FLUSH_EN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH6_OV_OEN,  //MODULE_MCTL_CHN_OV_OEN
	DSS_MCTRL_SYS_OFFSET + MCTL_RCH6_STARTY,  //MODULE_MCTL_CHN_STARTY
	DSS_MCTRL_SYS_OFFSET + MCTL_MOD6_DBG,  //MODULE_MCTL_CHN_MOD_DBG
	DSS_RCH_D2_DMA_OFFSET,  //MODULE_DMA
	DSS_RCH_D2_DFC_OFFSET,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0, //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	DSS_RCH_D2_CSC_OFFSET,  //MODULE_CSC
	},

	// D3
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
	0, //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	DSS_RCH_D3_CSC_OFFSET,  //MODULE_CSC
	},

	// W0
	{
	MIF_CH8_OFFSET,   //MODULE_MIF_CHN
	AIF0_CH8_OFFSET,  //MODULE_AIF0_CHN
	AIF1_CH8_OFFSET,  //MODULE_AIF1_CHN
	MCTL_CTL_MUTEX_WCH0,  //MODULE_MCTL_CHN_MUTEX
	DSS_MCTRL_SYS_OFFSET + MCTL_WCH0_FLUSH_EN,  //MODULE_MCTL_CHN_FLUSH_EN
	DSS_MCTRL_SYS_OFFSET + MCTL_WCH0_OV_IEN,  //MODULE_MCTL_CHN_OV_OEN
	0,  //MODULE_MCTL_CHN_STARTY
	0,  //MODULE_MCTL_CHN_MOD_DBG
	DSS_WCH0_DMA_OFFSET,  //MODULE_DMA
	DSS_WCH0_DFC_OFFSET,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0, //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	DSS_WCH0_CSC_OFFSET,  //MODULE_CSC
	},

	// W1
	{
	0,   //MODULE_MIF_CHN
	0,  //MODULE_AIF0_CHN
	0,  //MODULE_AIF1_CHN
	0,  //MODULE_MCTL_CHN_MUTEX
	0,  //MODULE_MCTL_CHN_FLUSH_EN
	0,  //MODULE_MCTL_CHN_OV_OEN
	0,  //MODULE_MCTL_CHN_STARTY
	0,  //MODULE_MCTL_CHN_MOD_DBG
	0,  //MODULE_DMA
	0,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0, //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	0,  //MODULE_CSC
	},

	// V2
	{
	0,   //MODULE_MIF_CHN
	0,  //MODULE_AIF0_CHN
	0,  //MODULE_AIF1_CHN
	0,  //MODULE_MCTL_CHN_MUTEX
	0,  //MODULE_MCTL_CHN_FLUSH_EN
	0,  //MODULE_MCTL_CHN_OV_OEN
	0,  //MODULE_MCTL_CHN_STARTY
	0,  //MODULE_MCTL_CHN_MOD_DBG
	0,  //MODULE_DMA
	0,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0,  //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	0,  //MODULE_CSC
	},
	// W2
	{
	0,   //MODULE_MIF_CHN
	0,  //MODULE_AIF0_CHN
	0,  //MODULE_AIF1_CHN
	0,  //MODULE_MCTL_CHN_MUTEX
	0,  //MODULE_MCTL_CHN_FLUSH_EN
	0,  //MODULE_MCTL_CHN_OV_OEN
	0,  //MODULE_MCTL_CHN_STARTY
	0,  //MODULE_MCTL_CHN_MOD_DBG
	0,  //MODULE_DMA
	0,  //MODULE_DFC
	0,  //MODULE_SCL
	0,  //MODULE_SCL_LUT
	0,  //MODULE_ARSR2P
	0,  //MODULE_ARSR2P_LUT
	0, //MODULE_POST_CLIP_ES
	0,  //MODULE_POST_CLIP
	0,  //MODULE_PCSC
	0,  //MODULE_CSC
	},
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

//SCF_LUT_CHN coef_idx
int g_scf_lut_chn_coef_idx[DSS_CHN_MAX_DEFINE] = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

uint32_t g_dss_module_cap[DSS_CHN_MAX_DEFINE][MODULE_CAP_MAX] = {
	/* D2 */
	{0,0,1,0,0,0,1,0,0,0,1},
	/* D3 */
	{0,0,1,0,0,0,0,0,0,0,1},
	/* V0 */
	{0,1,1,0,1,1,1,0,0,1,1},
	/* G0 */
	{0,1,0,0,0,0,1,0,0,0,0},
	/* V1 */
	{0,1,1,1,0,1,1,0,1,1,1},
	/* G1 */
	{0,1,0,0,0,0,1,0,0,0,0},
	/* D0 */
	{0,0,1,0,0,0,0,0,0,0,1},
	/* D1 */
	{0,0,1,0,0,0,0,0,0,0,1},

	/* W0 */
	{1,0,1,0,0,0,0,1,0,1,1},
	/* W1 */
	{1,0,1,0,0,0,0,1,0,1,1},

	/* V2 */
	{0,1,1,1,0,1,1,0,1,1,1},
	/* W2 */
	{1,0,1,0,0,0,0,1,0,1,1},
};

/* number of smrx idx for each channel */
uint32_t g_dss_chn_sid_num[DSS_CHN_MAX_DEFINE] = {
	//D0 D1 V0 G0 V1 G1 D2 D3 W0 W1 V2 W2
	4, 4, 0, 0, 4, 4, 1, 1, 3, 0, 0, 0
};

/* start idx of each channel */
/* smrx_idx = g_dss_smmu_smrx_idx[chn_idx] + (0 ~ g_dss_chn_sid_num[chn_idx]) */
uint32_t g_dss_smmu_smrx_idx[DSS_CHN_MAX_DEFINE] = {
	//D0 D1 V0 G0 V1 G1 D2 D3 W0 W1 V2 W2
	0, 4, 0, 0, 8, 12, 16, 17, 18, 0, 0, 0
};

uint32_t g_dss_mif_sid_map[DSS_CHN_MAX] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

void hisi_dss_mcu_interrupt_mask(struct hisifb_data_type *hisifd)
{
	uint32_t dss_base;
	uint32_t mask;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}
	dss_base = hisifd->dss_base;
	mask = ~0;
	outp32(dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INT_MSK, mask);
	outp32(dss_base + GLB_MCU_PDP_INT_MSK, mask);
	outp32(dss_base + GLB_MCU_OFF_INT_MSK, mask);
}

void hisi_dss_mcu_interrupt_unmask(struct hisifb_data_type *hisifd)
{
	uint32_t unmask;
	uint32_t ldi_base;
	uint32_t dss_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}
	dss_base = hisifd->dss_base;
	ldi_base = dss_base + DSS_LDI0_OFFSET;

	//irq unmask
	unmask = ~0;
	unmask &= ~(BIT_ITF0_INTS);
	outp32(dss_base + GLB_MCU_PDP_INT_MSK, unmask);

	unmask = ~0;
	unmask &= ~(BIT_VACTIVE0_START | BIT_FRM_END | BIT_LDI_UNFLOW);

	outp32(ldi_base + LDI_MCU_ITF_INT_MSK, unmask);
}

int hisi_vactive0_start_config(struct hisifb_data_type *hisifd)
{
	int count = 0;
	uint32_t isr_s1 = 0;
	uint32_t isr_s1_mask = 0;
	uint32_t isr_s2 = 0;
	uint32_t isr_s2_mask = 0;
	uint32_t dss_base;
	uint32_t ldi_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}

	dss_base = hisifd->dss_base;
	ldi_base = dss_base + DSS_LDI0_OFFSET;

	int prev_vactive0_start = hisifd->vactive_start_flag;
	single_frame_update(hisifd);
	HISI_FB_DEBUG("prev_vactive0_start = %d  enter! \n", prev_vactive0_start);

	/* check vactive start flag, if 0, wait until changed to 1,
	 * the maximum waiting time is 200ms
	 */
	do {
		if (hisifd->vactive_start_flag != prev_vactive0_start) {
			HISI_FB_DEBUG("vactive_start_flag = %d exit! \n", hisifd->vactive_start_flag);
			break;
		} else {
			HISI_FB_DEBUG(" count=%d! \n", count);
			SRE_SwMsleep(1);
			count++;
		}
	} while (count < TIME_OUT);

	if (count == TIME_OUT) {
		isr_s1_mask = inp32(dss_base + GLB_MCU_PDP_INT_MSK);
		isr_s1      = inp32(dss_base + GLB_MCU_PDP_INTS);
		isr_s2_mask = inp32(ldi_base + LDI_MCU_ITF_INT_MSK);
		isr_s2      = inp32(ldi_base + LDI_MCU_ITF_INTS);

		HISI_FB_ERR("wait vactive0_start timeout: vactive_start_flag = %d,"
				"isr_s1_mask = 0x%x, isr_s1 = 0x%x,"
				"isr_s2_mask = 0x%x, isr_s2 = 0x%x,"
				"LDI_CTRL(0x%x), LDI_FRM_MSK(0x%x).\n",
				hisifd->vactive_start_flag,
				isr_s1_mask, isr_s1,
				isr_s2_mask, isr_s2,
				inp32(ldi_base + LDI_CTRL), inp32(ldi_base + LDI_FRM_MSK));
		return -1;
	}

	return 0;
}

int hisi_frame_end_config(struct hisifb_data_type *hisifd)
{
	int count = 0;
	uint32_t isr_s1 = 0;
	uint32_t isr_s1_mask = 0;
	uint32_t isr_s2 = 0;
	uint32_t isr_s2_mask = 0;
	uint32_t dss_base;
	uint32_t ldi_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}
	dss_base = hisifd->dss_base;
	ldi_base = dss_base + DSS_LDI0_OFFSET;
	int prev_frame_end = hisifd->frame_end_flag;

	single_frame_update(hisifd);

	HISI_FB_DEBUG("prev_frame_end = %d enter!\n", prev_frame_end);

	/* check vactive end flag, if 0, wait until it is changed to 1,
	 * the maximum waiting time is 200ms
	 */
	do {
		if (hisifd->frame_end_flag != prev_frame_end) {
			HISI_FB_DEBUG("frame_end_flag = %d exit! \n", hisifd->frame_end_flag);
			break;
		} else {
			HISI_FB_DEBUG("frame_end_flag count=%d! \n", count);
			SRE_SwMsleep(1);
			count++;
		}
	} while (count < TIME_OUT);

	if (count == TIME_OUT) {
		isr_s1_mask = inp32(hisifd->dss_base + GLB_MCU_PDP_INT_MSK);
		isr_s1      = inp32(hisifd->dss_base + GLB_MCU_PDP_INTS);
		isr_s2_mask = inp32(ldi_base + LDI_MCU_ITF_INT_MSK);
		isr_s2      = inp32(ldi_base + LDI_MCU_ITF_INTS);

		HISI_FB_ERR("wait frame_end timeout: frame_end_flag = %d,"
				"isr_s1_mask = 0x%x, isr_s1 = 0x%x,"
				"isr_s2_mask = 0x%x, isr_s2 = 0x%x,"
				"LDI_CTRL(0x%x), LDI_FRM_MSK(0x%x).\n",
				hisifd->frame_end_flag,
				isr_s1_mask, isr_s1,
				isr_s2_mask, isr_s2,
				inp32(ldi_base + LDI_CTRL), inp32(ldi_base + LDI_FRM_MSK));

		return -1;
	}

	return 0;
}

void dump_dss_reg_info(struct hisifb_data_type *hisifd)
{
	uint32_t count = 0;
	uint32_t step = 0;
	uint32_t dss_base;
	uint32_t ovl_base;
	uint32_t rdma_base;
	uint32_t mctrl_sys_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}

	if (hisifd->sec_rch_idx >= DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("sec_rch_idx is invalid!\n", hisifd->sec_rch_idx);
		return;
	}

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid!\n", hisifd->sec_mctl_idx);
		return;
	}

	dss_base = hisifd->dss_base;
	mctrl_sys_base = dss_base + DSS_MCTRL_SYS_OFFSET;
	rdma_base = dss_base + g_dss_module_base[hisifd->sec_rch_idx][MODULE_DMA];
	ovl_base  = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_OVL_BASE];

	while (step < 0x029C) {
		count = 0;
		do {
			if (count == 0) {
				HISI_FB_ERR("------ MCTL_SYS[0x%x]: 0x%x \t",
						mctrl_sys_base + step, inp32(mctrl_sys_base + step));
			} else {
				HISI_FB_PRINTF(" 0x%x \t", inp32(mctrl_sys_base + step));
			}
			step += 0x4;
			count++;
		} while (count < 4);
		HISI_FB_PRINTF("\n");
	}

	step = 0x0;
	while (step < 0x0070) {
		count = 0;
		do {
			if (count == 0) {
				HISI_FB_ERR("------ MCTRL_CTL0[0x%x]: 0x%x \t",
						dss_base + DSS_MCTRL_CTL0_OFFSET + step,
						inp32(dss_base + DSS_MCTRL_CTL0_OFFSET + step));
			} else {
				HISI_FB_PRINTF(" 0x%x \t", inp32(dss_base + DSS_MCTRL_CTL0_OFFSET + step));
			}
			step += 0x4;
			count++;
		} while (count < 4);
		HISI_FB_PRINTF("\n");
	}

	step = 0x0;
	while (step < 0x0070) {
		count = 0;
		do {
			if (count == 0) {
				HISI_FB_ERR("------ MCTRL_CTL4[0x%x]: 0x%x \t",
						dss_base + DSS_MCTRL_CTL4_OFFSET + step,
						inp32(dss_base + DSS_MCTRL_CTL4_OFFSET + step));
			} else {
				HISI_FB_PRINTF(" 0x%x \t", inp32(hisifd->dss_base + DSS_MCTRL_CTL4_OFFSET + step));
			}
			step += 0x4;
			count++;
		} while (count < 4);
		HISI_FB_PRINTF("\n");
	}

	step = 0x0;
	while (step < 0x0020) {
		count = 0;
		do {
			if (count == 0) {
				HISI_FB_ERR("------ RCH_DMA[0x%x]: 0x%x \t",
						rdma_base + step, inp32(rdma_base + step));
			} else {
				HISI_FB_PRINTF(" 0x%x \t", inp32(rdma_base + step));
			}
			step += 0x4;
			count++;
		} while (count < 4);
		HISI_FB_PRINTF("\n");
	}

	step = 0x60;
	while (step < 0x0070) {
		count = 0;
		do {
			if (count == 0) {
				HISI_FB_ERR("------ RCH_DMA[0x%x]: 0x%x \t",
						rdma_base + step, inp32(rdma_base + step));
			} else {
				HISI_FB_PRINTF(" 0x%x \t", inp32(rdma_base + step));
			}
			step += 0x4;
			count++;
		} while (count < 4);
		HISI_FB_PRINTF("\n");
	}

	step = 0x0;
	while (step < 0x188) {
		count = 0;
		do {
			if (count == 0) {
				HISI_FB_ERR("------ OV6[0x%x]: 0x%x \t",
						ovl_base + step, inp32(ovl_base + step));
			} else {
				HISI_FB_PRINTF(" 0x%x \t", inp32(ovl_base + step));
			}
			step += 0x4;
			count++;
		} while (count < 4);
		HISI_FB_PRINTF("\n");
	}
}

static int hisi_fb_underflow_clear(struct hisifb_data_type *hisifd)
{
	int ret;
	uint32_t mctl_base;
	uint32_t isr_s1, isr_s2;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}
	uint32_t dss_base = hisifd->dss_base;

	if (hisifd->sec_mctl_idx >= DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n", hisifd->sec_mctl_idx);
		return -1;
	}

	HISI_FB_INFO("+.!\n");

	if (tee_mutex_lock(hisifd->disp_lock)){
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}

	if (hisifd->panel_power_on && hisifd->panel_power_on(hisifd)) {
		HISI_FB_INFO("hisi fb is already power off!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}
	hisi_dss_mcu_interrupt_mask(hisifd);

	ret = (int)SRE_HwiDisable(hisifd->dpe_sec_irq);
	if (ret != 0) {
		HISI_FB_ERR("failed to disable fb irq!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}
	hisi_exit_secu_pay(hisifd);

	// clear config
	mctl_base = dss_base + g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_MCTL_BASE];
	hisifd->set_reg(mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);
	SRE_SwMsleep(5);
	hisifd->set_reg(mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);
	SRE_SwMsleep(5);
	hisifd->set_reg(mctl_base + MCTL_CTL_CLEAR, 0x1, 1, 0);
	SRE_SwMsleep(32);

	hisifd->alpha_enable = 0;
	hisifd->first_frame = 1;
	ret = (int)SRE_HwiEnable(hisifd->dpe_sec_irq);
	if (ret != 0) {
		HISI_FB_ERR("failed to enable fb irq!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	hisi_dss_mcu_interrupt_unmask(hisifd);
	isr_s1 = inp32(dss_base + GLB_MCU_PDP_INTS);
	isr_s2 = inp32(dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INTS);
	outp32(dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INTS, isr_s2);
	outp32(dss_base + GLB_MCU_PDP_INTS, isr_s1);

	if (hisifd->pan_display_sec) {
		ret = hisifd->pan_display_sec(hisifd, &(hisifd->layer));
	}
	tee_mutex_unlock(hisifd->disp_lock);
	HISI_FB_INFO("-.!\n");

	return ret;
}

int hisi_fb_irq_handle(uint32_t ptr)
{
	uint32_t isr_s1, isr_s2;
	struct hisifb_data_type *hisifd;
	uint32_t dss_base;
	static int count = 0;

	hisifd = (struct hisifb_data_type *)ptr;
	if (!hisifd) {
		HISI_FB_ERR("hisifd is NULL\n");
		return -1;
	}
	dss_base = hisifd->dss_base;
	isr_s1 = inp32(dss_base + GLB_MCU_PDP_INTS);
	isr_s2 = inp32(dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INTS);
	outp32(dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INTS, isr_s2);
	outp32(dss_base + GLB_MCU_PDP_INTS, isr_s1);

	//vactive_start irq
	if (isr_s2 & BIT_VACTIVE0_START) {
		HISI_FB_DEBUG("BIT_VACTIVE0_START hisifd->vactive_start_flag =%d \n", hisifd->vactive_start_flag);
		hisifd->vactive_start_flag++;
	}

	if (isr_s2 & BIT_FRM_END) {
		HISI_FB_DEBUG("BIT_FRM_END hisifd->frame_end_flag = %d \n", hisifd->frame_end_flag);
		hisifd->frame_end_flag++;
	}

	if (isr_s2 & BIT_LDI_UNFLOW) {
		if (count == 0) {
			hisi_fb_underflow_clear(hisifd);
		}
		count++;
		if (count == MAX_UNDERFLOW_COUNT) {
			HISI_FB_ERR("ldi underflow!\n");
			count = 0;
		}

		if (hisifd->disp_debug_dump == 1) {
			HISI_FB_INFO("dump_dss_reg_info shadow regs-----------\n");
			hisifd->set_reg(dss_base + DSS_SEC_RCH_DMA_OFFSET + CH_RD_SHADOW, 0x1, 1, 0);
			hisifd->set_reg(dss_base + DSS_OVL0_OFFSET + OVL6_RD_SHADOW_SEL, 0x1, 1, 0);
			dump_dss_reg_info(hisifd);

			hisifd->set_reg(dss_base + DSS_SEC_RCH_DMA_OFFSET + CH_RD_SHADOW, 0x0, 1, 0);
			hisifd->set_reg(dss_base + DSS_OVL0_OFFSET + OVL6_RD_SHADOW_SEL, 0x0, 1, 0);

			HISI_FB_INFO("dump_dss_reg_info work regs-----------\n");
			dump_dss_reg_info(hisifd);
			hisifd->disp_debug_dump = 0;
		}
	}

	return 0;
}

int hisi_dss_mif_config(struct hisifb_data_type *hisifd, uint32_t chn_idx, int securemode)
{
	uint32_t mif_ch_base;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}

	if (chn_idx >=  DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("chn_idx is invalid! \n");
		return -1;
	}

	HISI_FB_DEBUG("+.\n");

	mif_ch_base = hisifd->dss_base +
		g_dss_module_base[chn_idx][MODULE_MIF_CHN];

	if (securemode) {
		hisifd->set_reg(mif_ch_base + MIF_CTRL1, 0x00000020, 32, 0);
		hisifd->set_reg(mif_ch_base + MIF_CTRL2, 0x0, 32, 0);
		hisifd->set_reg(mif_ch_base + MIF_CTRL3, 0x0, 32, 0);
		hisifd->set_reg(mif_ch_base + MIF_CTRL4, 0x0, 32, 0);
		hisifd->set_reg(mif_ch_base + MIF_CTRL5, 0x0, 32, 0);
	}

	HISI_FB_DEBUG("-.\n");

	return 0;
}

int hisi_dss_smmu_config(struct hisifb_data_type *hisifd, uint32_t chn_idx, int securemode)
{
	uint32_t smmu_base;
	uint32_t idx = 0, i = 0;

	if (!hisifd) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return -1;
	}

	if (chn_idx >=  DSS_CHN_MAX_DEFINE) {
		HISI_FB_ERR("chn_idx is invalid! \n");
		return -1;
	}

	HISI_FB_DEBUG("+.\n");

	smmu_base = hisifd->dss_base + DSS_SMMU_OFFSET;

	if (securemode) {
		for (i = 0; i < g_dss_chn_sid_num[chn_idx]; i++) {
			idx = g_dss_smmu_smrx_idx[chn_idx] + i;
			hisifd->set_reg(smmu_base + SMMU_SMRx_S + idx * 0x4, 0x6, 3, 0);
			 if (idx < 32) {
				hisifd->set_reg(smmu_base + SMMU_RLD_EN0_S, 0x1, 1, (uint8_t)idx);
				hisifd->set_reg(smmu_base + SMMU_RLD_EN0_P, 0x1, 1, (uint8_t)idx);
				hisifd->set_reg(smmu_base + SMMU_RLD_EN0_NS, 0x1, 1, (uint8_t)idx);
			 } else {
				hisifd->set_reg(smmu_base + SMMU_RLD_EN1_S, 0x1, 1, (uint8_t)(idx - 32));
				hisifd->set_reg(smmu_base + SMMU_RLD_EN1_P, 0x1, 1, (uint8_t)(idx - 32));
				hisifd->set_reg(smmu_base + SMMU_RLD_EN1_NS, 0x1, 1, (uint8_t)(idx - 32));
			 }
		}
	} else {
		for (i = 0; i < g_dss_chn_sid_num[chn_idx]; i++) {
			idx = g_dss_smmu_smrx_idx[chn_idx] + i;
			hisifd->set_reg(smmu_base + SMMU_SMRx_S + idx * 0x4, 0x3, 3, 0);
			if (idx < 32) {
				hisifd->set_reg(smmu_base + SMMU_RLD_EN0_S, 0x1, 1, (uint8_t)idx);
				hisifd->set_reg(smmu_base + SMMU_RLD_EN0_P, 0x1, 1, (uint8_t)idx);
				hisifd->set_reg(smmu_base + SMMU_RLD_EN0_NS, 0x1, 1, (uint8_t)idx);
			 } else {
				hisifd->set_reg(smmu_base + SMMU_RLD_EN1_S, 0x1, 1, (uint8_t)(idx - 32));
				hisifd->set_reg(smmu_base + SMMU_RLD_EN1_P, 0x1, 1, (uint8_t)(idx - 32));
				hisifd->set_reg(smmu_base + SMMU_RLD_EN1_NS, 0x1, 1, (uint8_t)(idx - 32));
			 }
		}
	}

	HISI_FB_DEBUG("-.\n");
	return 0;
}

void hisi_dss_ovl_layer_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	uint32_t ovl0_base;

	if (!hisifd || !layer) {
		HISI_FB_ERR("The input parameter is NULL\n");
		return;
	}

	if (hisifd->sec_mctl_idx >=  DSS_MCTL_IDX_MAX) {
		HISI_FB_ERR("sec_mctl_idx is invalid! \n");
		return;
	}

	HISI_FB_DEBUG("enter! \n");

	ovl0_base = hisifd->dss_base +
		g_dss_module_ovl_base[hisifd->sec_mctl_idx][MODULE_OVL_BASE];

	hisifd->set_reg(ovl0_base + OVL_LAYER5_POS, (layer->dst_rect.x)|(layer->dst_rect.y << 16), 32, 0);
	hisifd->set_reg(ovl0_base + OVL_LAYER5_SIZE, DSS_WIDTH(layer->dst_rect.x + layer->dst_rect.w)
		| (DSS_HEIGHT(layer->dst_rect.y + layer->dst_rect.h) << 16), 32, 0);

	if (hisifd->alpha_enable) {
		hisifd->set_reg(ovl0_base + OVL_LAYER5_ALPHA, 0xA0CCE0CC, 32, 0);
	} else {
		hisifd->set_reg(ovl0_base + OVL_LAYER5_ALPHA, 0x00ff40ff, 32, 0);
	}
	hisifd->set_reg(ovl0_base + OVL_LAYER5_CFG, 0x1, 1, 0);
	HISI_FB_DEBUG("exit! \n");
}

