/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display ldi registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_ldi.h"

/* In the fold sences, judge the mipi type from panel resolutions */
static bool is_dual_mipi(struct hisifb_data_type *hisifd)
{
	if ((hisifd->xres == TUI_FOLD_PANEL_XRES1) && (hisifd->yres == TUI_FOLD_PANEL_YRES1))
		return true;

	return false;
}

bool is_dsi1_te1(struct hisifb_data_type *hisifd)
{
	if ((hisifd->xres == TUI_FOLD_PANEL_XRES2) && (hisifd->yres == TUI_FOLD_PANEL_YRES2))
		return true;

	return false;
}

static uint32_t get_mipi_dsi_base(struct hisifb_data_type *hisifd)
{
	uint32_t mipi_dsi_base;

	mipi_dsi_base = hisifd->mipi_dsi0_base;
	if (is_dsi1_te1(hisifd)) {
		mipi_dsi_base = hisifd->mipi_dsi1_base;
	}
	return mipi_dsi_base;
}

static void dss_single_frame_update(struct hisifb_data_type *hisifd)
{
	HISI_FB_DEBUG("enter+!\n");

	uint32_t mipi_dsi_base;

	if (hisifd == NULL) {
		HISI_FB_ERR("hisifd is NULL");
		return;
	}

	mipi_dsi_base = get_mipi_dsi_base(hisifd);

	hisifd->set_reg(mipi_dsi_base + MIPI_LDI_FRM_MSK_UP, 0x1, 1, 0);
	if (is_dual_mipi(hisifd)) {
		hisifd->set_reg(hisifd->mipi_dsi1_base + MIPI_LDI_FRM_MSK_UP, 0x1, 1, 0);
		hisifd->set_reg(mipi_dsi_base + MIPI_LDI_CTRL, 0x1, 1, 5);
		return;
	}
	hisifd->set_reg(mipi_dsi_base + MIPI_LDI_CTRL, 0x1, 1, 0);

	HISI_FB_DEBUG("exit-!\n");
}

static void dss_vactive0_dump(struct hisifb_data_type *hisifd)
{
	uint32_t isr_s1;
	uint32_t isr_s1_mask;
	uint32_t isr_s2;
	uint32_t isr_s2_mask;
	uint32_t mipi_dsi_base;

	mipi_dsi_base = get_mipi_dsi_base(hisifd);

	isr_s1_mask = inp32(hisifd->dss_base + GLB_MCU_PDP_INT_MSK);
	isr_s1 = inp32(hisifd->dss_base + GLB_MCU_PDP_INTS);
	isr_s2_mask = inp32(mipi_dsi_base + MIPI_LDI_MCU_ITF_INT_MSK);
	isr_s2 = inp32(mipi_dsi_base + MIPI_LDI_MCU_ITF_INTS);

	HISI_FB_ERR("wait vactive0 timeout: vactive_start_flag = %d, vactive_end_flag = %d,"
		"isr_s1_mask = 0x%x, isr_s1 = 0x%x,"
		"isr_s2_mask = 0x%x, isr_s2 = 0x%x,"
		"LDI_CTRL(0x%x), LDI_FRM_MSK(0x%x)\n",
		hisifd->vactive_start_flag, hisifd->frame_end_flag,
		isr_s1_mask, isr_s1,
		isr_s2_mask, isr_s2,
		inp32(mipi_dsi_base + MIPI_LDI_CTRL), inp32(mipi_dsi_base + MIPI_LDI_FRM_MSK));
}

// get irq status and clear it, return irq status
static int dss_clear_irq(struct hisifb_data_type *hisifd)
{
	uint32_t isr_s1;
	uint32_t isr_s2;
	uint32_t mipi_dsi_base;

	mipi_dsi_base = get_mipi_dsi_base(hisifd);

	isr_s1 = inp32(hisifd->dss_base + GLB_MCU_PDP_INTS);
	isr_s2 = inp32(mipi_dsi_base + MIPI_LDI_MCU_ITF_INTS);
	outp32(mipi_dsi_base + MIPI_LDI_MCU_ITF_INTS, isr_s2);
	outp32(hisifd->dss_base + GLB_MCU_PDP_INTS, isr_s1);
	return (int)isr_s2;
}

static void dss_mcu_interrupt_mask(struct hisifb_data_type *hisifd)
{
	uint32_t mask;
	uint32_t mipi_dsi_base;

	mask = ~0;
	mipi_dsi_base = get_mipi_dsi_base(hisifd);

	outp32(mipi_dsi_base + MIPI_LDI_MCU_ITF_INT_MSK, mask);
	outp32(hisifd->dss_base + GLB_MCU_PDP_INT_MSK, mask);
	outp32(hisifd->dss_base + GLB_MCU_OFF_INT_MSK, mask);
}

static void dss_mcu_interrupt_unmask(struct hisifb_data_type *hisifd)
{
	uint32_t unmask;
	uint32_t mipi_dsi_base;

	unmask = ~0;
	unmask &= ~(BIT_VACTIVE0_START | BIT_FRM_END | BIT_LDI_UNFLOW);
	mipi_dsi_base = get_mipi_dsi_base(hisifd);

	outp32(mipi_dsi_base + MIPI_LDI_MCU_ITF_INT_MSK, unmask);
}

void dss_registe_base_ldi_cb(struct dss_ldi_cb *ldi_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((ldi_cb == NULL), "ldi_cb is NULL\n");

	ldi_cb->single_frame_update = dss_single_frame_update;
	ldi_cb->vactive0_dump = dss_vactive0_dump;
	ldi_cb->clear_irq = dss_clear_irq;
	ldi_cb->mcu_interrupt_mask = dss_mcu_interrupt_mask;
	ldi_cb->mcu_interrupt_unmask = dss_mcu_interrupt_unmask;

	dss_registe_platform_ldi_cb(ldi_cb);
}



