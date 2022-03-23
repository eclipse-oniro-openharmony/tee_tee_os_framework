/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display ldi registers configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_ldi.h"

static void dss_single_frame_update(struct hisifb_data_type *hisifd)
{
	uint32_t ldi_base;

	HISI_FB_DEBUG("enter!\n");
	ldi_base = hisifd->dss_base + DSS_LDI0_OFFSET;
	hisifd->set_reg(ldi_base + LDI_FRM_MSK_UP, 0x1, 1, 0);
	hisifd->set_reg(ldi_base + LDI_CTRL, 0x1, 1, 0);
	HISI_FB_DEBUG("exit!\n");
}

// index = "start" or "end"
static void dss_vactive0_dump(struct hisifb_data_type *hisifd)
{
	uint32_t isr_s1;
	uint32_t isr_s1_mask;
	uint32_t isr_s2;
	uint32_t isr_s2_mask;
	uint32_t ldi_base;

	ldi_base = hisifd->dss_base + DSS_LDI0_OFFSET;
	isr_s1_mask = inp32(hisifd->dss_base + GLB_MCU_PDP_INT_MSK);
	isr_s1 = inp32(hisifd->dss_base + GLB_MCU_PDP_INTS);
	isr_s2_mask = inp32(ldi_base + LDI_MCU_ITF_INT_MSK);
	isr_s2 = inp32(ldi_base + LDI_MCU_ITF_INTS);

	HISI_FB_ERR("wait vactive0 timeout: vactive_start_flag = %d, vactive_end_flag = %d,"
		"isr_s1_mask = 0x%x, isr_s1 = 0x%x,"
		"isr_s2_mask = 0x%x, isr_s2 = 0x%x,"
		"LDI_CTRL = 0x%x, LDI_FRM_MSK = 0x%x\n",
		hisifd->vactive_start_flag, hisifd->frame_end_flag,
		isr_s1_mask, isr_s1,
		isr_s2_mask, isr_s2,
		inp32(ldi_base + LDI_CTRL), inp32(ldi_base + LDI_FRM_MSK));
}

// get irq status and clear it, return irq status
static int dss_clear_irq(struct hisifb_data_type *hisifd)
{
	uint32_t isr_s1, isr_s2;

	isr_s1 = inp32(hisifd->dss_base + GLB_MCU_PDP_INTS);
	isr_s2 = inp32(hisifd->dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INTS);
	outp32(hisifd->dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INTS, isr_s2);
	outp32(hisifd->dss_base + GLB_MCU_PDP_INTS, isr_s1);
	return (int)isr_s2;
}

static void dss_mcu_interrupt_mask(struct hisifb_data_type *hisifd)
{
	uint32_t mask;

	mask = ~0;
	outp32(hisifd->dss_base + DSS_LDI0_OFFSET + LDI_MCU_ITF_INT_MSK, mask);
	outp32(hisifd->dss_base + GLB_MCU_PDP_INT_MSK, mask);
	outp32(hisifd->dss_base + GLB_MCU_OFF_INT_MSK, mask);
}

static void dss_mcu_interrupt_unmask(struct hisifb_data_type *hisifd)
{
	uint32_t unmask;
	uint32_t ldi_base;

	ldi_base = hisifd->dss_base + DSS_LDI0_OFFSET;

	// irq unmask
	unmask = ~0;
	unmask &= ~(BIT_ITF0_INTS);
	outp32(hisifd->dss_base + GLB_MCU_PDP_INT_MSK, unmask);

	unmask = ~0;
	unmask &= ~(BIT_VACTIVE0_START | BIT_FRM_END | BIT_LDI_UNFLOW);

	outp32(ldi_base + LDI_MCU_ITF_INT_MSK, unmask);
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




