/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display main process
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */
#include <sre_hwi.h> // HWI_PROC_FUNC
#include "tee_mutex.h"
#include "hisi_overlay_utils.h"
#include "hisi_dss_module_registe.h"

static void hisi_enter_secure_display(struct hisifb_data_type *hisifd)
{
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_NO_RETVAL((hisifd == NULL), "hisifd is NULL\n");

	hisi_vactive0_start_config(hisifd);
	HISI_FB_INFO("enter !\n");
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.enter_display_mctl_config, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->smmu_cb.smmu_config, hisifd, SECURE_MODE);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mif_cb.mif_config, hisifd, SECURE_MODE);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.enter_display_mctrl_config, hisifd);
	HISI_FB_INFO("exit !\n");
}

static void hisi_exit_secure_display(struct hisifb_data_type *hisifd)
{
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_NO_RETVAL((hisifd == NULL), "hisifd is NULL\n");

	HISI_FB_DEBUG("enter !\n");
	HISI_CHECK_AND_CALL_FUNC(module_cb->smmu_cb.smmu_config, hisifd, NON_SECURE_MODE);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mif_cb.mif_config, hisifd, NON_SECURE_MODE);
	HISI_CHECK_AND_CALL_FUNC(module_cb->dma_cb.exit_display_rdma_config, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.exit_display_mctl_mctrl_config, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mix_cb.dump_secure_display_reg, hisifd, DUMP_REG_ALWAYS, DUMP_REG_SHADOW);
	HISI_FB_DEBUG("clear secure config success!\n");
}

static void hisi_secure_config_clear(struct hisifb_data_type *hisifd)
{
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_NO_RETVAL((hisifd == NULL), "hisifd is NULL\n");

	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.mctl_mutex_lock, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->ovl_cb.ovl_config_clear, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.mctl_sec_flush_en, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.mctl_mutex_unlock, hisifd);
	HISI_FB_INFO("clear secure layer config ok, wait for frame update!\n");

	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.single_frame_update, hisifd);
	// make sure secure layer exit.
	hisi_vactive0_start_config(hisifd);
}

static bool dss_is_vactive0_action_done(int prev_vactive0_flag, const int *current_vactive0_flag)
{
	int count = 0;

	HISI_ERR_CHECK_RETURN((current_vactive0_flag == NULL), false, "current_vactive0_flag is NULL\n");

	/* check vactive start/end flag, if 0, wait until changed to 1,
	 * the maximum waiting time is 200ms
	 */
	do {
		if (*current_vactive0_flag != prev_vactive0_flag)
			return true;

		HISI_FB_DEBUG("count=%d!\n", count);
		SRE_SwMsleep(1);
		count++;
	} while (count < TIME_OUT);

	return false;
}

int hisi_vactive0_start_config(struct hisifb_data_type *hisifd)
{
	int prev_vactive0_start;
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");

	prev_vactive0_start = hisifd->vactive_start_flag;
	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.single_frame_update, hisifd);
	HISI_FB_DEBUG("prev_vactive0_start = %d  enter!\n", prev_vactive0_start);

	if (dss_is_vactive0_action_done(prev_vactive0_start, &hisifd->vactive_start_flag) == true) {
		HISI_FB_DEBUG("vactive_start_flag = %d exit!\n", hisifd->vactive_start_flag);
		return 0;
	}
	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.vactive0_dump, hisifd);
	return -1;
}

int hisi_frame_end_config(struct hisifb_data_type *hisifd)
{
	int prev_frame_end;
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");

	prev_frame_end = hisifd->frame_end_flag;
	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.single_frame_update, hisifd);
	HISI_FB_DEBUG("prev_frame_end = %d enter!\n", prev_frame_end);

	if (dss_is_vactive0_action_done(prev_frame_end, &hisifd->frame_end_flag) == true) {
		HISI_FB_DEBUG("frame_end_flag = %d exit!\n", hisifd->frame_end_flag);
		return 0;
	}
	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.vactive0_dump, hisifd);
	return -1;
}


int do_pan_display_config(struct hisifb_data_type *hisifd, dss_layer_t *layer)
{
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_RETURN(((hisifd == NULL) || (layer == NULL)), -1, "input parameter is NULL\n");
	HISI_FB_INFO("enter!\n");

	if (hisifd->first_frame) {
		hisi_enter_secure_display(hisifd);
		HISI_CHECK_AND_CALL_FUNC(module_cb->mix_cb.dump_secure_display_reg,
			hisifd, DUMP_REG_ALWAYS, DUMP_REG_NOSHADOW);
		hisifd->first_frame = 0;
	}
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.mctl_mutex_lock, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->dma_cb.display_rdma_config, hisifd, layer);
	HISI_CHECK_AND_CALL_FUNC(module_cb->dfc_cb.display_rdfc_config, hisifd, layer);
	HISI_CHECK_AND_CALL_FUNC(module_cb->ovl_cb.ovl_layer_config, hisifd, layer);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.mctl_sec_flush_en, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.mctl_mutex_unlock, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.single_frame_update, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mix_cb.dump_secure_display_reg, hisifd, DUMP_REG_ALWAYS, DUMP_REG_NOSHADOW);

	HISI_FB_INFO("exit!\n");
	return 0;
}

static int hisi_fb_underflow_clear(struct hisifb_data_type *hisifd)
{
	int ret;
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");
	HISI_FB_INFO("+!\n");

	if (tee_mutex_lock(hisifd->disp_lock)) {
		HISI_FB_INFO("wait lock failed!\n");
		return -1;
	}

	if ((hisifd->panel_power_on != NULL) && hisifd->panel_power_on(hisifd)) {
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}

	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.mcu_interrupt_mask, hisifd);
	ret = (int)SRE_HwiDisable(hisifd->dpe_sec_irq);
	if (ret != 0) {
		HISI_FB_ERR("failed to disable fb irq!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}
	hisi_exit_secure_display(hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->mctl_cb.mctl_clear, hisifd);
	hisifd->alpha_enable = 0;
	hisifd->first_frame = 1;
	ret = (int)SRE_HwiEnable(hisifd->dpe_sec_irq);
	if (ret != 0) {
		HISI_FB_ERR("failed to enable fb irq!\n");
		tee_mutex_unlock(hisifd->disp_lock);
		return -1;
	}
	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.mcu_interrupt_unmask, hisifd);
	HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.clear_irq, hisifd);

	if (hisifd->pan_display_sec != NULL) {
		ret = hisifd->pan_display_sec(hisifd, &(hisifd->layer));
	}
	tee_mutex_unlock(hisifd->disp_lock);
	HISI_FB_INFO("-!\n");
	return ret;
}

int hisi_fb_irq_handle(uint32_t ptr)
{
	uint32_t isr_s2;
	int ret;
	struct hisifb_data_type *hisifd = NULL;
	static int count; /* initialize as 0 */
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	hisifd = (struct hisifb_data_type *)(uintptr_t)ptr;

	if (module_cb->ldi_cb.clear_irq == NULL)
		return -1;

	ret = module_cb->ldi_cb.clear_irq(hisifd);

	/* vactive_start irq */
	isr_s2 = (uint32_t)ret;
	if (isr_s2 & BIT_VACTIVE0_START) {
		HISI_FB_DEBUG("BIT_VACTIVE0_START hisifd->vactive_start_flag =%d\n", hisifd->vactive_start_flag);
		hisifd->vactive_start_flag++;
	}

	if (isr_s2 & BIT_FRM_END) {
		HISI_FB_DEBUG("BIT_FRM_END hisifd->frame_end_flag = %d\n", hisifd->frame_end_flag);
		hisifd->frame_end_flag++;
	}

	if (isr_s2 & BIT_LDI_UNFLOW) {
		if (count == 0)
			hisi_fb_underflow_clear(hisifd);

		count++;
		if (count == MAX_UNDERFLOW_COUNT) {
			HISI_FB_ERR("ldi underflow!\n");
			count = 0;
		}
		/* underflow should only dump once */
		HISI_CHECK_AND_CALL_FUNC(module_cb->mix_cb.dump_secure_display_reg, hisifd, DUMP_REG_ONCE, DUMP_REG_NOSHADOW);
	}

	return 0;
}

int hisi_secure_display_config(struct hisifb_data_type *hisifd, int sec_value)
{
	uint32_t ret = 0;
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	HISI_ERR_CHECK_RETURN((hisifd == NULL), -1, "hisifd is NULL\n");
	HISI_FB_INFO("sec_value = %d! enter\n", sec_value);

	if (sec_value) {
		HISI_CHECK_AND_CALL_FUNC(module_cb->dma_cb.check_rch_idle, hisifd);
		hisifd->first_frame = 1;
		hisifd->alpha_enable = 0;
		/* set initial flag */
		hisifd->secure_status = SEC_PAY_ENABLE;
		HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.mcu_interrupt_unmask, hisifd);
		/* register dss secure irq */
#if defined(CONFIG_DSS_TYPE_BALTIMORE)
		if (is_dsi1_te1(hisifd)) {
			hisifd->dpe_sec_irq = HISI_FB_SEC_DSI1_IRQ;
			HISI_FB_INFO("change to mcu dsi1 irq");
		} else {
			hisifd->dpe_sec_irq = HISI_FB_SEC_IRQ;
		}
#endif
		if (SRE_HwiCreate((HWI_HANDLE_T)hisifd->dpe_sec_irq, (HWI_PRIOR_T)0, (HWI_MODE_T)0,
			(HWI_PROC_FUNC)hisi_fb_irq_handle, (uint32_t)(uintptr_t)hisifd)) {
			HISI_FB_ERR("failed to create fb irq!\n");
			return -1;
		}
		if (SRE_HwiEnable(hisifd->dpe_sec_irq) != SRE_OK) {
			HISI_FB_ERR("failed to SRE_HwiEnable fb irq!\n");
			return -1;
		}
	} else {
		hisi_vactive0_start_config(hisifd);
		hisi_secure_config_clear(hisifd);
		HISI_CHECK_AND_CALL_FUNC(module_cb->mix_cb.dump_secure_display_reg, hisifd, DUMP_REG_ALWAYS, DUMP_REG_SHADOW);
		hisi_exit_secure_display(hisifd);
		/* deinit initial flag */
		hisifd->secure_status = SEC_PAY_DISABLE;
		HISI_CHECK_AND_CALL_FUNC(module_cb->ldi_cb.mcu_interrupt_mask, hisifd);
		ret = SRE_HwiDisable(hisifd->dpe_sec_irq);
		if (ret != 0) {
			HISI_FB_ERR("failed to disable fb irq!\n");
			return -1;
		}
		ret = SRE_HwiDelete(hisifd->dpe_sec_irq);
		if (ret != 0) {
			HISI_FB_ERR("failed to delete fb irq, return!\n");
			return -1;
		}
	}
	HISI_FB_INFO("sec_value = %d! exit\n", sec_value);
	return 0;
}


