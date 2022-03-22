/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: TUI secure display different types registers mixed configuration callback functions
 * Author: Hisilicon DSS
 * Create: 2019-06-19
 */

#include "hisi_dss_mix.h"
#include "hisi_dss_module_registe.h"

/*
 * is_once: true-dump only once, false-dump each time
 * need_shadow: true-dump both shadow and work register, false-only dump work register
 */
static void dss_dump_secure_display_reg(struct hisifb_data_type *hisifd, bool is_once, bool need_shadow)
{
	struct hisi_dss_module_cb *module_cb = dss_get_module_cb();

	if (hisifd->disp_debug_dump == 1) {
		if (need_shadow) {
			HISI_FB_INFO("dss_dump_reg_info shadow regs:\n");
			hisifd->set_reg(hisifd->rdma_base + CH_RD_SHADOW, 0x1, 1, 0);
			hisifd->set_reg(hisifd->ovl_base + OV8_RD_SHADOW_SEL, 0x1, 1, 0);

			HISI_CHECK_AND_CALL_FUNC(module_cb->mix_cb.dump_reg_info, hisifd);

			hisifd->set_reg(hisifd->rdma_base + CH_RD_SHADOW, 0x0, 1, 0);
			hisifd->set_reg(hisifd->ovl_base + OV8_RD_SHADOW_SEL, 0x0, 1, 0);
		}
		HISI_FB_INFO("dss_dump_reg_info work regs:\n");
		HISI_CHECK_AND_CALL_FUNC(module_cb->mix_cb.dump_reg_info, hisifd);
		if (is_once)
			hisifd->disp_debug_dump = 0;
	}
}

static void dss_dump_reg_info(struct hisifb_data_type *hisifd)
{
	dss_dump_single_reg("MCTL_SYS", hisifd->mctrl_sys_base, 0x0328);
	dss_dump_single_reg("MCTRL_CTL0", (hisifd->dss_base + DSS_MCTRL_CTL0_OFFSET), 0x00E4);
	dss_dump_single_reg("MCTRL_CTL4", (hisifd->dss_base + DSS_MCTRL_CTL4_OFFSET), 0x00E4);
	dss_dump_single_reg("RCH_DMA", hisifd->rdma_base, 0x012C);
	dss_dump_single_reg("OV8", hisifd->ovl_base, 0x358);
}


void dss_registe_base_mix_cb(struct dss_mix_cb *mix_cb)
{
	HISI_ERR_CHECK_NO_RETVAL((mix_cb == NULL), "mix_cb is NULL\n");

	mix_cb->dump_secure_display_reg = dss_dump_secure_display_reg;
	mix_cb->dump_reg_info = dss_dump_reg_info;

	dss_registe_platform_mix_cb(mix_cb);
}



