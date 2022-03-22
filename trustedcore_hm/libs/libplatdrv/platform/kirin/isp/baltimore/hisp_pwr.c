/*
* Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
* Description: isp interface
* Author: w00422787
* Create: 2019-9-26
*/

#include "hisp.h"
#include <mem_mode.h>
#include <soc_media1_crg_interface.h>
#include "soc_acpu_baseaddr_interface.h"
#include "soc_isp_nmanager_isp_subctrl_interface.h"
#include "soc_crgperiph_interface.h"
#include "soc_pctrl_interface.h"
#include "soc_sctrl_interface.h"
#include "soc_csi_wrapper_interface.h"
#include "soc_pmctrl_interface.h"
#include "soc_actrl_interface.h"
#include "soc_isp_nmanager_sec_adpt_interface.h"
#include "soc_smmuv3_tbu_interface.h"
#include "hisi_boot.h"
#include "hisp_power.h"
#include "sec_smmu_com.h"
#include "secmem.h"
#include <stdlib.h>
#include "ccmgr_ops_ext.h"

#define ISP_DELAY_TIME (100)

#define SECISP_BOOTWARE_PROT    (IOMMU_READ | IOMMU_EXEC | IOMMU_SEC)
#define MAX_MALLOC_SIZE         0x00080000
#define SECISP_MEM_INFOLENGTH       (1)
#define SECISP_MEM_PAGE_ALIGN       (0x1000)

#define ISP_CORE_SEC_CFG_CMDLIST_SEC_ATTR_BIT       2
#define ISP_CORE_SEC_CFG_JPEGENC_SEC_ATTR_BIT       1
#define ISP_CORE_SEC_CFG_ISP_SEC_ATTR_BIT           0

#define ISP_SUBSYS_SEC_CFG_DPM_SEC_ATTR_BIT         5
#define ISP_SUBSYS_SEC_CFG_TCMDMA_SEC_ATTR_BIT      4
#define ISP_SUBSYS_SEC_CFG_SUB_CTRL_SEC_ATTR_BIT    3
#define ISP_SUBSYS_SEC_CFG_IPC_SEC_ATTR_BIT         2
#define ISP_SUBSYS_SEC_CFG_TIMER_SEC_ATTR_BIT       1
#define ISP_SUBSYS_SEC_CFG_WATCHDOG_SEC_ATTR_BIT    0

#ifndef ISP_CHIP_ES
enum {
	BOOTWARE_UNMAP = 0,
	BOOTWARE_MAP,
};

static int g_bootware_map_flag;
#endif

static UINT32 is_media1_reset(void)
{
	UINT32 reg;

	reg = hisi_readl(SOC_CRGPERIPH_PERRSTSTAT5_ADDR(SOC_ACPU_PERI_CRG_BASE_ADDR))
		  & BIT(SOC_CRGPERIPH_PERRSTSTAT5_ip_rst_media_START);
	return (reg == 0) ? SECISP_SUCCESS : SECISP_FAIL;
}

static UINT32 is_vivobus_idle(void)
{
	UINT32 reg;

	reg = hisi_readl(SOC_PMCTRL_NOC_POWER_IDLE_2_ADDR(SOC_ACPU_PMC_BASE_ADDR))
		  & BIT(SOC_PMCTRL_NOC_POWER_IDLE_2_syspmc_pwrd_ack_vivo_START);
	return (reg == 0) ? SECISP_SUCCESS : SECISP_FAIL;
}

static UINT32 is_isp_reset(void)
{
	UINT32 reg;

	reg = hisi_readl(SOC_MEDIA1_CRG_PERRSTSTAT_ISP_SEC_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR))
		  & BIT(SOC_MEDIA1_CRG_PERRSTSTAT_ISP_SEC_ip_rst_isp_START);
	return (reg == 0) ? SECISP_SUCCESS : SECISP_FAIL;
}

static UINT32 is_isp_idle(void)
{
	UINT32 reg;

	reg = hisi_readl(SOC_PMCTRL_NOC_POWER_IDLE_2_ADDR(SOC_ACPU_PMC_BASE_ADDR))
		  & BIT(SOC_PMCTRL_NOC_POWER_IDLE_2_syspmc_pwrd_ack_isp_START);
	return (reg == 0) ? SECISP_SUCCESS : SECISP_FAIL;
}

static UINT32 is_csiwrapper_reset(void)
{
	UINT32 reg;

	reg = hisi_readl(SOC_MEDIA1_CRG_PERRSTSTAT_ISP_SEC_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR))
		  & BIT(SOC_MEDIA1_CRG_PERRSTSTAT_ISP_SEC_ip_rst_csi_wrapper_cfg_START);
	return (reg == 0) ? SECISP_SUCCESS : SECISP_FAIL;
}

static UINT32 is_csi_reset(void)
{
	UINT32 reg;

	reg = hisi_readl(SOC_SCTRL_SCPERRSTSTAT1_ADDR(SOC_ACPU_SCTRL_BASE_ADDR))
		  & BIT(SOC_SCTRL_SCPERRSTSTAT1_ip_rst_csi_cfg_START);
	return (reg == 0) ? SECISP_SUCCESS : SECISP_FAIL;
}

static void set_ispcputocfg(void)
{
	UINT32 reg;

	reg = hisi_readl(SOC_MEDIA1_CRG_PERRSTSTAT_ISP_SEC_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR))
		  & BIT(SOC_MEDIA1_CRG_PERRSTSTAT_ISP_SEC_ip_rst_isp_cputocfg_START);
	if (reg == BIT(SOC_MEDIA1_CRG_PERRSTSTAT_ISP_SEC_ip_rst_isp_cputocfg_START))
		hisi_writel(BIT(SOC_MEDIA1_CRG_PERRSTDIS_ISP_SEC_ip_rst_isp_cputocfg_START),
			SOC_MEDIA1_CRG_PERRSTDIS_ISP_SEC_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
}

static UINT32 set_powerup_isprt(void)
{
	UINT32 value = 0;
	UINT32 timeout = 400;

	ISP_DEBUG("isp rt module mtcmos on");
	hisi_writel(BIT(SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_isp_rtvid_mtcmos_en_START) |
		BIT(SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_isp_rtvid_mtcmos_en_START +
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_mtcmos_en_group1_peri_msk_START),
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));
	hisi_udelay(ISP_DELAY_TIME);
	ISP_DEBUG("isp rt module sd off");
	hisi_writel(BIT(SOC_PCTRL_PERI_CTRL102_pctrl_mem_ctrl_sd_isp_fe_START +
		SOC_PCTRL_PERI_CTRL102_peri_ctrl102_msk_START),
		SOC_PCTRL_PERI_CTRL102_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	hisi_udelay(1);
	ISP_DEBUG("isp rt module clk enable");
	hisi_writel(BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc_START +
		SOC_MEDIA1_CRG_CLKDIV9_bitmasken_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc4_START +
		SOC_MEDIA1_CRG_CLKDIV9_bitmasken_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc4_START),
		SOC_MEDIA1_CRG_CLKDIV9_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	hisi_writel(BIT(SOC_MEDIA1_CRG_PEREN0_gt_clk_ispfunc_START) |
		BIT(SOC_MEDIA1_CRG_PEREN0_gt_clk_ispfunc4_START),
		SOC_MEDIA1_CRG_PEREN0_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	hisi_udelay(1);
	ISP_DEBUG("isp rt module clk disable");
	hisi_writel(BIT(CGR_RT), ISPSS_MODULE_CGR_HARDEN_CLEAR);
	ISP_DEBUG("isp rt module iso disable");
	hisi_writel(BIT(SOC_ACTRL_ISO_EN_GROUP1_PERI_isp_rtvid_iso_en_START +
		SOC_ACTRL_ISO_EN_GROUP1_PERI_iso_en_group1_peri_msk_START),
		SOC_ACTRL_ISO_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));
	ISP_DEBUG("isp rt memory repair");

	do {
		value = hisi_readl(SOC_ACTRL_BISR_REPAIR_ACK_STATUS0_ADDR(SOC_ACPU_ACTRL_BASE_ADDR))
			& ISP_SUBSYS1_REPAIR_ACK_STATUS0;
		hisi_udelay(1);
		timeout--;

		if (timeout == 0) {
			ISP_ERR("isp rt memory repair value =0x%x", value);
			return SECISP_TIMEOUT;
		}
	} while (value != ISP_SUBSYS1_REPAIR_ACK_STATUS0);

	ISP_DEBUG("isp rt module unrst");
	hisi_writel(BIT(CGR_RT), ISPSS_MODULE_RESET_HARDEN_CLEAR);
	ISP_DEBUG("isp rt module clk enable");
	hisi_writel(BIT(CGR_RT), ISPSS_MODULE_CGR_HARDEN_SET);

	return SECISP_SUCCESS;
}

static UINT32 set_powerdown_isprt(void)
{
	ISP_DEBUG("isp rt module sd off");
	hisi_writel(BIT(SOC_PCTRL_PERI_CTRL102_pctrl_mem_ctrl_sd_isp_fe_START +
		SOC_PCTRL_PERI_CTRL102_peri_ctrl102_msk_START) |
		BIT(SOC_PCTRL_PERI_CTRL102_pctrl_mem_ctrl_sd_isp_fe_START),
		SOC_PCTRL_PERI_CTRL102_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	ISP_DEBUG("isp rt module rst");
	hisi_writel(BIT(CGR_RT), ISPSS_MODULE_RESET_HARDEN_SET);
	ISP_DEBUG("isp rt module clk disable");
	hisi_writel(BIT(SOC_MEDIA1_CRG_PERDIS0_gt_clk_ispfunc4_START),
		SOC_MEDIA1_CRG_PERDIS0_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	hisi_writel(BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc4_START +
		SOC_MEDIA1_CRG_CLKDIV9_bitmasken_START),
		SOC_MEDIA1_CRG_CLKDIV9_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	ISP_DEBUG("isp rt module iso");
	hisi_writel(BIT(SOC_ACTRL_ISO_EN_GROUP1_PERI_isp_rtvid_iso_en_START +
		SOC_ACTRL_ISO_EN_GROUP1_PERI_iso_en_group1_peri_msk_START) |
		BIT(SOC_ACTRL_ISO_EN_GROUP1_PERI_isp_rtvid_iso_en_START),
		SOC_ACTRL_ISO_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));
	ISP_DEBUG("isp rt module mtcmos off");
	hisi_writel(BIT(SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_isp_rtvid_mtcmos_en_START +
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_mtcmos_en_group1_peri_msk_START),
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));

	return SECISP_SUCCESS;
}

static UINT32 set_powerup_ispcap(void)
{
	UINT32 value = 0;
	UINT32 timeout = 400;

	ISP_DEBUG("isp cap module mtcmos on");
	hisi_writel(BIT(SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_isp_cap_mtcmos_en_START) |
		BIT(SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_isp_cap_mtcmos_en_START +
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_mtcmos_en_group1_peri_msk_START),
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));
	hisi_udelay(ISP_DELAY_TIME);
	ISP_DEBUG("isp cap module sd off");
	hisi_writel(BIT(SOC_PCTRL_PERI_CTRL102_pctrl_mem_ctrl_sd_isp_bpecap_START +
		SOC_PCTRL_PERI_CTRL102_peri_ctrl102_msk_START),
		SOC_PCTRL_PERI_CTRL102_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	hisi_udelay(1);
	ISP_DEBUG("isp cap module clk enable");
	hisi_writel(BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc_START +
		SOC_MEDIA1_CRG_CLKDIV9_bitmasken_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc2_START +
		SOC_MEDIA1_CRG_CLKDIV9_bitmasken_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc2_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc3_START +
		SOC_MEDIA1_CRG_CLKDIV9_bitmasken_START) |
		BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc3_START),
		SOC_MEDIA1_CRG_CLKDIV9_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	hisi_writel(BIT(SOC_MEDIA1_CRG_PEREN0_gt_clk_ispfunc_START) |
		BIT(SOC_MEDIA1_CRG_PEREN0_gt_clk_ispfunc2_START) |
		BIT(SOC_MEDIA1_CRG_PEREN0_gt_clk_ispfunc3_START),
		SOC_MEDIA1_CRG_PEREN0_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	hisi_udelay(1);
	ISP_DEBUG("isp cap module clk disable");
	hisi_writel(BIT(CGR_CAP), ISPSS_MODULE_CGR_HARDEN_CLEAR);
	ISP_DEBUG("isp cap module iso disable");
	hisi_writel(BIT(SOC_ACTRL_ISO_EN_GROUP1_PERI_isp_cap_iso_en_START +
		SOC_ACTRL_ISO_EN_GROUP1_PERI_iso_en_group1_peri_msk_START),
		SOC_ACTRL_ISO_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));

	do {
		value = hisi_readl(SOC_ACTRL_BISR_REPAIR_ACK_STATUS0_ADDR(SOC_ACPU_ACTRL_BASE_ADDR))
			& ISP_SUBSYS2_REPAIR_ACK_STATUS0;
		hisi_udelay(1);
		timeout--;

		if (timeout == 0) {
			ISP_ERR("isp cap memory repair value =0x%x", value);
			return SECISP_TIMEOUT;
		}
	} while (value != ISP_SUBSYS2_REPAIR_ACK_STATUS0);

	ISP_DEBUG("isp cap module unrst");
	hisi_writel(BIT(CGR_CAP) | BIT(CGR_SRT), ISPSS_MODULE_RESET_HARDEN_CLEAR);
	ISP_DEBUG("module clk enable");
	hisi_writel(BIT(CGR_CAP), ISPSS_MODULE_CGR_HARDEN_SET);

	return SECISP_SUCCESS;
}

static UINT32 set_powerdown_ispcap(void)
{
	ISP_DEBUG("isp cap module sd off");
	hisi_writel(BIT(SOC_PCTRL_PERI_CTRL102_pctrl_mem_ctrl_sd_isp_bpecap_START +
		SOC_PCTRL_PERI_CTRL102_peri_ctrl102_msk_START) |
		BIT(SOC_PCTRL_PERI_CTRL102_pctrl_mem_ctrl_sd_isp_bpecap_START),
		SOC_PCTRL_PERI_CTRL102_ADDR(SOC_ACPU_PCTRL_BASE_ADDR));
	ISP_DEBUG("isp cap module rst");
	hisi_writel(BIT(CGR_CAP), ISPSS_MODULE_RESET_HARDEN_SET);
	ISP_DEBUG("isp cap module clk disable");
	hisi_writel(BIT(SOC_MEDIA1_CRG_PERDIS0_gt_clk_ispfunc3_START),
		SOC_MEDIA1_CRG_PERDIS0_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	hisi_writel(BIT(SOC_MEDIA1_CRG_CLKDIV9_sc_gt_clk_ispfunc3_START +
		SOC_MEDIA1_CRG_CLKDIV9_bitmasken_START),
		SOC_MEDIA1_CRG_CLKDIV9_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	ISP_DEBUG("isp cap module iso");
	hisi_writel(BIT(SOC_ACTRL_ISO_EN_GROUP1_PERI_isp_cap_iso_en_START +
		SOC_ACTRL_ISO_EN_GROUP1_PERI_iso_en_group1_peri_msk_START) |
		BIT(SOC_ACTRL_ISO_EN_GROUP1_PERI_isp_cap_iso_en_START),
		SOC_ACTRL_ISO_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));
	ISP_DEBUG("isp cap module mtcmos off");
	hisi_writel(BIT(SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_isp_cap_mtcmos_en_START +
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_mtcmos_en_group1_peri_msk_START),
		SOC_ACTRL_MTCMOS_EN_GROUP1_PERI_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));

	return SECISP_SUCCESS;
}

static void set_ispsec(void)
{
	UINT32 value;

	set_ispcputocfg();
	value = hisi_readl(SOC_ISP_nManager_ISP_SUBCTRL_ISP_CORE_CTRL_S_ADDR(SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR)) &
		(~((BIT(ISP_CORE_SEC_CFG_CMDLIST_SEC_ATTR_BIT) | BIT(ISP_CORE_SEC_CFG_ISP_SEC_ATTR_BIT))));
	hisi_writel(value,
		SOC_ISP_nManager_ISP_SUBCTRL_ISP_CORE_CTRL_S_ADDR(SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR));
	value = hisi_readl(SOC_ISP_nManager_ISP_SUBCTRL_ISP_SUB_CTRL_S_ADDR(SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR)) &
		(~(BIT(ISP_SUBSYS_SEC_CFG_TCMDMA_SEC_ATTR_BIT) | BIT(ISP_SUBSYS_SEC_CFG_SUB_CTRL_SEC_ATTR_BIT) |
		BIT(ISP_SUBSYS_SEC_CFG_IPC_SEC_ATTR_BIT) | BIT(ISP_SUBSYS_SEC_CFG_TIMER_SEC_ATTR_BIT) |
		BIT(ISP_SUBSYS_SEC_CFG_WATCHDOG_SEC_ATTR_BIT)));
	hisi_writel(value,
		SOC_ISP_nManager_ISP_SUBCTRL_ISP_SUB_CTRL_S_ADDR(SOC_ACPU_ISP_SUB_CTRL_BASE_ADDR));
}

static UINT32 get_ispcore_clk_enable(void)
{
	unsigned int value = 0;

	value = hisi_readl(ISPSS_MODULE_CGR_TOP);
	if ((value & ISP_MODULE_CRG_MASK) != ISP_MODULE_CRG_MASK) {
		ISP_ERR("Miss ispcore module Func clk\n");
		return SECISP_FAIL;
	}

	return SECISP_SUCCESS;
}

static UINT32 smmuv3_reg_set_ackbit(UINT32 addr, UINT32 reqval, UINT32 ackval,
	UINT32 reqoffset, UINT32 ackoffset, UINT32 reqbit, UINT32 ackbit)
{
	UINT32 stat = 0;
	UINT32 reg;
	int timeout;
	UINT32 i;

	reg = hisi_readl(addr + reqoffset);
	if (reqval) {
		reg |= (1 << reqbit);
	} else {
		reg &= ~(1 << reqbit);
	}

	hisi_writel(reg, addr + reqoffset);
	timeout = SMMUV3_DELAY_TIMEOUT;

	do {
		stat = 0;
		stat = hisi_readl(addr + ackoffset);
		stat &= 1 << ackbit;
		timeout--;

		for (i = 0; i < SMMUV3_DELAY_TIME; i++) {}
	} while ((stat != (ackval << ackbit)) && (timeout >= 0));

	if (timeout < 0) {
		return SECISP_TIMEOUT;
	}

	return SECISP_SUCCESS;
}

static void set_ssid_valid(UINT32 sec_adpt_base)
{
	UINT32 i = 0;
	SOC_ISP_nManager_SEC_ADPT_swid_cfg_ns_UNION cfg_ns;
	SOC_ISP_nManager_SEC_ADPT_swid_cfg_s_UNION cfg_s;

	for (i = 0; i < SMMUV3_SSID_MAX; i++) {
		cfg_ns.value = hisi_readl(sec_adpt_base + i * SMMUV3_SID_OFFSET); // ssidv_ns
		cfg_ns.reg.ssidv_ns = 1;
		cfg_ns.reg.user_def_ns = SECSMMU_STREAMID_ISP;
		hisi_writel(cfg_ns.value, (sec_adpt_base + i * SMMUV3_SID_OFFSET));
		cfg_s.value = hisi_readl(sec_adpt_base + SMMUV3_TBU_REG_SWID_CFG_S + i * SMMUV3_SID_OFFSET); // ssidv_s
		cfg_s.reg.secsid_s = 1;
		cfg_s.reg.ssid_s = SECSMMU_SUBSTREAMID_ISP;
		cfg_s.reg.ssidv_s = 1;
		cfg_s.reg.user_def_s = SECSMMU_STREAMID_ISP;
		hisi_writel(cfg_s.value, (sec_adpt_base + SMMUV3_TBU_REG_SWID_CFG_S + i * SMMUV3_SID_OFFSET));
	}
}

static UINT32 smmuv3_tbu_init(UINT32 tbu_base)
{
	UINT32 offset;
	UINT32 ret;
	UINT32 addr;
	SOC_SMMUv3_TBU_SMMU_TBU_SCR_UNION scr;
	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION cr;
	SOC_SMMUv3_TBU_SMMU_TBU_CRACK_UNION crack;

	addr = tbu_base;
	/* Set tbu reg secure attribute */
	offset = SMMUV3_TBU_REG_SMMU_TBU_SCR_REG;
	scr.value = hisi_readl(addr + offset);
	scr.reg.ns_uarch = 0;
	scr.reg.tbu_bypass = 0;
	hisi_writel(scr.value, addr + offset);
	/* Request the TBU to establish a connection with the TCU */
	ret = smmuv3_reg_set_ackbit(addr, 1, 1, SMMUV3_TBU_REG_SMMU_TBU_CR_REG,
		SMMUV3_TBU_REG_SMMU_TBU_CRACK_REG, SMMUV3_TBU_REG_TBU_EN_REQ_OFFSET,
		SMMUV3_TBU_REG_TBU_EN_ACK_OFFSET);
	if (ret) {
		ISP_ERR("Failed: smmuv3_reg_set_ack_bit.");
		return SECISP_FAIL;
	}

	/* Determine whether the connection is established successfully */
	offset = SMMUV3_TBU_REG_SMMU_TBU_CRACK_REG;
	crack.value = hisi_readl(addr + offset);

	if (crack.reg.tbu_connected != 1) {
		ISP_ERR("Failed: tbu_connected = %d.", crack.reg.tbu_connected);
		return SECISP_FAIL;
	}

	/* determine tok_trans_gnt value */
	offset = SMMUV3_TBU_REG_SMMU_TBU_CR_REG;
	cr.value = hisi_readl(addr + offset);

	if (crack.reg.tok_trans_gnt < cr.reg.max_tok_trans) {
		ISP_ERR("Failed: tok_trans_gnt = %d.max_tok_trans",
			crack.reg.tok_trans_gnt, cr.reg.max_tok_trans);
		return SECISP_FAIL;
	}

	return SECISP_SUCCESS;
}

static UINT32 smmuv3_tbu_disconnect(UINT32 tbu_base)
{
	UINT32 offset = 0;
	UINT32 ret    = 0;
	UINT32 addr   = 0;

	addr = tbu_base;
	offset = SMMUV3_TBU_REG_SMMU_TBU_CRACK_REG;
	SOC_SMMUv3_TBU_SMMU_TBU_CRACK_UNION crack;
	crack.value = hisi_readl(addr + offset);

	if (crack.reg.tbu_connected == 0) {
		ISP_ERR("tbu is disconnected\n");
		return SECISP_SUCCESS;
	}

	/*Request the TBU to disconnection with the TCU*/
	ret = smmuv3_reg_set_ackbit(addr, 0, 1, SMMUV3_TBU_REG_SMMU_TBU_CR_REG, \
					SMMUV3_TBU_REG_SMMU_TBU_CRACK_REG, \
					SMMUV3_TBU_REG_TBU_EN_REQ_OFFSET, \
					SMMUV3_TBU_REG_TBU_EN_ACK_OFFSET);

	if (ret) {
		ISP_ERR("Failed: smmuv3_reg_set_ack_bit");
		return SECISP_FAIL;
	}

	/*Determine whether the disconnection is established successfully*/
	crack.value = hisi_readl(addr + offset);

	if (crack.reg.tbu_connected != 0) {
		ISP_ERR("tbu_cr = %x    tbu_crack = %x\n",
			hisi_readl(addr), hisi_readl(addr + offset));
		ISP_ERR("Failed: tbu_connected = %x\n", crack.reg.tbu_connected);
		return SECISP_FAIL;
	}

	return SECISP_SUCCESS;
}

static int arc_smmuv3_enable(void)
{
	set_ssid_valid(ISP_ARC_SEC_ADPT);

	if (smmuv3_tbu_init(ISP_ARC_SMMU_TBU)) {
		ISP_ERR("smmuv3_tbu_init");
		return -1;
	}

	return 0;
}

static int arc_smmu_v3_disable(void)
{
	if (smmuv3_tbu_disconnect(ISP_ARC_SMMU_TBU)) {
		ISP_ERR("smmuv3_tbu_disconnect ISPCPU\n");
		return -1;
	}

	if (get_ispcore_clk_enable()) {
		ISP_ERR("ispcore_clk_enable is disable\n");
		return 0;
	}

	if (smmuv3_tbu_disconnect(ISP_SRT_SMMU_TBU)) {
		ISP_ERR("smmuv3_tbu_disconnect SRT\n");
		return -1;
	}

	if (smmuv3_tbu_disconnect(ISP_RT_SMMU_TBU)) {
		ISP_ERR("smmuv3_tbu_disconnect RT\n");
		return -1;
	}

	if (smmuv3_tbu_disconnect(ISP_RYYB_SMMU_TBU)) {
		ISP_ERR("smmuv3_tbu_disconnect RYYB\n");
		return -1;
	}

	return 0;
}

#ifndef ISP_CHIP_ES
static uint32_t hisp_alloc_bw_sglist(struct sglist **sgl, uint32_t size)
{
	struct sglist *sglist = NULL;

	if (size > MAX_MALLOC_SIZE) {
		ISP_ERR("size is wrong! 0x%x", size);
		return SECISP_BAD_PARA;
	}

	sglist = (struct sglist *)malloc(sizeof(struct sglist) + sizeof(TEE_PAGEINFO));
	if (sglist == NULL) {
		ISP_ERR("sglist is NULL!", size);
		return SECISP_BAD_PARA;
	}

	sglist->sglistSize = sizeof(struct sglist) + sizeof(TEE_PAGEINFO);
	sglist->ion_size   = size;
	sglist->infoLength = SECISP_MEM_INFOLENGTH;
	sglist->info[0].phys_addr = SEC_ISP_IMG_TEXT_BASE_ADDR;
	sglist->info[0].npages    = size / SECISP_MEM_PAGE_ALIGN;
	*sgl = sglist;

	return SECISP_SUCCESS;
}

static uint32_t hisp_bw_mem_map(struct smmu_domain *domain)
{
	struct sglist *sgl = NULL;
	uint32_t ret;
	int result;

	ISP_DEBUG("iommu map for bw secisp sec mem");
	if (g_bootware_map_flag == BOOTWARE_MAP)
		return SECISP_SUCCESS;

	if (domain == NULL) {
		ISP_ERR("fail, domain is NULL");
		return SECISP_BAD_PARA;
	}

	ret = hisp_alloc_bw_sglist(&sgl, SECISP_BOOTWARE_SIZE);
	if (ret != 0) {
		ISP_ERR("fail, hisp_alloc_bw_sglist. ret.%u", ret);
		return ret;
	}

	result = siommu_map(domain, sgl, 0, SECISP_BOOTWARE_SIZE, SECISP_BOOTWARE_PROT, non_secure);
	if (result < 0) {
		ISP_ERR("fail, siommu_map. ret.%u", result);
		free(sgl);
		return SECISP_INVAILD_ADDR_MAP;
	}

	g_bootware_map_flag = BOOTWARE_MAP;
	free(sgl);
	return SECISP_SUCCESS;
}

static uint32_t hisp_bw_mem_unmap(struct smmu_domain *domain)
{
	struct sglist *sgl = NULL;
	uint32_t ret;
	int result;

	ISP_DEBUG("iommu map for bw secisp sec mem");
	if (g_bootware_map_flag == BOOTWARE_UNMAP)
		return SECISP_SUCCESS;

	if (domain == NULL) {
		ISP_ERR("fail, domain is NULL");
		return SECISP_BAD_PARA;
	}

	ret = hisp_alloc_bw_sglist(&sgl, SECISP_BOOTWARE_SIZE);
	if (ret != 0) {
		ISP_ERR("fail, hisp_alloc_bw_sglist. ret.%u", ret);
		return ret;
	}

	result = siommu_unmap(domain, sgl, 0, SECISP_BOOTWARE_SIZE, non_secure);
	if (result < 0) {
		ISP_ERR("fail, siommu_map. ret.%u", result);
		free(sgl);
		return SECISP_INVAILD_ADDR_MAP;
	}

	g_bootware_map_flag = BOOTWARE_UNMAP;
	free(sgl);
	return SECISP_SUCCESS;
}

static void hisi_isp_cs_disreset(void)
{
	UINT32 value;

	SOC_MEDIA1_CRG_ISPCPU_CLKEN_UNION media_crg_ispcpu_clken;
	SOC_MEDIA1_CRG_ISPCPU_RSTEN_UNION media_crg_ispcpu_rsten;
	SOC_MEDIA1_CRG_PERRSTEN_ISP_SEC_UNION media_crg_isp_sec;
	SOC_MEDIA1_CRG_PERRSTDIS0_UNION   media_crg_perrstdiso;

	ISP_DEBUG("+");
	hisi_writel(MEDIA_ISPCPU_CTRL0_SEC, MEDIA1_ISPCPU_CTRL0_SEC);
	hisi_writel(ISP_SUBCTRL_CSSYS_DBGEN | ISP_SUBCTRL_CSSYS_NIDEN,ISP_ARC_CTRL_8);
	value = hisi_readl(ISP_ARC_CTRL_10);
	value &= (~ISP_SUBCTRL_CFGNMFI);
	value |= ISP_SUBCTRL_NCPUHALT;
	hisi_writel(value, ISP_ARC_CTRL_10);
	hisi_writel(ISP_SUBCTRL_DBG_SPRAM_MEM_CTRL, ISP_ARC_CTRL_12);
	/* close reamp */
	value = hisi_readl(ISP_ARC_CTRL_0);
	value &= (~ISP_ARC_REMAP_ENABLE);
	hisi_writel(value, ISP_ARC_CTRL_0);
	media_crg_ispcpu_clken.reg.ccpu_pd_clk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_core_clk_en  = 0x3;
	media_crg_ispcpu_clken.reg.ccpu_dbg_clk_en   = 0x3;
	media_crg_ispcpu_clken.reg.ccpu_etm_clk_en   = 0x3;
	media_crg_ispcpu_clken.reg.ccpu_ct_clk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_atbclk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_dbgclk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_m0clk_divnum = 0x3;
	media_crg_ispcpu_clken.reg.bitmasken         = 0x7FF;
	hisi_writel(media_crg_ispcpu_clken.value, MEDIA1_ISP_CPU_CLKEN);
	media_crg_ispcpu_rsten.reg.ccpu_core_srst_req_n   = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_scu_srst_req_n    = 0x1;
	media_crg_ispcpu_rsten.reg.ccpu_ct_srst_req_n     = 0x1;
	media_crg_ispcpu_rsten.reg.ccpu_wdt_srst_req_n    = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_dbg_srst_req_n    = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_etm_srst_req_n    = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_periph_srst_req_n = 0x1;
	media_crg_ispcpu_rsten.reg.cs_ccpu_dbg_srst_req_n = 0x1;
	media_crg_ispcpu_rsten.reg.ccpu_pd_srst_req_n     = 0x1;
	hisi_writel(media_crg_ispcpu_rsten.value, MEDIA1_ISP_CPU_RSTEN);
	media_crg_isp_sec.reg.ip_rst_isp_cpu = 0x1;
	hisi_writel(media_crg_isp_sec.value, MEDIA1_PERRSTDIS_ISP_SEC);
	media_crg_perrstdiso.reg.ip_rst_trace = 0x1;
	hisi_writel(media_crg_perrstdiso.value, MEDIA1_PERRSTDIS0);
	ISP_DEBUG("-");
}
#else
static void hisi_isp_es_disreset(void)
{
	UINT32 value;
	UINT32 timeout  = 400;
	SOC_MEDIA1_CRG_ISPCPU_CTRL0_SEC_UNION media_crg_ispcpu_ctrl0_s;

	ISP_DEBUG("+");
	hisi_writel(0x00001000, ISP_ARC_SUB_CTRL10); /* arc1 num : 1 */
	/* close reamp */
	value = hisi_readl(ISP_ARC_CTRL_0);
	value &= (~ISP_ARC_REMAP_ENABLE);
	hisi_writel(value, ISP_ARC_CTRL_0);
	/* start addr cfg */
	value = TEXT_BASE >> ISP_CPU_INTVBASE_IN;
	hisi_writel(value, ISP_ARC_CTRL_8);
	hisi_writel(value, ISP_ARC_CTRL_9);
	hisi_udelay(1);
	hisi_writel(0x00000010, MEDIA1_PERRSTDIS_ISP_SEC);
	/* start isp cpu */
	media_crg_ispcpu_ctrl0_s.value = hisi_readl(MEDIA1_ISPCPU_CTRL0_SEC);
	media_crg_ispcpu_ctrl0_s.reg.c1_arc_run_req = 1;
	media_crg_ispcpu_ctrl0_s.reg.c0_arc_run_req = 1;
	media_crg_ispcpu_ctrl0_s.reg.isp_arc_mem_ctrl_s = ISP_CPU_ARC_MEM_CTRLS;
	hisi_writel(media_crg_ispcpu_ctrl0_s.value, MEDIA1_ISPCPU_CTRL0_SEC);

	do {
		value = hisi_readl(MEDIA1_ISP_CPU_STATE0);
		hisi_udelay(1);
		timeout--;

		if (timeout == 0) {
			ISP_ERR("<ISP CPU State value =0x%x>", value);
			return;
		}
	} while ((value & ISP_CPU_ARC_RUN_ACK) != ISP_CPU_ARC_RUN_ACK);

	media_crg_ispcpu_ctrl0_s.value = hisi_readl(MEDIA1_ISPCPU_CTRL0_SEC);
	media_crg_ispcpu_ctrl0_s.reg.c1_arc_run_req = 0;
	media_crg_ispcpu_ctrl0_s.reg.c0_arc_run_req = 0;
	hisi_writel(media_crg_ispcpu_ctrl0_s.value, MEDIA1_ISPCPU_CTRL0_SEC);
	hisi_writel(0x00000800, MEDIA1_PERRSTDIS0);
	ISP_DEBUG("-");
}
#endif

static UINT32 set_isp_disreset(struct smmu_domain *domain)
{
	if (sec_smmu_poweron(SMMU_MEDIA1)) {
		ISP_ERR("Failed: sec_smmu_poweron");
		return SECISP_FAIL;
	}

	if (sec_smmu_bind(SMMU_MEDIA1, SECSMMU_STREAMID_ISP, SECSMMU_SUBSTREAMID_ISP, 0)) {
		ISP_ERR("Failed: sec_smmu_bind");
		goto err_smmu_bind;
	}

	if (arc_smmuv3_enable() < 0) {
		ISP_ERR("Failed: arc_smmuv3_enable");
		goto err_smmu_enable;
	}

#ifndef ISP_CHIP_ES
	if (hisp_bw_mem_map(domain) != 0) {
		ISP_ERR("Failed: hisp_bw_mem_map");
		goto err_mem_map;
	}

	hisi_isp_cs_disreset();
#else
	(void)domain;
	hisi_isp_es_disreset();
#endif
	return SECISP_SUCCESS;

err_mem_map:
	if (arc_smmu_v3_disable() < 0) {
		ISP_ERR("Failed: arc_smmu_v3_disable");
		return SECISP_FAIL;
	}
err_smmu_enable:
	if (sec_smmu_unbind(SMMU_MEDIA1, SECSMMU_STREAMID_ISP, SECSMMU_SUBSTREAMID_ISP)) {
		ISP_ERR("Failed: sec_smmu_unbind");
		return SECISP_FAIL;
	}
err_smmu_bind:
	if (sec_smmu_poweroff(SMMU_MEDIA1)) {
		ISP_ERR("Failed: sec_smmu_poweroff");
		return SECISP_FAIL;
	}
	return SECISP_FAIL;
}

static UINT32 set_isp_reset(struct smmu_domain *domain)
{
	hisi_writel(BIT(SOC_MEDIA1_CRG_PERRSTEN0_ip_rst_trace_START),
		SOC_MEDIA1_CRG_PERRSTEN0_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));
	hisi_writel(BIT(SOC_MEDIA1_CRG_PERRSTEN_ISP_SEC_ip_rst_isp_cpu_START),
		SOC_MEDIA1_CRG_PERRSTEN_ISP_SEC_ADDR(SOC_ACPU_MEDIA1_CRG_BASE_ADDR));

#ifndef ISP_CHIP_ES
	if (hisp_bw_mem_unmap(domain) != 0) {
		ISP_ERR("Failed: hisp_bw_mem_unmap");
		return SECISP_FAIL;
	}
#endif

	(void)domain;
	if (arc_smmu_v3_disable() < 0) {
		ISP_ERR("Failed: arc_smmu_v3_disable");
		return SECISP_FAIL;
	}

	if (sec_smmu_unbind(SMMU_MEDIA1, SECSMMU_STREAMID_ISP, SECSMMU_SUBSTREAMID_ISP)) {
		ISP_ERR("Failed: sec_smmu_unbind");
		return SECISP_FAIL;
	}

	if (sec_smmu_poweroff(SMMU_MEDIA1)) {
		ISP_ERR("Failed: sec_smmu_poweroff");
		return SECISP_FAIL;
	}
	return SECISP_SUCCESS;
}

static UINT32 set_csi_disreset(void)
{
	int ret;

	ret = is_csi_reset();
	if (ret < 0) {
		ISP_ERR("ip csi is reset, need to config");
		hisi_writel(BIT(SOC_SCTRL_SCPERRSTDIS1_ip_rst_csi_cfg_START),
			SOC_SCTRL_SCPERRSTDIS1_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));
		return SECISP_FAIL;
	}

	hisi_writel(BIT(SOC_SCTRL_SCPEREN4_gt_clk_csi_cfg_isp_START),
		SOC_SCTRL_SCPEREN4_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));
	return SECISP_SUCCESS;
}

static UINT32 set_csi_reset(void)
{
	int ret;

	ret = is_csi_reset();
	if (ret < 0) {
		ISP_ERR("ip csi is reset, need to config");
		hisi_writel(BIT(SOC_SCTRL_SCPERRSTDIS1_ip_rst_csi_cfg_START),
			SOC_SCTRL_SCPERRSTDIS1_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));
		return SECISP_FAIL;
	}

	hisi_writel(BIT(SOC_SCTRL_SCPERDIS4_gt_clk_csi_cfg_isp_START),
		SOC_SCTRL_SCPERDIS4_ADDR(SOC_ACPU_SCTRL_BASE_ADDR));
	return SECISP_SUCCESS;
}

static UINT32 set_phyclk_source(void)
{
	int ret;
	UINT32 value;

	ret = is_csiwrapper_reset();
	if (ret < 0) {
		ISP_ERR("fail: csi wrapper is in the reset status, ret.%d", ret);
		return SECISP_FAIL;
	}

    value = hisi_readl(SOC_CSI_WRAPPER_CSIE_CTRL_ADDR(SOC_ACPU_CSI_adapter_BASE_ADDR));
	value |= BIT(SOC_CSI_WRAPPER_CSIE_CTRL_phya_cfg_clk_mux_START);
	value |= BIT(SOC_CSI_WRAPPER_CSIE_CTRL_phye_cfg_clk_mux_START);
    hisi_writel(value, SOC_CSI_WRAPPER_CSIE_CTRL_ADDR(SOC_ACPU_CSI_adapter_BASE_ADDR));
	return SECISP_SUCCESS;
}

static void set_canary_value(void)
{
	UINT32 ret;
	UINT32 canary;

	ret = CRYS_RND_GenerateVector(sizeof(canary), (unsigned char *)(&canary));
	if (ret != 0) {
		ISP_ERR("CRYS_RND_GenerateVector fail.%u\n", ret);
		canary = 0;
	}

	hisi_writel(canary, ISP_SUBCTRL_CANARY_ADDR);
}

UINT32 hisp_top_pwron_and_disreset(struct smmu_domain *domain)
{
	UINT32 ret;

	ret = is_media1_reset();
	if (ret != 0) {
		ISP_ERR("fail : media1 status is reset");
		return ret;
	}

	ret = is_vivobus_idle();
	if (ret != 0) {
		ISP_ERR("fail : vivobus status is idle");
		return ret;
	}

	ret = is_isp_reset();
	if (ret != 0) {
		ISP_ERR("fail : ispsys status is reset");
		return ret;
	}

	ret = is_isp_idle();
	if (ret != 0) {
		ISP_ERR("fail : ispsys status is idle");
		return ret;
	}

	ret = set_powerup_isprt();
	if (ret != 0) {
		ISP_ERR("fail : isp rt power up");
		return ret;
	}

	ret = set_powerup_ispcap();
	if (ret != 0) {
		ISP_ERR("fail : isp cap power up");
		return ret;
	}

	set_ispsec();
	set_canary_value();
	ret = set_csi_disreset();
	if(ret != 0) {
		ISP_ERR("fail : set_csi_disreset");
		return ret;
	}
	ret = set_phyclk_source();
	if(ret != 0) {
		ISP_ERR("fail : set_phyclk_source");
		return ret;
	}
	ret = set_isp_disreset(domain);
	if(ret != 0) {
		ISP_ERR("fail : set_isp_disreset");
		return ret;
	}
	return ret;
}

UINT32 hisp_top_pwroff_and_reset(struct smmu_domain *domain)
{
	UINT32 ret;

	ret = is_media1_reset();
	if (ret != 0) {
		ISP_ERR("fail : media1 status is reset");
		return ret;
	}

	ret = is_vivobus_idle();
	if (ret != 0) {
		ISP_ERR("fail : vivobus status is idle");
		return ret;
	}

	ret = is_isp_reset();
	if (ret != 0) {
		ISP_ERR("fail : ispsys status is reset");
		return ret;
	}

	ret = is_isp_idle();
	if (ret != 0) {
		ISP_ERR("fail : ispsys status is idle");
		return ret;
	}

	ret = set_isp_reset(domain);
	if (ret != 0) {
		ISP_ERR("fail : set_isp_reset");
		return ret;
	}

	ret = set_csi_reset();
	if (ret != 0) {
		ISP_ERR("fail : set_csi_reset");
		return ret;
	}

	ret = set_powerdown_ispcap();
	if (ret != 0) {
		ISP_ERR("fail : isp cap power up");
		return ret;
	}

	ret = set_powerdown_isprt();
	if (ret != 0) {
		ISP_ERR("fail : isp rt power up");
		return ret;
	}

	return ret;
}

