/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implement smmu v2
 * Author: Security Engine
 * Create: 2020/07/15
 */
#include "mspe_smmu_v2.h"
#include <soc_eps_config_interface.h>
#include <soc_smmu_interface.h>
#include <soc_eps_smmu_mstr_interface.h>
#include <soc_acpu_baseaddr_interface.h>
#include <soc_baseaddr_interface.h>
#include <mspe_ddr_layout.h>
#include <common_utils.h>
#include <pal_types.h>
#include <pal_errno.h>
#include <pal_log.h>
#include <pal_memory.h>

static u64 g_mspe_pagetable_base_s;
static u64 g_mspe_pagetable_base_ns;

#define cfg_is_leagal(cfg) (cfg <= MSPE_SMMU_BYPASS_NON_SECURE)

/* 0:secure, 1: non-secure */
#define get_ns(cfg) ((cfg == MSPE_SMMU_SECURE || \
		      cfg == MSPE_SMMU_PROTECT || \
		      cfg == MSPE_SMMU_BYPASS_SECURE) ? 0 : 1)

/*
 * SID, hardware define
 * MSPE_SCE1_RD_SID_SECURE     : 0,
 * MSPE_SCE1_RD_SID_NON_SECURE : 1,
 * MSPE_SCE2_RD_SID_SECURE     : 2,
 * MSPE_SCE2_RD_SID_NON_SECURE : 3,
 * MSPE_SCE1_WR_SID_SECURE     : 4,
 * MSPE_SCE1_WR_SID_NON_SECURE : 5,
 * MSPE_SCE2_WR_SID_SECURE     : 6,
 * MSPE_SCE2_WR_SID_NON_SECURE : 7,
 */
#define make_up_sid(wr, mid, ns)  ((((wr) & 0x1) << 2) | ((((mid) - MSPE_MID_SCE1) & 0x1) << 1) | ((ns) & 0x1))
#define get_rd_sid(cfg, mid) make_up_sid(0, mid, get_ns(cfg))
#define get_wr_sid(cfg, mid) make_up_sid(1, mid, get_ns(cfg))

/* stream bypass, hardware define */
enum mspe_smmu_stream_bypass {
	MSPE_SMMU_STREAM_NON_BYPASS = 0,
	MSPE_SMMU_STREAM_BYPASS = 1,
};

static void mspe_smmu_cfg_sce1_sid(u32 rd_cfg, u32 wr_cfg)
{
	SOC_CONFIG_HIEPS_SCE1_SID_UNION sce1_sid;

	sce1_sid.value = pal_read_u32(SOC_CONFIG_HIEPS_SCE1_SID_ADDR(SOC_CONFIG_BASE_ADDR));
	sce1_sid.reg.arsid_sce1 = get_rd_sid(rd_cfg, MSPE_MID_SCE1);
	sce1_sid.reg.awsid_sce1 = get_wr_sid(wr_cfg, MSPE_MID_SCE1);
	pal_write_u32(sce1_sid.value, SOC_CONFIG_HIEPS_SCE1_SID_ADDR(SOC_CONFIG_BASE_ADDR));
}

static void mspe_smmu_cfg_sce2_sid(u32 rd_cfg, u32 wr_cfg)
{
	SOC_CONFIG_HIEPS_SCE2_SID_UNION sce2_sid;

	sce2_sid.value = pal_read_u32(SOC_CONFIG_HIEPS_SCE2_SID_ADDR(SOC_CONFIG_BASE_ADDR));
	sce2_sid.reg.arsid_sce2 = get_rd_sid(rd_cfg, MSPE_MID_SCE2);;
	sce2_sid.reg.awsid_sce2 = get_wr_sid(wr_cfg, MSPE_MID_SCE2);
	pal_write_u32(sce2_sid.value, SOC_CONFIG_HIEPS_SCE2_SID_ADDR(SOC_CONFIG_BASE_ADDR));
}

static void mspe_smmu_cfg_sid(u32 mid, u32 rd_cfg, u32 wr_cfg)
{
	if (mid == MSPE_MID_SCE1)
		mspe_smmu_cfg_sce1_sid(rd_cfg, wr_cfg);
	else
		mspe_smmu_cfg_sce2_sid(rd_cfg, wr_cfg);
}

static void mspe_smmu_cfg_com_non_secure(u32 mid, u32 sid, u32 bypass)
{
	SOC_SMMU_SCR_S_UNION scr_s;
	SOC_SMMU_SCR_P_UNION scr_p;
	SOC_SMMU_SCR_UNION scr;
	SOC_SMMU_SMRX_S_UNION smrx_s;
	SOC_SMMU_SMRX_P_UNION smrx_p;
	SOC_SMMU_SMRX_NS_UNION smrx_ns;

	/* smmu global config */
	scr_s.value = pal_read_u32(SOC_SMMU_SCR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_s.reg.glb_nscfg = 0x3; /* non-secure */
	pal_write_u32(scr_s.value, SOC_SMMU_SCR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_p.value = pal_read_u32(SOC_SMMU_SCR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_p.reg.glb_prot_cfg = 0x0; /* non-secure */
	pal_write_u32(scr_p.value, SOC_SMMU_SCR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr.value = pal_read_u32(SOC_SMMU_SCR_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr.reg.glb_bypass = 0x0; /* non-bypass */
	pal_write_u32(scr.value, SOC_SMMU_SCR_ADDR(SOC_SMMU_COM_BASE_ADDR));

	/* clear all interrupt and unmask interrupt */
	pal_write_u32(0xFF, SOC_SMMU_INTCLR_NS_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0x0, SOC_SMMU_INTMASK_NS_ADDR(SOC_SMMU_COM_BASE_ADDR));

	/* smmu stream config */
	smrx_s.value = pal_read_u32(SOC_SMMU_SMRX_S_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));
	smrx_s.reg.smr_nscfg = 0x1; /* non-secure */
	smrx_s.reg.smr_nscfg_en = 0x1; /* enable secure control */
	smrx_s.reg.smr_mid_en_s = 0x1; /* mid use smr_mid_s */
	smrx_s.reg.smr_mid_s = mid;
	pal_write_u32(smrx_s.value, SOC_SMMU_SMRX_S_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));

	smrx_p.value = pal_read_u32(SOC_SMMU_SMRX_P_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));
	smrx_p.reg.smr_protect_en = 0x0; /* non-secure */
	pal_write_u32(smrx_p.value, SOC_SMMU_SMRX_P_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));

	smrx_ns.value = pal_read_u32(SOC_SMMU_SMRX_NS_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));
	smrx_ns.reg.smr_bypass = bypass;
	pal_write_u32(smrx_ns.value, SOC_SMMU_SMRX_NS_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));

	/* smmu context config */
	pal_write_u32(U64_MSB(g_mspe_pagetable_base_ns), SOC_SMMU_CB_TTBR_MSB_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(U64_LSB(g_mspe_pagetable_base_ns), SOC_SMMU_CB_TTBR0_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0x1, SOC_SMMU_SCB_TTBCR_ADDR(SOC_SMMU_COM_BASE_ADDR)); /* Long Descriptor */

	/* error address */
	pal_write_u32(MSPE_DDR_REGION_SMMUV2_ERRADDR_BASE, SOC_SMMU_ERR_RDADDR_NS_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0, SOC_SMMU_ERR_ADDR_MSB_NS_ADDR(SOC_SMMU_COM_BASE_ADDR));
}

static void mspe_smmu_cfg_com_protect(u32 mid, u32 sid, u32 bypass)
{
	SOC_SMMU_SCR_S_UNION scr_s;
	SOC_SMMU_SCR_P_UNION scr_p;
	SOC_SMMU_SMRX_S_UNION smrx_s;
	SOC_SMMU_SMRX_P_UNION smrx_p;

	/* smmu global config */
	scr_s.value = pal_read_u32(SOC_SMMU_SCR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_s.reg.glb_nscfg = 0x3; /* non-secure */
	pal_write_u32(scr_s.value, SOC_SMMU_SCR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_p.value = pal_read_u32(SOC_SMMU_SCR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_p.reg.glb_prot_cfg = 0x1; /* protected */
	scr_p.reg.glb_bypass_p = 0x0; /* non-bypass */
	pal_write_u32(scr_p.value, SOC_SMMU_SCR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));

	/* clear all interrupt and unmask interrupt */
	pal_write_u32(0xFF, SOC_SMMU_INTCLR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0x0, SOC_SMMU_INTMAS_P_ADDR(SOC_SMMU_COM_BASE_ADDR));

	/* smmu stream config */
	smrx_s.value = pal_read_u32(SOC_SMMU_SMRX_S_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));
	smrx_s.reg.smr_nscfg = 0x1; /* non-secure */
	smrx_s.reg.smr_nscfg_en = 0x1; /* enable secure control */
	smrx_s.reg.smr_mid_en_s = 0x1; /* mid use smr_mid_s */
	smrx_s.reg.smr_mid_s = mid;
	pal_write_u32(smrx_s.value, SOC_SMMU_SMRX_S_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));

	smrx_p.value = pal_read_u32(SOC_SMMU_SMRX_P_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));
	smrx_p.reg.smr_protect_en = 0x1; /* protected */
	smrx_p.reg.smr_bypass_p = bypass;
	pal_write_u32(smrx_p.value, SOC_SMMU_SMRX_P_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));

	/* smmu context config */
	pal_write_u32(U64_MSB(g_mspe_pagetable_base_ns), SOC_SMMU_PCB_TTBR_MSB_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(U64_LSB(g_mspe_pagetable_base_ns), SOC_SMMU_PCB_TTBR_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0x1, SOC_SMMU_PCB_TTBCR_ADDR(SOC_SMMU_COM_BASE_ADDR)); /* Long Descriptor */

	/* error address */
	pal_write_u32(MSPE_DDR_REGION_SMMUV2_ERRADDR_BASE, SOC_SMMU_ERR_RDADDR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0, SOC_SMMU_ERR_ADDR_MSB_P_ADDR(SOC_SMMU_COM_BASE_ADDR));
}

static void mspe_smmu_cfg_com_secure(u32 mid, u32 sid, u32 bypass)
{
	SOC_SMMU_SCR_S_UNION scr_s;
	SOC_SMMU_SCR_P_UNION scr_p;
	SOC_SMMU_SMRX_S_UNION smrx_s;
	SOC_SMMU_SMRX_P_UNION smrx_p;

	/* smmu global config */
	scr_s.value = pal_read_u32(SOC_SMMU_SCR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_s.reg.glb_nscfg = 0x2; /* secure */
	scr_s.reg.glb_bypass_s = 0x0; /* non-bypass */
	pal_write_u32(scr_s.value, SOC_SMMU_SCR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));

	scr_p.value = pal_read_u32(SOC_SMMU_SCR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));
	scr_p.reg.glb_prot_cfg = 0x0; /* non-secure */
	pal_write_u32(scr_p.value, SOC_SMMU_SCR_P_ADDR(SOC_SMMU_COM_BASE_ADDR));

	/* clear all interrupt and unmask interrupt */
	pal_write_u32(0x3F, SOC_SMMU_INTCLR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0x0, SOC_SMMU_INTMAS_S_ADDR(SOC_SMMU_COM_BASE_ADDR));

	/* smmu stream config */
	smrx_s.value = pal_read_u32(SOC_SMMU_SMRX_S_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));
	smrx_s.reg.smr_nscfg = 0x0; /* secure */
	smrx_s.reg.smr_nscfg_en = 0x1; /* enable secure control */
	smrx_s.reg.smr_mid_en_s = 0x1; /* mid use smr_mid_s */
	smrx_s.reg.smr_mid_s = mid;
	smrx_s.reg.smr_bypass_s = bypass;
	pal_write_u32(smrx_s.value, SOC_SMMU_SMRX_S_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));

	smrx_p.value = pal_read_u32(SOC_SMMU_SMRX_P_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));
	smrx_p.reg.smr_protect_en = 0x0; /* non-secure */
	pal_write_u32(smrx_p.value, SOC_SMMU_SMRX_P_ADDR(SOC_SMMU_COM_BASE_ADDR, sid));

	/* smmu context config */
	pal_write_u32(U64_MSB(g_mspe_pagetable_base_s), SOC_SMMU_SCB_TTBR_MSB_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(U64_LSB(g_mspe_pagetable_base_s), SOC_SMMU_SCB_TTBR_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0x1, SOC_SMMU_SCB_TTBCR_ADDR(SOC_SMMU_COM_BASE_ADDR)); /* Long Descriptor */

	/* error address */
	pal_write_u32(MSPE_DDR_REGION_SMMUV2_ERRADDR_BASE, SOC_SMMU_ERR_RDADDR_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
	pal_write_u32(0, SOC_SMMU_ERR_ADDR_MSB_S_ADDR(SOC_SMMU_COM_BASE_ADDR));
}

static void mspe_smmu_cfg_com_item(u32 mid, u32 cfg, u32 sid)
{
	switch (cfg) {
	case MSPE_SMMU_SECURE:
		mspe_smmu_cfg_com_secure(mid, sid, MSPE_SMMU_STREAM_NON_BYPASS);
		break;
	case MSPE_SMMU_PROTECT:
		mspe_smmu_cfg_com_protect(mid, sid, MSPE_SMMU_STREAM_NON_BYPASS);
		break;
	case MSPE_SMMU_NON_SECURE:
		mspe_smmu_cfg_com_non_secure(mid, sid, MSPE_SMMU_STREAM_NON_BYPASS);
		break;
	case MSPE_SMMU_BYPASS_SECURE:
		mspe_smmu_cfg_com_secure(mid, sid, MSPE_SMMU_STREAM_BYPASS);
		break;
	case MSPE_SMMU_BYPASS_PROTECT:
		mspe_smmu_cfg_com_protect(mid, sid, MSPE_SMMU_STREAM_BYPASS);
		break;
	case MSPE_SMMU_BYPASS_NON_SECURE:
		mspe_smmu_cfg_com_non_secure(mid, sid, MSPE_SMMU_STREAM_BYPASS);
		break;
	default:
		break;
	}
}

static void mspe_smmu_inv_tlb(void)
{
	SOC_CONFIG_HIEPS_SMMU_CTRL_UNION ctrl;

	ctrl.value = SOC_CONFIG_HIEPS_SMMU_CTRL_ADDR(SOC_CONFIG_BASE_ADDR);

	/* start invalidateattention!!! first high, then low, pulse needed!!! */
	ctrl.reg.stream_start = 0xFF;
	pal_write_u32(ctrl.value, SOC_CONFIG_HIEPS_SMMU_CTRL_ADDR(SOC_CONFIG_BASE_ADDR));
	ctrl.reg.stream_start = 0x0;
	pal_write_u32(ctrl.value, SOC_CONFIG_HIEPS_SMMU_CTRL_ADDR(SOC_CONFIG_BASE_ADDR));
}

static void mspe_smmu_cfg_com(u32 mid, u32 rd_cfg, u32 wr_cfg)
{
	mspe_smmu_cfg_com_item(mid, rd_cfg, get_rd_sid(rd_cfg, mid));
	mspe_smmu_cfg_com_item(mid, wr_cfg, get_wr_sid(wr_cfg, mid));
}

static void mspe_smmu_cfg_mst_item(u32 mid, u32 cfg, u32 sid)
{
	SOC_EPS_SMMU_MSTR_SMMU_MSTR_GLB_BYPASS_UNION mstr_glb_bypass;
	SOC_EPS_SMMU_MSTR_SMMU_MSTR_CLK_EN_UNION mstr_clk;
	SOC_EPS_SMMU_MSTR_SMMU_MSTR_SMRX_0_UNION mstr_smrx_0;
	u32 bypass = 0; /* non-bypass */

	UNUSED(mid);

	/* smmu global config */
	mstr_glb_bypass.value = pal_read_u32(SOC_EPS_SMMU_MSTR_SMMU_MSTR_GLB_BYPASS_ADDR(SOC_SMMU_MST_BASE_ADDR));
	mstr_glb_bypass.reg.glb_bypass = 0x0; /* non-bypass */
	pal_write_u32(mstr_glb_bypass.value, SOC_EPS_SMMU_MSTR_SMMU_MSTR_GLB_BYPASS_ADDR(SOC_SMMU_MST_BASE_ADDR));
	mstr_clk.value = pal_read_u32(SOC_EPS_SMMU_MSTR_SMMU_MSTR_CLK_EN_ADDR(SOC_SMMU_MST_BASE_ADDR));
	mstr_clk.reg.apb_clk_en = 0x1;
	mstr_clk.reg.core_clk_en = 0x1;
	pal_write_u32(mstr_clk.value, SOC_EPS_SMMU_MSTR_SMMU_MSTR_CLK_EN_ADDR(SOC_SMMU_MST_BASE_ADDR));

	/* interrupt config */
	pal_write_u32(0x1F, SOC_EPS_SMMU_MSTR_SMMU_MSTR_INTCLR_ADDR(SOC_SMMU_MST_BASE_ADDR)); /* clear all int */
	pal_write_u32(0x0, SOC_EPS_SMMU_MSTR_SMMU_MSTR_INTMASK_ADDR(SOC_SMMU_MST_BASE_ADDR)); /* no mask */

	if (cfg == MSPE_SMMU_BYPASS_NON_SECURE ||
	    cfg == MSPE_SMMU_BYPASS_PROTECT ||
	    cfg == MSPE_SMMU_BYPASS_SECURE)
		bypass = 1;
	/* stream config */
	mstr_smrx_0.value = pal_read_u32(SOC_EPS_SMMU_MSTR_SMMU_MSTR_SMRX_0_ADDR(SOC_SMMU_MST_BASE_ADDR, sid));
	mstr_smrx_0.reg.bypass = bypass;
	pal_write_u32(mstr_smrx_0.value, SOC_EPS_SMMU_MSTR_SMMU_MSTR_SMRX_0_ADDR(SOC_SMMU_MST_BASE_ADDR, sid));
}

static void mspe_smmu_cfg_mst(u32 mid, u32 rd_cfg, u32 wr_cfg)
{
	mspe_smmu_cfg_mst_item(mid, rd_cfg, get_rd_sid(rd_cfg, mid));
	mspe_smmu_cfg_mst_item(mid, wr_cfg, get_wr_sid(wr_cfg, mid));
}

/*
 * related configration:
 * 1.CONFIG:SID
 * 2.SMMU-COMMON
 * 3.SMMU-Master
 */
void mspe_smmu_enable(u32 mid, u32 rd_cfg, u32 wr_cfg)
{
	if (PAL_CHECK(mid != MSPE_MID_SCE1 && mid != MSPE_MID_SCE2)) {
		PAL_ERROR("mid is illegal, mid=%d\n", mid);
		return;
	}
	if (!cfg_is_leagal(rd_cfg)) {
		PAL_ERROR("rd_cfg is illegal, rd_cfg=%d\n", rd_cfg);
		return;
	}
	if (!cfg_is_leagal(wr_cfg)) {
		PAL_ERROR("wr_cfg is illegal, wr_cfg=%d\n", wr_cfg);
		return;
	}

	mspe_smmu_cfg_sid(mid, rd_cfg, wr_cfg);
	mspe_smmu_inv_tlb();
	mspe_smmu_cfg_com(mid, rd_cfg, wr_cfg);
	mspe_smmu_cfg_mst(mid, rd_cfg, wr_cfg);
}

void mspe_smmu_disable(u32 mid)
{
	if (PAL_CHECK(mid != MSPE_MID_SCE1 && mid != MSPE_MID_SCE2)) {
		PAL_ERROR("mid is illegal, mid=%d\n", mid);
		return;
	}

	mspe_smmu_cfg_sid(mid, MSPE_SMMU_SECURE, MSPE_SMMU_SECURE);
	mspe_smmu_cfg_com(mid, MSPE_SMMU_BYPASS_SECURE, MSPE_SMMU_BYPASS_SECURE);
	mspe_smmu_cfg_mst(mid, MSPE_SMMU_BYPASS_SECURE, MSPE_SMMU_BYPASS_SECURE);
}

void mspe_smmu_bypass(void)
{
	mspe_smmu_disable(MSPE_MID_SCE1);
	mspe_smmu_disable(MSPE_MID_SCE2);
}

void mspe_smmu_set_pgt_addr(u64 pgt_pa, u32 is_sec)
{
	if (is_sec)
		g_mspe_pagetable_base_s = pgt_pa;
	else
		g_mspe_pagetable_base_ns = pgt_pa;
}

