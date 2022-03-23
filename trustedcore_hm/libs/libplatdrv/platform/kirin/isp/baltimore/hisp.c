/*
* Copyright (c) Huawei Technologies Co., Ltd. 2012-2019. All rights reserved.
* Description: isp interface
* Author: z00367550
* Create: 2019-9-26
*/

#include "hisp.h"
#include "register_ops.h"
#include "tee_log.h"
#include "hisi_boot.h"
#include "mem_page_ops.h"
#include "dynion.h"
#include <soc_smmuv3_tbu_interface.h>
#include <soc_isp_nmanager_sec_adpt_interface.h>
#include <soc_media1_crg_interface.h>

static int is_media1_reset(void)
{
	unsigned int reg;
	reg = readl(CRG_PERRSTSTAT5) & IP_RST_MEDIA;
	return (reg == 0) ? 0 : -1;
}

static int is_isp_reset(void)
{
	unsigned int reg;
	reg = readl(MEDIA1_PERRSTSTAT_ISP_SEC) & IP_RST_ISP;
	return (reg == 0) ? 0 : -1;
}

int hisi_isp_reset(void)
{
	tloge("[%s] +\n", __func__);

	if (is_media1_reset() < 0) {
		tloge("[%s] : Media1 is Reset.-1\n", __func__);
		return -1;
	}

	writel(0x00000010, MEDIA1_PERRSTEN_ISP_SEC);
	tloge("[%s] -\n", __func__);
	return 0;
}

static int smmuv3_reg_set_ackbit(unsigned int addr, unsigned int reqval, unsigned int ackval,
							  unsigned int reqoffset, unsigned int ackoffset, unsigned int reqbit, unsigned int ackbit)
{
	unsigned int stat = 0;
	unsigned int reg;
	int timeout;
	unsigned int i;

	reg = readl(addr + reqoffset);
	if (reqval) {
		reg |= (1 << reqbit);
	} else {
		reg &= ~(1 << reqbit);
	}

	writel(reg, addr + reqoffset);
	timeout = SMMUV3_DELAY_TIMEOUT;

	do {
		stat = 0;
		stat = readl(addr + ackoffset);
		stat &= 1 << ackbit;
		timeout--;

		for (i = 0; i < SMMUV3_DELAY_TIME; i++) {}
	} while ((stat != (ackval << ackbit)) && (timeout >= 0));

	if (timeout < 0) {
		return -1;
	}

	return 0;
}

static void set_ssid_valid(unsigned int sec_adpt_base)
{
	unsigned int i = 0;
	SOC_ISP_nManager_SEC_ADPT_swid_cfg_ns_UNION cfg_ns;
	SOC_ISP_nManager_SEC_ADPT_swid_cfg_s_UNION cfg_s;

	for (i = 0; i < SMMUV3_SSID_MAX; i++) {
		cfg_ns.value = readl(sec_adpt_base + i * SMMUV3_SID_OFFSET); // ssidv_ns
		cfg_ns.reg.ssidv_ns = 1;
		cfg_ns.reg.user_def_ns = ISP_SMMUV3_SID;
		writel(cfg_ns.value, (sec_adpt_base + i * SMMUV3_SID_OFFSET));
		cfg_s.value = readl(sec_adpt_base + SMMUV3_TBU_REG_SWID_CFG_S + i * SMMUV3_SID_OFFSET); // ssidv_s
		cfg_s.reg.ssidv_s = 1;
		cfg_s.reg.user_def_s = ISP_SMMUV3_SID;
		writel(cfg_s.value, (sec_adpt_base + SMMUV3_TBU_REG_SWID_CFG_S + i * SMMUV3_SID_OFFSET));
	}
}

static int smmuv3_tbu_init(unsigned int tbu_base)
{
	unsigned int offset;
	unsigned int ret;
	unsigned int addr;
	SOC_SMMUv3_TBU_SMMU_TBU_SCR_UNION scr;
	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION cr;
	SOC_SMMUv3_TBU_SMMU_TBU_CRACK_UNION crack;

	addr = tbu_base;
	/* Set tbu reg secure attribute */
	offset = SMMUV3_TBU_REG_SMMU_TBU_SCR_REG;
	scr.value = readl(addr + offset);
	scr.reg.tlb_inv_sel = 1; // Invalid from TBU

	if (addr == ISP_ARC_SMMU_TBU) {
		scr.reg.tlb_inv_sel = 0;
	}

	scr.reg.tbu_bypass = 0;
	writel(scr.value, addr + offset);
	/* Request the TBU to establish a connection with the TCU */
	ret = smmuv3_reg_set_ackbit(addr, 1, 1, SMMUV3_TBU_REG_SMMU_TBU_CR_REG,
							    SMMUV3_TBU_REG_SMMU_TBU_CRACK_REG,
							    SMMUV3_TBU_REG_TBU_EN_REQ_OFFSET,
							    SMMUV3_TBU_REG_TBU_EN_ACK_OFFSET);

	if (ret) {
		tloge("[%s] Failed: smmuv3_reg_set_ack_bit.\n", __func__);
		return -1;
	}

	/* Determine whether the connection is established successfully */
	offset = SMMUV3_TBU_REG_SMMU_TBU_CRACK_REG;
	crack.value = readl(addr + offset);

	if (crack.reg.tbu_connected != 1) {
		tloge("[%s] Failed: tbu_connected = %d.\n", __func__, crack.reg.tbu_connected);
		return -1;
	}

	/* determine tok_trans_gnt value */
	offset = SMMUV3_TBU_REG_SMMU_TBU_CR_REG;
	cr.value = readl(addr + offset);

	if (crack.reg.tok_trans_gnt < cr.reg.max_tok_trans) {
		tloge("[%s] Failed: tok_trans_gnt = %d.max_tok_trans\n",
			  __func__, crack.reg.tok_trans_gnt, cr.reg.max_tok_trans);
		return -1;
	}

	return 0;
}

static int arc_smmuv3_enable(void)
{
	set_ssid_valid(ISP_ARC_SEC_ADPT);

	if (smmuv3_tbu_init(ISP_ARC_SMMU_TBU)) {
		tloge("[%s] smmuv3_tbu_init\n", __func__);
		return -1;
	}

	return 0;
}

#ifndef ISP_CHIP_ES
static void hisi_isp_cs_disreset(void)
{
	unsigned int value;
	SOC_MEDIA1_CRG_ISPCPU_CLKEN_UNION media_crg_ispcpu_clken;
	SOC_MEDIA1_CRG_ISPCPU_RSTEN_UNION media_crg_ispcpu_rsten;
	SOC_MEDIA1_CRG_PERRSTEN_ISP_SEC_UNION media_crg_isp_sec;
	SOC_MEDIA1_CRG_PERRSTDIS0_UNION   media_crg_perrstdiso;

	writel(MEDIA_ISPCPU_CTRL0_SEC, MEDIA1_ISPCPU_CTRL0_SEC);
	writel(ISP_SUBCTRL_CSSYS_DBGEN | ISP_SUBCTRL_CSSYS_NIDEN, ISP_ARC_CTRL_8);
	value = readl(ISP_ARC_CTRL_10);
	value &= (~ISP_SUBCTRL_CFGNMFI);
	value |= ISP_SUBCTRL_NCPUHALT;
	writel(value, ISP_ARC_CTRL_10);
	writel(ISP_SUBCTRL_DBG_SPRAM_MEM_CTRL, ISP_ARC_CTRL_12);
	/* close reamp */
	value = readl(ISP_ARC_CTRL_0);
	value &= (~ISP_ARC_REMAP_ENABLE);
	writel(value, ISP_ARC_CTRL_0);
	media_crg_ispcpu_clken.reg.ccpu_pd_clk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_core_clk_en  = 0x3;
	media_crg_ispcpu_clken.reg.ccpu_dbg_clk_en   = 0x3;
	media_crg_ispcpu_clken.reg.ccpu_etm_clk_en   = 0x3;
	media_crg_ispcpu_clken.reg.ccpu_ct_clk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_atbclk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_dbgclk_en    = 0x1;
	media_crg_ispcpu_clken.reg.ccpu_m0clk_divnum = 0x3;
	media_crg_ispcpu_clken.reg.bitmasken         = 0x7FF;
	writel(media_crg_ispcpu_clken.value, MEDIA1_ISP_CPU_CLKEN);
	media_crg_ispcpu_rsten.reg.ccpu_core_srst_req_n   = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_scu_srst_req_n    = 0x1;
	media_crg_ispcpu_rsten.reg.ccpu_ct_srst_req_n     = 0x1;
	media_crg_ispcpu_rsten.reg.ccpu_wdt_srst_req_n    = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_dbg_srst_req_n    = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_etm_srst_req_n    = 0x3;
	media_crg_ispcpu_rsten.reg.ccpu_periph_srst_req_n = 0x1;
	media_crg_ispcpu_rsten.reg.cs_ccpu_dbg_srst_req_n = 0x1;
	media_crg_ispcpu_rsten.reg.ccpu_pd_srst_req_n     = 0x1;
	writel(media_crg_ispcpu_rsten.value, MEDIA1_ISP_CPU_RSTEN);
	media_crg_isp_sec.reg.ip_rst_isp_cpu = 0x1;
	writel(media_crg_isp_sec.value, MEDIA1_PERRSTDIS_ISP_SEC);
	media_crg_perrstdiso.reg.ip_rst_trace = 0x1;
	writel(media_crg_perrstdiso.value, MEDIA1_PERRSTDIS0);
}
#else
static void hisi_isp_es_disreset(void)
{
	unsigned int value;
	unsigned int timeout  = 400;

	writel(0x00001000, ISP_ARC_SUB_CTRL10); /* arc1 num : 1 */
	writel(0x00000010, MEDIA1_PERRSTDIS_ISP_SEC);
	/* close reamp */
	value = readl(ISP_ARC_CTRL_0);
	value &= (~ISP_ARC_REMAP_ENABLE);
	writel(value, ISP_ARC_CTRL_0);
	/* start addr cfg */
	value = TEXT_BASE >> ISP_CPU_INTVBASE_IN;
	writel(value, ISP_ARC_CTRL_8);
	writel(value, ISP_ARC_CTRL_9);
	/* start isp cpu */
	writel(readl(MEDIA1_ISPCPU_CTRL0_SEC) | ISP_CPU_ARC_RUN_REQ, MEDIA1_ISPCPU_CTRL0_SEC);

	do {
		value = readl(MEDIA1_ISP_CPU_STATE0);
		hisi_udelay(1);
		timeout--;

		if (timeout == 0) {
			tloge("<ISP CPU State value =0x%x>\n", value);
			return;
		}
	} while ((value & ISP_CPU_ARC_RUN_ACK) != ISP_CPU_ARC_RUN_ACK);

	writel(readl(MEDIA1_ISPCPU_CTRL0_SEC) & (~ISP_CPU_ARC_RUN_REQ), MEDIA1_ISPCPU_CTRL0_SEC);
	writel(0x00000800, MEDIA1_PERRSTDIS0);
}
#endif

/*lint -e438 -e529 -esym(438,*) -esym(529,*)*/
int hisi_isp_disreset(unsigned int remapaddr)
{
	tloge("[%s] +\n", __func__);

	(VOID)remapaddr;
	if (is_media1_reset() < 0) {
		tloge("[%s] : Media1 is Reset.-1\n", __func__);
		return -1;
	}

	if (is_isp_reset() < 0) {
		tloge("[%s] : Isp is Reset.-1\n", __func__);
		return -1;
	}

	writel(0x00000008, MEDIA1_PERRSTDIS_ISP_SEC);

	if (arc_smmuv3_enable() < 0) {
		tloge("[%s] Failed: arc_smmuv3_enable%d\n", __func__);
		return -1;
	}

#ifndef ISP_CHIP_ES
	hisi_isp_cs_disreset();
#else
	hisi_isp_es_disreset();
#endif
	tloge("[%s] -\n", __func__);
	return 0;
}

unsigned int get_isp_img_size(void)
{
	return SEC_ISP_BIN_SIZE;
}

unsigned int get_isp_cma_size(void)
{
	return SEC_CMA_IMAGE_SIZE;
}

unsigned int get_isp_baseaddr(void)
{
	return SEC_ISP_IMG_BASE_ADDR;
}

int is_isp_rdr_addr(struct sglist *sgl)
{
	if (sgl == NULL) {
		ISP_ERR("wrong, sgl is NULL");
		return 0;
	}

	if (sgl->ion_size == 0) {
		ISP_ERR("wrong size, size.0x%x", sgl->ion_size);
		return 0;
	}

	if (sgl->info[0].phys_addr == 0) {
		ISP_ERR("wrong sgl, sgl->info[0].phys_addr is 0x%x", sgl->info[0].phys_addr);
		return 0;
	}

	if (((sgl->info[0].phys_addr >= BBOX_MEM_BASE_ADDR) &&
		((sgl->info[0].phys_addr - BBOX_MEM_BASE_ADDR_SIZE) < BBOX_MEM_BASE_ADDR) &&
		(sgl->info[0].phys_addr >= BBOX_MEM_BASE_ADDR - sgl->ion_size) &&
		((sgl->info[0].phys_addr - BBOX_MEM_BASE_ADDR_SIZE) < (BBOX_MEM_BASE_ADDR - sgl->ion_size))) ||
		((sgl->info[0].phys_addr == SEC_ISP_IMG_TEXT_BASE_ADDR) &&
		(sgl->ion_size == SECISP_BOOTWARE_SIZE))) {
		ISP_DEBUG("memory is in the rdr region");
		return 1;
	}

	ISP_DEBUG("memory is not in the rdr region");
	return 0;
}


