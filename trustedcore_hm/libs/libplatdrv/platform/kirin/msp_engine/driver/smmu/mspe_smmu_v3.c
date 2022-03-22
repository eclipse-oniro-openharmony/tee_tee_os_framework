/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: Stub for baltimore, and need to modify.
 * Author : w00371137, wangyuzhu4@huawei.com
 * Create: 2019/04/11
 */

#include <mspe_smmu_v3.h>
#include <register_ops.h> /* read32 */
#include <hieps_errno.h>
#include <hieps_timer.h>
#include <soc_smmuv3_tbu_interface.h>
#include <soc_smmuv3_tcu_interface.h>
#include <soc_eps_config_interface.h>
#include <soc_acpu_baseaddr_interface.h>
#include <secmem.h>
#include <sec_smmu_com.h>

/* Accroding to SOC, hieps translation number is 8. */
#define MAX_TRANS_TOKENS       8
#define TBU_REQUEST_TIMEOUT    1000 /* 100us */

#define SMMU_SCE_RD_SID        SECSMMU_STREAMID_EPS
#define SMMU_SCE_WR_SID        SECSMMU_STREAMID_EPS
#define SMMU_SCE_RD_BYPASS_SID SECSMMU_STREAMID_BYPASS
#define SMMU_SCE_WR_BYPASS_SID SECSMMU_STREAMID_BYPASS
#define SMMU_SCE_SSID          SECSMMU_SUBSTREAMID_EPS

#define SMMU_SSID_SEC          1
#define SMMU_SSID_UNSEC        0
#define SMMU_SSID_VALID        1
#define SMMU_SSID_INVALID      0
#define SMMU_CLR_IRQ           0xFFFFFFFF
#define SCE1_WT_SWID           0x00
#define SCE1_RD_SWID           0x01
#define SCE2_WT_SWID           0x02
#define SCE2_RD_SWID           0x03
#define EPS_PRESLOT_FULL_LEVEL 0x8
#define EPS_PREF_ENABLE        0x1
#define EPS_CATCHE_HINT        0x2

void hieps_smmu_interrupt_init(void)
{
	/* Non-secure interrupt. */
	write32(SOC_SMMUv3_TBU_SMMU_TBU_IRPT_CLR_NS_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), SMMU_CLR_IRQ);
	write32(SOC_SMMUv3_TBU_SMMU_TBU_IRPT_MASK_NS_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), 0x0);

	/* Secure interrupt. */
	write32(SOC_SMMUv3_TBU_SMMU_TBU_IRPT_CLR_S_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), SMMU_CLR_IRQ);
	write32(SOC_SMMUv3_TBU_SMMU_TBU_IRPT_MASK_S_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), 0x0);
}

void hieps_smmu_perf_init(void)
{
	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION pref_config = { 0 };
	SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_UNION pref_en_config = { 0 };

	/* step1 set prefslot_full_level and fetchslot_full_level */
	pref_config.value = readl(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	pref_config.reg.prefslot_full_level = EPS_PRESLOT_FULL_LEVEL;
	pref_config.reg.fetchslot_full_level = EPS_PRESLOT_FULL_LEVEL;
	write32(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), pref_config.value);

	/* step2 SCE1 enable */
	pref_en_config.value = readl(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE1_WT_SWID));
	pref_en_config.reg.pref_en = EPS_PREF_ENABLE;
	pref_en_config.reg.syscache_hint_sel = EPS_CATCHE_HINT;
	write32(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE1_WT_SWID), pref_en_config.value);

	pref_en_config.value = readl(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE1_RD_SWID));
	pref_en_config.reg.pref_en = EPS_PREF_ENABLE;
	pref_en_config.reg.syscache_hint_sel = EPS_CATCHE_HINT;
	write32(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE1_RD_SWID), pref_en_config.value);

	/* step3 SCE2 enable */
	pref_en_config.value = readl(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE2_WT_SWID));
	pref_en_config.reg.pref_en = EPS_PREF_ENABLE;
	pref_en_config.reg.syscache_hint_sel = EPS_CATCHE_HINT;
	write32(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE2_WT_SWID), pref_en_config.value);

	pref_en_config.value = readl(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE2_RD_SWID));
	pref_en_config.reg.pref_en = EPS_PREF_ENABLE;
	pref_en_config.reg.syscache_hint_sel = EPS_CATCHE_HINT;
	write32(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, SCE2_RD_SWID), pref_en_config.value);
}

/*
 * trust cant access write protect ddr.
 * sce is default to be trust, we need convert it to protect.
 */
void hieps_smmu_set_tbu_protect(void)
{
	SOC_SMMUv3_TBU_SMMU_TBU_PROT_EN_UNION prot_en;
	SOC_CONFIG_HIEPS_SEC_CTRL_UNION ctrl;
	u32 i;
	u32 addr;

	for (i = 0; i <= SCE1_RD_SWID; i++) {
		addr = SOC_SMMUv3_TBU_SMMU_TBU_PROT_EN_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR, i);
		prot_en.value = readl(addr);
		prot_en.reg.protect_en = 1;
		write32(addr, prot_en.value);
	}

	addr = SOC_CONFIG_HIEPS_SEC_CTRL_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR);
	ctrl.value = readl(addr);
	ctrl.reg.cfg_trust2prot_en = 1;
	write32(addr, ctrl.value);
}

/*
 * @brief      : hieps_mmu_init : initialize mmu.
 *
 * @return     : OK: successful, Others: failed.
 */
uint32_t hieps_mmu_init(void)
{
	uint32_t timeout;
	SOC_SMMUv3_TBU_SMMU_TBU_SCR_UNION scr_config = { 0 };
	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION cr_config = { 0 };
	SOC_SMMUv3_TBU_SMMU_TBU_CRACK_UNION crack_config = { 0 };

	scr_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_SCR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	/* Step 0: non-bypass summu. */
	scr_config.reg.tbu_bypass = 0; /* 0: Non-bypass, bypass for rom. */
	/* Step 1: Set TBU to be secure. */
	scr_config.reg.ns_uarch = 1; /* 1: Non-secure accesses are permitted. */
	/* Step 2: set TLB invalidation. */
	scr_config.reg.tlb_inv_sel = 0; /* 0: Invalid from TCU. */
	write32(SOC_SMMUv3_TBU_SMMU_TBU_SCR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), scr_config.value);
	scr_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_SCR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	cr_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	/* Step 3: Set the number of DTI translation tokens to request when connecting to the TCU. */
	cr_config.reg.max_tok_trans = MAX_TRANS_TOKENS;
	/* Step 4: Set TBU to enable request. */
	cr_config.reg.tbu_en_req = 1; /* 1: enable TBU request. */
	write32(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), cr_config.value);
	cr_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));

	/* Step 5. Check acknowledge of TBU enabling request. Timeout is 100us. */
	crack_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	timeout = TBU_REQUEST_TIMEOUT;
	while ((crack_config.reg.tbu_en_ack != 1) && (timeout)) {
		hieps_udelay(1); /* Every loop delay 1us. */
		timeout--;
		crack_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	}
	if (timeout == 0) {
		tloge("%s: TBU request TCU timeout! 0x%x\n", __func__, crack_config.value);
		return HIEPS_MMU_TIME_OUT_ERR;
	}

	/* Step 6: Check TBU connecting status. */
	/* Step 7: Check the number of DTI translation tokens granted from TCU. */
	crack_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	if ((crack_config.reg.tbu_connected != 1) ||
			(crack_config.reg.tok_trans_gnt < MAX_TRANS_TOKENS)) {
		tloge("%s: TBU connect TCU failed!\n", __func__);
		return HIEPS_MMU_INIT_ERR;
	}

	hieps_smmu_perf_init();
	hieps_smmu_interrupt_init();
	hieps_smmu_set_tbu_protect();

	return HIEPS_OK;
}

uint32_t hieps_mmu_exit(void)
{
	uint32_t ret = HIEPS_OK;
	uint32_t timeout;
	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION cr_config = { 0 };
	SOC_SMMUv3_TBU_SMMU_TBU_CRACK_UNION crack_config = { 0 };

	cr_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	/* Step 1: Set TBU to disable request. */
	cr_config.reg.tbu_en_req = 0; /* 1: disable TBU request. */
	write32(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), cr_config.value);

	/* Step 2. Check acknowledge of TBU disabling request. Timeout is 100us. */
	crack_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	timeout = TBU_REQUEST_TIMEOUT;
	while ((crack_config.reg.tbu_en_ack != 1) && (timeout)) {
		hieps_udelay(1); /* Every loop delay 1us. */
		timeout--;
		crack_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	}
	if (timeout == 0) {
		tloge("%s: TBU request TCU timeout!\n", __func__);
		ret = HIEPS_MMU_TIME_OUT_ERR;
		goto end;
	}

	crack_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	if (crack_config.reg.tbu_connected != 0) {
		tloge("%s: TBU disconnect TCU failed!\n", __func__);
		ret = HIEPS_MMU_EXIT_ERR;
		goto end;
	}

end:
	hieps_mmu_tbu_bypass();

	return ret;
}

void hieps_mmu_tbu_bypass(void)
{
	SOC_SMMUv3_TBU_SMMU_TBU_SCR_UNION scr_config;

	scr_config.value = read32(SOC_SMMUv3_TBU_SMMU_TBU_SCR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	scr_config.reg.tbu_bypass = 1; /* 1: bypass. */
	write32(SOC_SMMUv3_TBU_SMMU_TBU_SCR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR), scr_config.value);
}

/**
 * @brief      : mmu_enable : enable mmu.
 *
 * @return     : OK: successful, Others: failed.
 */
uint32_t hieps_mmu_sce1_enable(uint32_t read_enable, uint32_t write_enable, uint32_t is_sec)
{
	SOC_CONFIG_HIEPS_MMU_WID_UNION wr_config;
	SOC_CONFIG_HIEPS_MMU_RID_UNION rd_config;

	/* config sce1 write. */
	wr_config.value = read32(SOC_CONFIG_HIEPS_MMU_WID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	if (write_enable == TRUE) {
		wr_config.reg.awmmussidv_s0   = SMMU_SSID_VALID;
		wr_config.reg.awmmusid_s0     = SMMU_SCE_WR_SID;
	} else {
		wr_config.reg.awmmussidv_s0   = SMMU_SSID_INVALID;
		wr_config.reg.awmmusid_s0     = SMMU_SCE_WR_BYPASS_SID;
	}
	if (is_sec == TRUE)
		wr_config.reg.awmmusecsid_s0  = SMMU_SSID_SEC;
	else
		wr_config.reg.awmmusecsid_s0  = SMMU_SSID_UNSEC;
	wr_config.reg.awmmussid_s0    = SMMU_SCE_SSID;
	write32(SOC_CONFIG_HIEPS_MMU_WID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR), wr_config.value);

	/* config sce1 read. */
	rd_config.value = read32(SOC_CONFIG_HIEPS_MMU_RID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	if (read_enable == TRUE) {
		rd_config.reg.armmussidv_s0   = SMMU_SSID_VALID;
		rd_config.reg.armmusid_s0     = SMMU_SCE_RD_SID;
	} else {
		rd_config.reg.armmussidv_s0   = SMMU_SSID_INVALID;
		rd_config.reg.armmusid_s0     = SMMU_SCE_RD_BYPASS_SID;
	}

	if (is_sec == TRUE)
		rd_config.reg.armmusecsid_s0  = SMMU_SSID_SEC;
	else
		rd_config.reg.armmusecsid_s0  = SMMU_SSID_UNSEC;
	rd_config.reg.armmussid_s0    = SMMU_SCE_SSID;
	write32(SOC_CONFIG_HIEPS_MMU_RID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR), rd_config.value);

	return HIEPS_OK;
}

uint32_t hieps_mmu_sce2_enable(uint32_t read_enable, uint32_t write_enable, uint32_t is_sec)
{
	SOC_CONFIG_HIEPS_MMU2_WID_UNION wr_config;
	SOC_CONFIG_HIEPS_MMU2_RID_UNION rd_config;

	/* config sce1 write. */
	wr_config.value = read32(SOC_CONFIG_HIEPS_MMU2_WID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	if (write_enable == TRUE) {
		wr_config.reg.awmmussidv_s1   = SMMU_SSID_VALID;
		wr_config.reg.awmmusid_s1     = SMMU_SCE_WR_SID;
	} else {
		wr_config.reg.awmmussidv_s1   = SMMU_SSID_INVALID;
		wr_config.reg.awmmusid_s1     = SMMU_SCE_WR_BYPASS_SID;
	}

	if (is_sec == TRUE)
		wr_config.reg.awmmusecsid_s1  = SMMU_SSID_SEC;
	else
		wr_config.reg.awmmusecsid_s1  = SMMU_SSID_UNSEC;
	wr_config.reg.awmmussid_s1    = SMMU_SCE_SSID;
	write32(SOC_CONFIG_HIEPS_MMU2_WID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR), wr_config.value);

	/* config sce1 read. */
	rd_config.value = read32(SOC_CONFIG_HIEPS_MMU2_RID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR));
	if (read_enable == TRUE) {
		rd_config.reg.armmussidv_s1   = SMMU_SSID_VALID;
		rd_config.reg.armmusid_s1     = SMMU_SCE_RD_SID;
	} else {
		rd_config.reg.armmussidv_s1   = SMMU_SSID_INVALID;
		rd_config.reg.armmusid_s1     = SMMU_SCE_RD_BYPASS_SID;
	}

	if (is_sec == TRUE)
		rd_config.reg.armmusecsid_s1  = SMMU_SSID_SEC;
	else
		rd_config.reg.armmusecsid_s1  = SMMU_SSID_UNSEC;
	rd_config.reg.armmussid_s1    = SMMU_SCE_SSID;
	write32(SOC_CONFIG_HIEPS_MMU2_RID_ADDR(SOC_ACPU_EPS_CONFIG_BASE_ADDR), rd_config.value);

	return HIEPS_OK;
}
