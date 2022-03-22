/*
 * npu_adapter.c
 *
 * about npu adapter
 *
 * Copyright (c) 2012-2019 Huawei Technologies Co., Ltd.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

#include "npu_adapter.h"

#include <errno.h>
#include <drv_pal.h>
#include "list.h"
#include "securec.h"
#include "tee_mem_mgmt_api.h"
#include "sre_syscalls_ext.h"
#include "svm.h"
#include "secmem.h"
#include "sec_smmu_com.h"
#include "npu_log.h"
#include "npu_base_define.h"
#include "npu_reg.h"
#include "npu_platform_resource.h"
#include "npu_platform_register.h"
#include "npu_schedule_task.h"

#define NPU_SVC_OK              0
#define NPU_SVC_ERR             (~NPU_SVC_OK)

#define npu_udelay(usec)                                                      \
	do {                                                                   \
		int i;                                                         \
		for (i = 0; i < 500 * (usec); i++) {                             \
			asm("nop");                                            \
		};                                                             \
	} while (0)

int npu_subsys_tbu_connect(uint32_t tbu_base) //atf_npu_subsys_tbu_connect
{
	int max_tok_trans = 0;
	switch (tbu_base)
	{
		case SOC_ACPU_ts_tbu_BASE_ADDR:
			max_tok_trans = 7;
			break;
		case SOC_ACPU_aic0_smmu_cfg_BASE_ADDR:
			max_tok_trans = 23;
			break;
		case SOC_ACPU_aic1_smmu_cfg_BASE_ADDR:
			max_tok_trans = 23;
			break;
		default:
			break;
	}
	uint32_t timeout = 1000;
	NPU_DRV_DEBUG("atf_npu_subsys_tbu_power_up, tbu_base: 0x%llx", tbu_base);

	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION uCR;
	SOC_SMMUv3_TBU_SMMU_TBU_CRACK_UNION uCRACK;

	uCR.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));

	uCR.reg.clk_gt_ctrl = 0x2;
	uCR.reg.tbu_en_req = 0x1;
	hisi_writel(uCR.value, SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));

	do {
		uCRACK.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(tbu_base));
		if (uCRACK.reg.tbu_en_ack == 0x1)
			break;

		npu_udelay(1);
		timeout--;

	} while (timeout > 0);

	uCRACK.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(tbu_base));
	if (uCRACK.reg.tok_trans_gnt < max_tok_trans) {
		NPU_DRV_ERR("uCRACK.reg.tok_trans_gnt = %d, tbu powerup fail for not enough connect!\r\n", uCRACK.reg.tok_trans_gnt);
		return -3;
	}

	if (timeout == 0) {
		NPU_DRV_ERR("tbu powerup fail for not ack!\r\n");
		return -1;
	}

	if (uCRACK.reg.tbu_connected != 0x1) {
		NPU_DRV_ERR("tbu powerup fail for not connect!\r\n");
		return -2;
	}

	uCR.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));
	uCR.reg.clk_gt_ctrl = 0x1;
	hisi_writel(uCR.value, SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));

	NPU_DRV_INFO("Exit atf_npu_subsys_tbu_power_up");
	return 0;
}

int npu_smmu_tbu_set_swid(uint32_t tbu_base) //atf_npu_smmu_tbu_set_swid
{
	int prefslot_full_level = 0;
	int fetchslot_full_level = 0;
	int aicore_swid = 0; // aicore_swid: 0~15
	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION uCR;
	SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_UNION swid_cfg;

	switch(tbu_base)
	{
		case SOC_ACPU_ts_tbu_BASE_ADDR:
			prefslot_full_level = 8;
			fetchslot_full_level = 8;
			break;
		case SOC_ACPU_aic0_smmu_cfg_BASE_ADDR:
		case SOC_ACPU_aic1_smmu_cfg_BASE_ADDR:
			prefslot_full_level = 24;
			fetchslot_full_level = 24;
			break;
		default:
			break;
	}
	/* ???????? */
	uCR.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));
	uCR.reg.prefslot_full_level = prefslot_full_level;
	uCR.reg.fetchslot_full_level = fetchslot_full_level;
	hisi_writel(uCR.value, SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));

	for (; aicore_swid < 16; aicore_swid++) {
		swid_cfg.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(tbu_base, aicore_swid));
		swid_cfg.reg.pref_en = 1;
		hisi_writel(swid_cfg.value, SOC_SMMUv3_TBU_SMMU_TBU_SWID_CFG_ADDR(tbu_base, aicore_swid));
	}

	NPU_DRV_INFO("Exit atf_npu_smmu_tbu_set_swid");
	return 0;
}

int npu_subsys_hwts_change_to_unsec(void)
{
	NPU_DRV_INFO("change hwts regs to non-sec,");
	SOC_NPU_HWTS_HWTS_SEC_EN_UNION uHWTSSec;
	uHWTSSec.value = npu_read64(SOC_NPU_HWTS_HWTS_SEC_EN_ADDR(SOC_ACPU_hwts_BASE_ADDR));
	npu_write64(uHWTSSec.value, SOC_NPU_HWTS_HWTS_SEC_EN_ADDR(SOC_ACPU_hwts_BASE_ADDR));
	return 0;
}

static void npu_power_up_smmu_tbu_hwts_ts()
{
	/* set hwts/arc smmu sid */
	SOC_NPU_TS_SYSCTRL_SC_PERCTRL5_UNION ts_ctrl5;
	ts_ctrl5.reg.hwts_smmu_awsid = 0x3F; //hwts sid
	ts_ctrl5.reg.hwts_smmu_arsid = 0x3F; //hwts sid
	ts_ctrl5.reg.arc_smmu_awsid = 0x3F; //arc sid
	ts_ctrl5.reg.arc_smmu_arsid = 0x3F; //arc sid
	NPU_DRV_DEBUG("addr = 0x%llx, awsid = 0x%x, arsid = 0x%x",
					SOC_NPU_TS_SYSCTRL_SC_PERCTRL5_ADDR(SOC_ACPU_tscpu_sysctrl_BASE_ADDR),
					ts_ctrl5.reg.hwts_smmu_awsid,
					ts_ctrl5.reg.hwts_smmu_arsid);
	hisi_writel(ts_ctrl5.value, SOC_NPU_TS_SYSCTRL_SC_PERCTRL5_ADDR(SOC_ACPU_tscpu_sysctrl_BASE_ADDR));

	/* set hwts smmu ssid, will get from smmu */
	SOC_NPU_TS_SYSCTRL_SC_PERCTRL6_UNION ts_ctrl6;
	ts_ctrl6.reg.hwts_smmu_awssid = 0x0; /* hwts ssid */
	ts_ctrl6.reg.hwts_smmu_arssid = 0x0; /* hwts ssid */
	ts_ctrl6.reg.arc_smmu_awssid = 0x0; /* arc ssid */
	ts_ctrl6.reg.arc_smmu_arssid = 0x0; /* arc ssid */
	NPU_DRV_DEBUG("addr = 0x%llx, awssid = 0x%x, arssid = 0x%x",
					SOC_NPU_TS_SYSCTRL_SC_PERCTRL6_ADDR(SOC_ACPU_tscpu_sysctrl_BASE_ADDR),
					ts_ctrl6.reg.hwts_smmu_awssid,
					ts_ctrl6.reg.hwts_smmu_arssid);
	hisi_writel(ts_ctrl6.value, SOC_NPU_TS_SYSCTRL_SC_PERCTRL6_ADDR(SOC_ACPU_tscpu_sysctrl_BASE_ADDR));

	/* set hwts smmu ssidv, will get from smmu */
	SOC_NPU_TS_SYSCTRL_SC_PERCTRL7_UNION ts_ctrl7;
	ts_ctrl7.reg.hwts_smmu_awssidv = 0x0; /* hwts ssidv */
	ts_ctrl7.reg.hwts_smmu_arssidv = 0x0; /* hwts ssidv */
	ts_ctrl7.reg.arc_smmu_awssidv = 0x0; /* arc ssidv */
	ts_ctrl7.reg.arc_smmu_arssidv = 0x0; /* arc ssidv */
	NPU_DRV_DEBUG("addr = 0x%llx, awssidv = 0x%x, arssidv = 0x%x",
					SOC_NPU_TS_SYSCTRL_SC_PERCTRL7_ADDR(SOC_ACPU_tscpu_sysctrl_BASE_ADDR),
					ts_ctrl7.reg.hwts_smmu_awssidv,
					ts_ctrl7.reg.hwts_smmu_awssidv);
	hisi_writel(ts_ctrl7.value, SOC_NPU_TS_SYSCTRL_SC_PERCTRL7_ADDR(SOC_ACPU_tscpu_sysctrl_BASE_ADDR));
}

static void npu_power_up_smmu_tbu_secure()
{
	// 1. secure0
	SOC_NPU_TS_SYSCTRL_SECURE0_UNION ts_ctrl_secure0;
	ts_ctrl_secure0.value = hisi_readl(SOC_NPU_TS_SYSCTRL_SECURE0_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	ts_ctrl_secure0.reg.ts_wdog_ns = 0x0;
	ts_ctrl_secure0.reg.ts_timer_ns = 0x0;
	ts_ctrl_secure0.reg.ts_sysctrl_ns = 0x0;
	ts_ctrl_secure0.reg.ts_its_ns = 0x0;
	ts_ctrl_secure0.reg.ts_aximon_arc_cbu_ns = 0x0;
	ts_ctrl_secure0.reg.ts_dmmu_cbu_ns = 0x0;
	ts_ctrl_secure0.reg.ts_dmmu_lbu_ns = 0x0;
	ts_ctrl_secure0.reg.ts_smmu_tbu_ns = 0x0;
	hisi_writel(ts_ctrl_secure0.value, SOC_NPU_TS_SYSCTRL_SECURE0_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	// 2. secure1
	SOC_NPU_TS_SYSCTRL_SECURE1_UNION ts_ctrl_secure1;
	ts_ctrl_secure1.reg.hwts_smmu_awsid_phy = 0x3E; /* hwts sid */
	ts_ctrl_secure1.reg.hwts_smmu_arsid_phy = 0x3E; /* hwts sid */
	ts_ctrl_secure1.reg.arc_smmu_awsid_phy = 0x3E; /* arc sid */
	ts_ctrl_secure1.reg.arc_smmu_arsid_phy = 0x3E; /* arc sid */
	hisi_writel(ts_ctrl_secure1.value, SOC_NPU_TS_SYSCTRL_SECURE1_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	// 3. secure2
	SOC_NPU_TS_SYSCTRL_SECURE2_UNION ts_ctrl_secure2;
	ts_ctrl_secure2.reg.hwts_smmu_awsid = 0x3E; /* hwts ssid */
	ts_ctrl_secure2.reg.hwts_smmu_arsid = 0x3E; /* hwts ssid */
	ts_ctrl_secure2.reg.arc_smmu_awsid = 0x3E; /* arc ssid */
	ts_ctrl_secure2.reg.arc_smmu_arsid = 0x3E; /* arc ssid */
	hisi_writel(ts_ctrl_secure2.value, SOC_NPU_TS_SYSCTRL_SECURE2_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	// 4. secure3
	SOC_NPU_TS_SYSCTRL_SECURE3_UNION ts_ctrl_secure3;
	ts_ctrl_secure3.reg.hwts_smmu_awssidv_phy = 0x0;
	ts_ctrl_secure3.reg.hwts_smmu_arssidv_phy = 0x0;
	ts_ctrl_secure3.reg.arc_smmu_awssidv_phy  = 0x0;
	ts_ctrl_secure3.reg.arc_smmu_arssidv_phy  = 0x0;
	ts_ctrl_secure3.reg.hwts_smmu_awssidv	  = 0x0;
	ts_ctrl_secure3.reg.hwts_smmu_arssidv	  = 0x0;
	ts_ctrl_secure3.reg.arc_smmu_awssidv	  = 0x0;
	ts_ctrl_secure3.reg.arc_smmu_arssidv	  = 0x0;
	hisi_writel(ts_ctrl_secure3.value, SOC_NPU_TS_SYSCTRL_SECURE3_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	// 5. secure4
	SOC_NPU_TS_SYSCTRL_SECURE4_UNION ts_ctrl_secure4;
	ts_ctrl_secure4.reg.arc_smmu_arssid  = 0x1;
	ts_ctrl_secure4.reg.arc_smmu_awssid  = 0x1;
	ts_ctrl_secure4.reg.hwts_smmu_arssid = 0x1;
	ts_ctrl_secure4.reg.hwts_smmu_awssid = 0x1;
	hisi_writel(ts_ctrl_secure4.value, SOC_NPU_TS_SYSCTRL_SECURE4_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	// 6. secure5
	SOC_NPU_TS_SYSCTRL_SECURE5_UNION ts_ctrl_secure5;
	ts_ctrl_secure5.reg.arc_arssid_phy  = 0x1;
	ts_ctrl_secure5.reg.arc_awssid_phy  = 0x1;
	ts_ctrl_secure5.reg.hwts_arssid_phy = 0x1;
	ts_ctrl_secure5.reg.hwts_awssid_phy = 0x1;
	hisi_writel(ts_ctrl_secure5.value, SOC_NPU_TS_SYSCTRL_SECURE5_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	// 7. secure6
	SOC_NPU_TS_SYSCTRL_SECURE6_UNION ts_ctrl_secure6;
	ts_ctrl_secure6.value = hisi_readl(SOC_NPU_TS_SYSCTRL_SECURE6_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
	ts_ctrl_secure6.reg.arc_cbu_awprot = 0x0;
	ts_ctrl_secure6.reg.arc_cbu_arprot = 0x0;
	ts_ctrl_secure6.reg.arc_lbu_awprot = 0x0;
	ts_ctrl_secure6.reg.arc_lbu_arprot = 0x0;
	hisi_writel(ts_ctrl_secure6.value, SOC_NPU_TS_SYSCTRL_SECURE6_ADDR(SOC_ACPU_ts_secure0_BASE_ADDR));
}

static void npu_set_hwts_sec_sid(void)
{
	const uint16_t AXPROT_SECURE_ACCESS = 0x0;
	const uint16_t NS_DISABLE = 0x0;

	SOC_NPU_HWTS_HWTS_NS_SETTING1_UNION ns_setting1;
	SOC_NPU_HWTS_HWTS_NS_SETTING2_UNION ns_setting2;
	SOC_NPU_HWTS_HWTS_S_SQ_AXPROT_SETTING1_UNION s_sq_axprot_setting1;
	SOC_NPU_HWTS_HWTS_S_SQ_AXPROT_SETTING2_UNION s_sq_axprot_setting2;

	ns_setting1.value = npu_read64(SOC_NPU_HWTS_HWTS_NS_SETTING1_ADDR(SOC_ACPU_hwts_BASE_ADDR));
	ns_setting1.reg.hwts_awns_write_value  = NS_DISABLE;
	ns_setting1.reg.hwts_awns_cq = NS_DISABLE;
	ns_setting1.reg.hwts_arns_sq = NS_DISABLE;
	npu_write64(ns_setting1.value, SOC_NPU_HWTS_HWTS_NS_SETTING1_ADDR(SOC_ACPU_hwts_BASE_ADDR));

	ns_setting2.value = npu_read64(SOC_NPU_HWTS_HWTS_NS_SETTING2_ADDR(SOC_ACPU_hwts_BASE_ADDR));
	ns_setting2.reg.hwts_arns_aic  = NS_DISABLE;
	ns_setting2.reg.hwts_awns_aic = NS_DISABLE;
	npu_write64(ns_setting2.value, SOC_NPU_HWTS_HWTS_NS_SETTING2_ADDR(SOC_ACPU_hwts_BASE_ADDR));

	s_sq_axprot_setting1.value = npu_read64(SOC_NPU_HWTS_HWTS_S_SQ_AXPROT_SETTING1_ADDR(SOC_ACPU_hwts_BASE_ADDR));
	s_sq_axprot_setting1.reg.s_sq_arprot_aic  = AXPROT_SECURE_ACCESS;
	s_sq_axprot_setting1.reg.s_sq_awprot_aic = AXPROT_SECURE_ACCESS;
	npu_write64(s_sq_axprot_setting1.value, SOC_NPU_HWTS_HWTS_S_SQ_AXPROT_SETTING1_ADDR(SOC_ACPU_hwts_BASE_ADDR));

	s_sq_axprot_setting2.value = npu_read64(SOC_NPU_HWTS_HWTS_S_SQ_AXPROT_SETTING2_ADDR(SOC_ACPU_hwts_BASE_ADDR));
	s_sq_axprot_setting2.reg.s_sq_awprot_write_value  = AXPROT_SECURE_ACCESS;
	s_sq_axprot_setting2.reg.s_sq_awprot_cq = AXPROT_SECURE_ACCESS;
	s_sq_axprot_setting2.reg.s_sq_arprot_sq = AXPROT_SECURE_ACCESS;
	npu_write64(s_sq_axprot_setting2.value, SOC_NPU_HWTS_HWTS_S_SQ_AXPROT_SETTING2_ADDR(SOC_ACPU_hwts_BASE_ADDR));

	NPU_DRV_INFO("npu_set_hwts_sec_sid done, setting2=%llx", npu_read64(SOC_NPU_HWTS_HWTS_S_SQ_AXPROT_SETTING2_ADDR(SOC_ACPU_hwts_BASE_ADDR)));
}

int npu_power_up_smmu_tbu()
{
	NPU_DRV_INFO("ts subsys tbu init and connect with tcu");
	(void)npu_subsys_tbu_connect(SOC_ACPU_ts_tbu_BASE_ADDR);
	(void)npu_smmu_tbu_set_swid(SOC_ACPU_ts_tbu_BASE_ADDR);
	(void)npu_subsys_hwts_change_to_unsec(); /* do nothing */

	/* set hwts/arc non secure */
	npu_power_up_smmu_tbu_hwts_ts();

	/* set hwts/arc secure */
	npu_power_up_smmu_tbu_secure();

	/* set hwts secsid */
	npu_set_hwts_sec_sid();

	NPU_DRV_WARN("npu_power_up_smmu_tbu success");

	return 0;
}

int npu_subsys_tbu_power_down(uint32_t tbu_base)
{
	uint32_t timeout = 1000;

	SOC_SMMUv3_TBU_SMMU_TBU_CR_UNION uCR;
	SOC_SMMUv3_TBU_SMMU_TBU_CRACK_UNION uCRACK;

	uCR.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));
	uCR.reg.tbu_en_req = 0x0;
	hisi_writel(uCR.value, SOC_SMMUv3_TBU_SMMU_TBU_CR_ADDR(tbu_base));
	NPU_DRV_DEBUG("npu_subsys_tbu_power_down, tbu_base: %p", (void *)tbu_base);

	do {
		uCRACK.value = hisi_readl(SOC_SMMUv3_TBU_SMMU_TBU_CRACK_ADDR(tbu_base));
		if (uCRACK.reg.tbu_en_ack == 0x1)
			break;

		npu_udelay(1);
		timeout--;

	} while (timeout > 0);

	if (timeout == 0) {
		NPU_DRV_ERR("tbu power down fail for not ack!\r\n");
		return -1;
	}

	if (uCRACK.reg.tbu_connected != 0x0) {
		NPU_DRV_ERR("tbu power down fail for still connect!\r\n");
		return -2;
	}

	return 0;
}

int npu_power_down_smmu_tbu()
{
	(void)npu_subsys_tbu_power_down(SOC_ACPU_ts_tbu_BASE_ADDR);
	if (npu_plat_aicore_get_disable_status(0) == 0)
		(void)npu_subsys_tbu_power_down(SOC_ACPU_aic0_smmu_cfg_BASE_ADDR);
	if (npu_plat_aicore_get_disable_status(1) == 0)
		(void)npu_subsys_tbu_power_down(SOC_ACPU_aic1_smmu_cfg_BASE_ADDR);

	return 0;
}

static void npu_set_sec_aicore_smmu(uint16_t sid, uint16_t ssidv, uint32_t base)
{
	/* set sid */
	SOC_NPU_AICORE_SMMU_SEC_STREAMID_UNION stream_id_cfg = {0};
	stream_id_cfg.value = npu_read64(SOC_NPU_AICORE_SMMU_SEC_STREAMID_ADDR(base));
	stream_id_cfg.reg.smmu_sec_strmid_unbp = sid;
	npu_write64(stream_id_cfg.value, SOC_NPU_AICORE_SMMU_SEC_STREAMID_ADDR(base));

	/* set ssidv */
	SOC_NPU_AICORE_BIU_SMMU_CFG_UNION ssidv_cfg = {0};
	ssidv_cfg.value = npu_read64(SOC_NPU_AICORE_BIU_SMMU_CFG_ADDR(base));
	ssidv_cfg.reg.smmu_ssidv_unbp = ssidv;
	npu_write64(ssidv_cfg.value, SOC_NPU_AICORE_BIU_SMMU_CFG_ADDR(base));
}

int npu_plat_power_up(void *svm_dev)
{
    struct sec_smmu_para *svm_para_list = NULL;
	uint32_t ta_pid = 0;
	int ret;
	uint32_t power_status;

	NPU_DRV_INFO("npu_plat_power_up enter");
	if (svm_dev == NULL) {
		NPU_DRV_ERR("svm para list is null");
		return -1;
	}

	power_status = npu_pm_query_power_status();
	if (power_status != DRV_NPU_POWER_ON_SEC_FLAG) {
		NPU_DRV_ERR("npu status=%d is not in sec power-on, unable to powerup smmu", power_status);
		return -1;
	}

	svm_para_list = (struct sec_smmu_para *)svm_dev;
	svm_para_list->smmuid = SMMU_NPU;
	svm_para_list->sid = SECSMMU_STREAMID_NPU;
	/* power on sdma/aicore smmu */
    NPU_DRV_INFO("start SVM_SEC_CMD_POWER_ON");

	ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_ON, svm_para_list);
	if (ret) {
		NPU_DRV_ERR("tee npu sdma smmu svm power on failed, ret = %d", ret);
		return ret;
	}

	NPU_DRV_INFO("SVM_SEC_CMD_POWER_ON success, ssid=%p, ttbr=%p, tcr=%p", (void *)svm_para_list->ssid, (void *)svm_para_list->ttbr, (void *)svm_para_list->tcr);

	ret = npu_power_up_smmu_tbu();
	if (ret)
		NPU_DRV_ERR("tee npu sdma smmu tbu power on failed, ret = %d", ret);

	ret = SRE_TaskSelf(&ta_pid);
	if (ret < 0) {
		NPU_DRV_ERR("get ta pid failed in %s\n", __func__);
		goto get_ta_pid_failed;
	}

	/* bind tee task */
	svm_para_list->pid = ta_pid; /* is ta pid or drv pid ? */
	ret = __teesvm_ioctl(SVM_SEC_CMD_BIND, svm_para_list);
	if (ret) {
		NPU_DRV_ERR("tee npu task bind failed, ret = %d", ret);
		goto smmu_bind_failed;

	}

	NPU_DRV_INFO("SVM_SEC_CMD_BIND ssid=%p, ttbr=%p, tcr=%p", (void *)svm_para_list->ssid, (void *)svm_para_list->ttbr, (void *)svm_para_list->tcr);

	/* now ssid is created, and should set to HWTS sq (aicore) SET AICORE SID, SSID, SSIDV */
	if (npu_plat_aicore_get_disable_status(0) == 0)
		npu_set_sec_aicore_smmu(SECSMMU_STREAMID_NPU, 1, SOC_ACPU_aic0_subsys_cfg_BASE_ADDR);
	if (npu_plat_aicore_get_disable_status(1) == 0)
		npu_set_sec_aicore_smmu(SECSMMU_STREAMID_NPU, 1, SOC_ACPU_aic1_subsys_cfg_BASE_ADDR);

	ret = npu_hwts_irq_init();
	if (ret) {
		NPU_DRV_ERR("npu hwts_irq_init failed, ret = %d", ret);
		goto hwts_irq_init_failed;
	}

	NPU_DRV_INFO("npu_plat_power_up success");
	return 0;

hwts_irq_init_failed:
	if (__teesvm_ioctl(SVM_SEC_CMD_UNBIND, svm_para_list))
		NPU_DRV_ERR("tee hisi npu task unbind failed");
smmu_bind_failed:
get_ta_pid_failed:
	svm_para_list->smmuid = SMMU_NPU;
	svm_para_list->sid = SECSMMU_STREAMID_NPU;
	if (__teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list)) {
		NPU_DRV_ERR("aicore_smmu_poweron_failed teesvm_ioctl SVM_SEC_CMD_POWER_OFF failed");
	}
	return ret;
}

int npu_plat_power_down(void *svm_dev)
{
	struct sec_smmu_para *svm_para_list = NULL;
	int svm_clear_ret;
	uint32_t power_status;
	int unbind_ret;
	int sdma_ret;

	NPU_DRV_INFO("enter");
	if (svm_dev == NULL) {
		NPU_DRV_ERR("svm para list is null");
		return -1;
	}
	npu_hwts_irq_reset();

	svm_para_list = (struct sec_smmu_para *)svm_dev;
	svm_para_list->sid = SECSMMU_STREAMID_NPU;

	power_status = npu_pm_query_power_status();
	if (power_status != DRV_NPU_POWER_ON_SEC_FLAG) {
		NPU_DRV_ERR("npu is power down");
		// clear svm
		svm_clear_ret = __teesvm_ioctl(SVM_SEC_CMD_CLEAR_RES, svm_para_list);
		if (svm_clear_ret) {
			NPU_DRV_ERR("npu svm clear failed, ret = %d", svm_clear_ret);
		}

		return 0;
	}

	/* unbind tee task */
	unbind_ret = __teesvm_ioctl(SVM_SEC_CMD_UNBIND, svm_para_list);
	if (unbind_ret) {
		NPU_DRV_ERR("tee npu task bind failed, ret = %d", unbind_ret);
	}

	svm_para_list->smmuid = SMMU_NPU;

	sdma_ret = npu_power_down_smmu_tbu();
	if (sdma_ret) {
		NPU_DRV_ERR("tee npu sdma smmu tbu power down failed, ret = %d", sdma_ret);
	}
	/* power off sdma/aicore smmu */
	sdma_ret = __teesvm_ioctl(SVM_SEC_CMD_POWER_OFF, svm_para_list);
	if (sdma_ret)
		NPU_DRV_ERR("tee npu sdma smmu svm power off failed, ret = %d", sdma_ret);

	if (unbind_ret != 0 || sdma_ret != 0) {
		unbind_ret = (int)(unbind_ret + sdma_ret);
		NPU_DRV_ERR("tee smmu power off failed. ret = %d\n",unbind_ret);
	}

	NPU_DRV_INFO("success");
	return 0;
}

