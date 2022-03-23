/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: secure os teesvm module
 * Teesvm main functions
 * Create: 2019-12-26
 */
#include "pthread.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "drv_module.h"
#include "drv_mem.h" /* sre_mmap */
#include "drv_pal.h" /* task_caller */
#include "securec.h"
#include "list.h"
#include "cc_bitops.h"
#include "hm_unistd.h"
#include "sre_hwi.h" /* HWI_PROC_FUNC */
#include "secure_gic_common.h" /* INT_SECURE */
#include "hisi_teesvm_internal.h"
#include "drv_param_type.h"

#define hisi_get_smmu_platform_info(smmuid, platform_info)  \
	do {                                                    \
		platform_info.base = HISI_SMMUV3_BASE_##smmuid;     \
		platform_info.smmu_irq = HISI_SMMUV3_IRQ_##smmuid;  \
		platform_info.sid_bypass_wr_ai =            \
			HISI_SMMUV3_BYPASS_WR_AI_##smmuid;      \
		platform_info.sid_bypass_rd_ai =            \
			HISI_SMMUV3_BYPASS_RD_AI_##smmuid;      \
		platform_info.sid_bypass_wr_sdma =          \
			HISI_SMMUV3_BYPASS_WR_SDMA_##smmuid;    \
		platform_info.sid_bypass_rd_sdma =          \
			HISI_SMMUV3_BYPASS_RD_SDMA_##smmuid;    \
		platform_info.sid_mstr0_end0_val =          \
			HISI_SMMUV3_MSTR0_END0_VAL_##smmuid;    \
		platform_info.sid_mstr0_end1_val =          \
			HISI_SMMUV3_MSTR0_END1_VAL_##smmuid;    \
		platform_info.sid_mstr1_end0_val =          \
			HISI_SMMUV3_MSTR1_END0_VAL_##smmuid;    \
		platform_info.sid_mstr1_end1_val =          \
			HISI_SMMUV3_MSTR1_END1_VAL_##smmuid;    \
	} while (0)

static int hisi_sec_smmu_pgtable_cfg(
	struct hisi_sec_smmu_domain *smmu_domain, struct hisi_tee_svm *svm)
{
	int ret, lock_ret;
	struct hisi_tee_smmu_group *smmu_group = NULL;

	smmu_group = smmu_domain->smmu_grp;
	if (!smmu_group) {
		tloge("%s smmu_group is null\n", __func__);
		return -EINVAL;
	}
	lock_ret = pthread_mutex_lock(&smmu_group->sgrp_mtx);
	if (lock_ret) {
		tloge("%s: pthread_mutex_lock fail\n", __func__);
		return lock_ret;
	}

	ret = hisi_sec_smmu_domain_finalise(smmu_domain, svm);
	if (ret)
		goto out_unlock;

	/* enable cd */
	hisi_sec_smmu_enable_cd(smmu_group, smmu_domain);

out_unlock:
	lock_ret = pthread_mutex_unlock(&smmu_group->sgrp_mtx);
	if (lock_ret) {
		tloge("%s: pthread_mutex_unlock fail\n", __func__);
		return lock_ret;
	}

	return ret;
}

static int hisi_sec_smmu_pgtable_uncfg(
	struct hisi_sec_smmu_domain *smmu_domain)
{
	struct hisi_tee_smmu_group *smmu_group = NULL;
	int ret;

	if (!smmu_domain) {
		tloge("domain is null %s\n", __func__);
		return -EINVAL;
	}

	smmu_group = smmu_domain->smmu_grp;
	if (!smmu_group) {
		tloge("smmu_group is null %s\n", __func__);
		return -EINVAL;
	}

	ret = pthread_mutex_lock(&smmu_group->sgrp_mtx);
	if (ret) {
		tloge("%s: pthread_mutex_lock fail\n", __func__);
		return ret;
	}
	hisi_sec_smmu_domain_draft(smmu_domain);
	/* Invalidate the ctx desc table */
	hisi_sec_smmu_disable_cd(smmu_group, smmu_domain);

	ret = pthread_mutex_unlock(&smmu_group->sgrp_mtx);
	if (ret) {
		tloge("%s: pthread_mutex_unlock fail\n", __func__);
		return ret;
	}
	return 0;
}

/*
 * Because Hisilicon SVM with AI CPU
 * 1.realise the page fault function
 * 2.realise debug function of AI CPU
 */
void hisi_mmu_gerror_handler(void)
{
	u32 asid;
	u64 vaddr;
	int ret;

	if (g_pgfault_asid_addr && g_hisi_mmu_dev->asid_mem_base) {
		asid = *((u32 *)(uintptr_t)g_hisi_mmu_dev->asid_mem_base);
		tloge("%s: page fault,asid:0x%x\n", __func__, asid);
	}

	if (g_pgfault_va_addr_g && g_hisi_mmu_dev->va_mem_base) {
		vaddr = *((u64 *)(uintptr_t)g_hisi_mmu_dev->va_mem_base);
		tloge("%s: fault:0x%llx\n", __func__, vaddr);
		ret = hm_dump_pagetable(hm_getpid(), vaddr, SZ_4K);
		if (!ret)
			tloge("\t error dump:0x%llx ret:0x%x\n", vaddr, ret);
	}
}

/* IRQ and event handlers */
static void hisi_sec_smmu_evtq_handler(void *dev)
{
	struct hisi_sec_smmu_device *smmu = dev;
	struct hisi_sec_smmu_queue *q = &smmu->evtq.q;

	/*
	 * Not much we can do on overflow, so scream and pretend we're
	 * trying harder.
	 */
	if (queue_sync_prod(q) == -EOVERFLOW)
		tloge("smmuid:%d EVTQ overflow detected -- events lost\n",
			smmu->smmuid);
	else if (queue_empty(q)) {
		tloge("smmuid:%d EVTQ empty!\n", smmu->smmuid);
		return;
	}

	hisi_evt_flag_set(smmu);
	pthread_cond_signal(&smmu->evt_happen);
}

static int hisi_sec_smmu_cmdq_sync_handler(void)
{
	/* We don't actually use CMD_SYNC interrupts for anything */
	return 0;
}

static void hisi_sec_smmu_gerror_handler(void *dev)
{
	u32 gerror, gerrorn;
	struct hisi_sec_smmu_device *smmu = dev;

	gerror = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_GERROR_S);
	gerrorn = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_GERRORN_S);

	gerror ^= gerrorn;
	if (!(gerror & HISI_SEC_GERROR_ERR_MASK))
		return; /* No errors pending */

	tloge("smmuid:%d unexpected global error reported (0x%08x), this could be serious\n",
		smmu->smmuid, gerror);

	if (gerror & HISI_SEC_GERROR_SFM_ERR) {
		tloge("smmuid:%d device has entered Service Failure Mode!\n",
			smmu->smmuid);
		hisi_sec_smmu_device_disable(smmu);
	}

	if (gerror & HISI_SEC_GERROR_MSI_GERROR_ABT_ERR)
		tloge("smmuid:%d GERROR MSI write aborted\n", smmu->smmuid);

	if (gerror & HISI_SEC_GERROR_MSI_PRIQ_ABT_ERR)
		tloge("smmuid:%d PRIQ MSI write aborted\n", smmu->smmuid);

	if (gerror & HISI_SEC_GERROR_MSI_EVTQ_ABT_ERR)
		tloge("smmuid:%d EVTQ MSI write aborted\n", smmu->smmuid);

	if (gerror & HISI_SEC_GERROR_MSI_CMDQ_ABT_ERR) {
		tloge("smmuid:%d CMDQ MSI write aborted\n", smmu->smmuid);
		hisi_sec_smmu_cmdq_sync_handler();
	}

	if (gerror & HISI_SEC_GERROR_PRIQ_ABT_ERR)
		tloge("smmuid:%d PRIQ write aborted -- events may have been lost\n",
			smmu->smmuid);

	if (gerror & HISI_SEC_GERROR_EVTQ_ABT_ERR)
		tloge("smmuid:%d EVTQ write aborted -- events may have been lost\n",
			smmu->smmuid);

	if (gerror & HISI_SEC_GERROR_CMDQ_ERR)
		hisi_sec_smmu_cmdq_skip_err(smmu);

	hisi_writel(gerror, smmu->platform_info.base + HISI_SEC_SMMU_GERRORN_S);
}

static void hisi_sec_smmu_global_handler(HWI_ARG_T data)
{
	u32 irq_status;
	u32 raw_irq_status;
	u32 reg = (TCU_EVENT_Q_IRQ_CLR | TCU_CMD_SYNC_IRQ_CLR |
		   TCU_GERROR_IRQ_CLR);
	struct hisi_sec_smmu_device *smmu = (struct hisi_sec_smmu_device *)(uintptr_t)data;

	if (!smmu || (smmu->status != hisi_sec_smmu_enable))
		return;

	irq_status = hisi_readl(smmu->platform_info.base + SMMU_IRPT_STAT_S);
	raw_irq_status = hisi_readl(smmu->platform_info.base + SMMU_IRPT_RAW_S);
	tloge("into %s,status:0x%x,raw_status:0x%x\n", __func__,
		irq_status, raw_irq_status);
	hisi_writel(reg, smmu->platform_info.base + SMMU_IRPT_CLR_S);
	if (irq_status & TCU_EVENT_Q_IRQ)
		hisi_sec_smmu_evtq_handler(smmu);
	if (irq_status & TCU_CMD_SYNC_IRQ)
		hisi_sec_smmu_cmdq_sync_handler();
	if (irq_status & TCU_GERROR_IRQ)
		hisi_sec_smmu_gerror_handler(smmu);
}

static int hisi_smmu_setup_irqs(struct hisi_sec_smmu_device *smmu)
{
	int ret, irq;

	ret = pthread_mutex_init(&smmu->evt_lock, NULL);
	if (ret) {
		tloge("smmuid:%d evt_lock init failed\n", smmu->smmuid);
		return ret;
	}

	irq = smmu->platform_info.smmu_irq;
	if (irq) {
		ret = SRE_HwiCreate(irq, 0x0, INT_SECURE,
			hisi_sec_smmu_global_handler, (HWI_ARG_T)(uintptr_t)smmu);
		if (ret) {
			tloge("smmuid:%d failed to enable global irq\n",
				smmu->smmuid);
			return ret;
		}

		ret = SRE_HwiEnable(irq);
		if (ret) {
			tloge("smmuid:%d failed to enable global irq\n",
				smmu->smmuid);
			return ret;
		}

		ret = hisi_evt_irq_setup(smmu);
		if (ret) {
			tloge("smmuid:%d hisi_evt_irq_setup failed!\n",
				smmu->smmuid);
			return ret;
		}
	}
	return 0;
}

static int hisi_sec_tee_smmu_device_init(enum hisi_svm_id smmuid)
{
	int ret;
	struct hisi_sec_smmu_device *smmu = NULL;

	if (smmuid >= svm_max) {
		tloge("smmuid:%d invalid, max:%d, in %s\n", smmuid, svm_max,
			__func__);
		return -ENOMEM;
	}

	smmu = malloc_coherent(sizeof(*smmu));
	if (!smmu) {
		tloge("smmuid:%d %s:failed to alloc mem for smmu\n", smmuid,
			__func__);
		return -ENOMEM;
	}
	(void)memset_s(smmu, sizeof(*smmu), 0, sizeof(*smmu));

	smmu->smmuid = smmuid;

	switch (smmuid) {
	case 0: {
		hisi_get_smmu_platform_info(0, smmu->platform_info);
		break;
	}
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
	case 1: {
		hisi_get_smmu_platform_info(1, smmu->platform_info);
		break;
	}
#if defined(WITH_KIRIN990_CS2)
	case 2: {
		hisi_get_smmu_platform_info(2, smmu->platform_info);
		break;
	}
#endif
#endif
	default:
		tloge("smmuid invalid:%d\n", smmuid);
		return -ENOMEM;
	}

	list_add(&smmu->smmu_node, &g_hisi_tee_smmu_group->smmu_list);

	ret = hisi_smmu_setup_irqs(smmu);
	if (ret) {
		tloge("smmuid:%d hisi_smmu_setup_irqs failed\n", smmu->smmuid);
		return ret;
	}

	return 0;
}


static int hisi_smmu_mutex_init(void)
{
	int ret;

	ret = pthread_mutex_init(&g_hisi_svm_mutex, NULL);
	if (ret) {
		tloge("%s: g_hisi_svm_mutex init fail\n", __func__);
		return ret;
	}
	ret = pthread_mutex_init(&g_hisi_svmtlb_mutex, NULL);
	if (ret) {
		tloge("%s: g_hisi_svmtlb_mutex init fail\n", __func__);
		return ret;
	}
	return 0;
}

static int hisi_tee_smmu_group_init(void)
{
	u64 size;
	struct hisi_tee_smmu_group *grp = NULL;
	int ret;

	grp = malloc_coherent(sizeof(*grp));
	if (!grp) {
		tloge("failed to allocate g_hisi_tee_smmu_group\n");
		return -ENOMEM;
	}
	(void)memset_s(grp, sizeof(*grp), 0, sizeof(*grp));

	INIT_LIST_HEAD(&grp->smmu_list);

	grp->oas = HISI_SMMU_ADDR_SIZE_48;
	grp->ias = HISI_SMMU_ADDR_SIZE_48;

	grp->ssid_bits = HISI_SEC_IDR1_SSID_BITS;

	/*
	 * Allocation of the cd desc table.
	 * And all cd descs are invalid.
	 */
	size = (1UL << grp->ssid_bits) * (CTXDESC_CD_DWORDS << DWORD_BYTES_NUM);
	if (size > SZ_2K) {
		tloge("cd size more than 2K!ssid_bits:%u\n", grp->ssid_bits);
		return -ENOMEM;
	}

	if (sre_mmap(g_smmu_cd_base, size, (u32 *)(uintptr_t)&(grp->cdtab_cfg.cdtab), secure, non_cache) ||
		memset_s(grp->cdtab_cfg.cdtab, size, 0, size)) {
		tloge("smmu cd mmap fail!!\n");
		return -ENOMEM;
	}

	grp->cdtab_cfg.cdtab_phy = g_smmu_cd_base;

	grp->cdtab_cfg.sz = size;
	/* The phy base always aligned 4K */
	if (!IS_ALIGNED(grp->cdtab_cfg.cdtab_phy, PAGE_SIZE))
		tloge("cdtab_phy is not alined to pagesize\n");

	/*
	 * Because cd descs are invalid so,
	 * and ste is valid and bypass.
	 */
	ret = pthread_mutex_init(&grp->sgrp_mtx, NULL);
	if (ret) {
		tloge("%s: pthread_mutex_init fail\n", __func__);
		return ret;
	}

	if (test_and_set_bit(0, grp->ssid_map))
		tloge("test_and_set_bit failed\n");

	/* Record our private device structure */
	grp->status = hisi_sec_smmu_enable;
	ret = hisi_smmu_mutex_init();
	if (ret) {
		tloge("%s: hisi_smmu_mutex_init fail\n", __func__);
		return ret;
	}
	g_hisi_tee_smmu_group = grp;

	return 0;
}


int hisi_smmu_rsvmem_get(void)
{
	uintptr_t rsv_start;
	u32 len = 0;
	int ret;

	ret = npu_get_res_mem_of_smmu(&rsv_start, &len);
	if (ret || (len < HISI_SMMU_RSV_TOTAL_SIZE)) {
		tloge("get rsv fail!len:%u, ret:%d\n", len, ret);
		return -ENOMEM;
	}

	g_smmu_cmdq_base = rsv_start;
	g_smmu_eventq_base = g_smmu_cmdq_base + HISI_SMMU_CMDQ_SIZE;
	g_smmu_ste_base = g_smmu_eventq_base + HISI_SMMU_EVTQ_SIZE;
	g_smmu_cd_base = g_smmu_ste_base + HISI_SMMU_STE_SIZE;

	tloge("get succ!0x%x,0x%x,0x%x,0x%x\n", g_smmu_cmdq_base,
		g_smmu_eventq_base, g_smmu_ste_base, g_smmu_cd_base);

	return ret;
}

static int hisi_mmu_device_init(void)
{
	int ret;
	struct hisi_sec_smmu_device *hisi_mmu = NULL;

	hisi_mmu = malloc_coherent(sizeof(*hisi_mmu));
	if (!hisi_mmu) {
		tloge("%s failed to allocate hisi_sec_smmu_device\n", __func__);
		return -ENOMEM;
	}
	(void)memset_s(hisi_mmu, sizeof(*hisi_mmu), 0, sizeof(*hisi_mmu));

	/*
	 * Base fake register address
	 * Just for with AI CPU communication
	 */
	hisi_mmu->gerr_irq = HISI_AICPU_IRQ;

	ret = SRE_HwiCreate(HISI_AICPU_IRQ, 0x0,
		INT_SECURE, (HWI_PROC_FUNC)hisi_mmu_gerror_handler, 0);
	if (ret) {
		tloge("failed to enable aicpu irq: %d\n", ret);
		return ret;
	}

	hisi_mmu->status = hisi_sec_smmu_enable;
	g_hisi_mmu_dev = hisi_mmu;

	hisi_aicpu_intr_addr_remap();

	return 0;
}

s32 tee_svm_init(void)
{
	if (hisi_smmu_rsvmem_get()) {
		tloge("hisi_smmu_rsvmem_get fail\n");
		return -EINVAL;
	}

	if (hisi_tee_smmu_group_init()) {
		tloge("hisi_tee_smmu_group_init fail\n");
		return -EINVAL;
	}

	for (int i = 0; i < svm_max; i++) {
		if (hisi_sec_tee_smmu_device_init(i)) {
			tloge("hisi_sec_tee_smmu_device_init smmu%d fail\n", i);
			return -EINVAL;
		}
	}

	if (hisi_mmu_device_init()) {
		tloge("hisi_mmu_device_init fail\n");
		return -EINVAL;
	}

	tloge("%s success!\n", __func__);
	return 0;
}

static int hisi_smmu_poweron(struct tee_svm_para_list *mcl)
{
	int ret;
	unsigned int smmuid = mcl->smmuid;
	enum hisi_sec_smmu_status status_temp;
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *smmu = NULL;
	struct hisi_sec_smmu_device *tmp = NULL;

	tlogd("in %s,smmuid:%d\n", __func__, smmuid);

	if (smmuid >= svm_max) {
		tloge("invalid params!%s\n", __func__);
		return -EINVAL;
	}

	list_for_each_safe(p, n, &g_hisi_tee_smmu_group->smmu_list) {
		tmp = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (tmp && (tmp->smmuid == smmuid) &&
			(tmp->status != hisi_sec_smmu_enable)) {
			smmu = tmp;
			break;
		}
	}

	if (!smmu) {
		tloge("smmuid %d not found!%s\n", smmuid, __func__);
		return -EINVAL;
	}

	if (hisi_smmu_poweron_reg_set(smmu))
		return -EINVAL;

	status_temp = smmu->status;
	smmu->status = hisi_sec_smmu_enable;
	ret = hisi_sec_smmu_hw_set(smmu);
	if (ret) {
		smmu->status = status_temp;
		tloge("hisi_sec_smmu_hw_set failed !%s\n", __func__);
		return -EINVAL;
	}

	smmu->status = hisi_sec_smmu_enable;

	tlogd("out %s\n", __func__);

	return 0;
}


static int hisi_svm_bind_task(struct tee_svm_para_list *mcl)
{
	pid_t pid = mcl->pid;
	struct hisi_tee_svm *svm = NULL;
	struct hisi_sec_smmu_domain *smmu_domain = NULL;
	struct vsroot_info_t tee_task_info;
	int ret;

	tlogd("into %s\n", __func__);

	ret = pthread_mutex_lock(&g_hisi_svm_mutex);
	if (ret) {
		tloge("%s: pthread_mutex_lock fail\n", __func__);
		return ret;
	}
	if (g_hisi_svm_bind) {
		tloge("%s: pls unbind last svm!\n", __func__);
		goto out;
	}

	svm = malloc_coherent(sizeof(*svm));
	if (!svm) {
		tloge("%s malloc_coherent failed!\n", __func__);
		goto out;
	}

	(void)memset_s(svm, sizeof(*svm), 0, sizeof(*svm));

	smmu_domain = hisi_sec_smmu_domain_alloc();
	if (!smmu_domain) {
		tloge("%s smmu_domain_alloc failed!\n", __func__);
		goto out_free;
	}
	svm->smmu_domain = smmu_domain;

	if ((hm_get_vsrootinfo(pid, &tee_task_info))) {
		tloge("%s hm_get_vsrootinfo failed!\n", __func__);
		goto dom_free;
	}

	svm->pid = pid;
	svm->pgd = tee_task_info.pud;
	svm->asid = tee_task_info.asid;

	if (hisi_sec_smmu_pgtable_cfg(smmu_domain, svm)) {
		tloge("%s hisi_sec_smmu_pgtable_cfg failed!\n", __func__);
		goto dom_free;
	}

	g_hisi_svm_bind = svm;
	mcl->tee_svm_p = svm;
	tlogd("out %s\n", __func__);
	ret = pthread_mutex_unlock(&g_hisi_svm_mutex);
	if (ret) {
		tloge("%s: pthread_mutex_unlock fail\n", __func__);
		return ret;
	}

	return 0;

dom_free:
	hisi_sec_smmu_domain_free(smmu_domain);

out_free:
	free(svm);

out:
	(void)pthread_mutex_unlock(&g_hisi_svm_mutex);
	tloge("error out %s\n", __func__);
	hisi_tee_svm_dump_reg();

	return -EINVAL;
}

static void hisi_svm_unbind_task(struct tee_svm_para_list *mcl)
{
	struct hisi_tee_svm *svm = mcl->tee_svm_p;
	int ret;

	tlogd("into %s\n", __func__);

	if (!svm) {
		tloge("%s:svm NULL\n", __func__);
		return;
	}

	ret = pthread_mutex_lock(&g_hisi_svm_mutex);
	if (ret) {
		tloge("%s: pthread_mutex_lock fail\n", __func__);
		return;
	}
	if (!g_hisi_svm_bind || (g_hisi_svm_bind != svm)) {
		tloge("%s:svm invalid\n", __func__);
		(void)pthread_mutex_unlock(&g_hisi_svm_mutex);
		return;
	}

	if (hisi_sec_smmu_pgtable_uncfg(svm->smmu_domain)) {
		tloge("%s: fail\n", __func__);
		(void)pthread_mutex_unlock(&g_hisi_svm_mutex);
		return;
	}
	hisi_sec_smmu_domain_free(svm->smmu_domain);

	free(svm);
	g_hisi_svm_bind = NULL;
	ret = pthread_mutex_unlock(&g_hisi_svm_mutex);
	if (ret)
		tloge("%s: pthread_mutex_unlock fail\n", __func__);

	tlogd("out %s\n", __func__);
}

static int hisi_smmu_poweroff(struct tee_svm_para_list *mcl)
{
	int ret, lock_ret;
	unsigned int smmuid = mcl->smmuid;
	struct hisi_sec_smmu_device *smmu = NULL;

	tlogd("%s, smmuid:%d\n", __func__, smmuid);
	if (smmuid >= svm_max) {
		tloge("invalid params!%s\n", __func__);
		return -EINVAL;
	}

	smmu = hisi_smmu_poweroff_find_smmu(smmuid);
	if (!smmu) {
		tloge("smmuid %d not found!%s\n", smmuid, __func__);
		return -EINVAL;
	}

	lock_ret = pthread_mutex_lock(&g_hisi_svmtlb_mutex);
	if (lock_ret) {
		tloge("%s: pthread_mutex_lock fail\n", __func__);
		return lock_ret;
	}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER && \
	TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_LAGUNA && \
	TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_BURBANK)
	ret = hisi_smmu_master_end_check(smmu);
	if (ret) {
		tloge("master_end_check failed !%s\n", __func__);
		goto free_source;
	}
#endif
	ret = hisi_smmu_check_tbu_disconnected(smmu);
	if (ret) {
		tloge("%s:hisi_smmu_check_tbu_disconnected failed !\n",
			__func__);
		goto free_source;
	}

	ret = hisi_smmu_reg_unset(
		smmu, SMMU_LP_REQ, SMMU_LP_ACK, TCU_QREQN_PD, TCU_QACCEPTN_PD);
	if (ret) {
		tloge("TCU_QACCEPTN_PD failed !%s\n", __func__);
		goto free_source;
	}

	ret = hisi_smmu_reg_unset(
		smmu, SMMU_LP_REQ, SMMU_LP_ACK, TCU_QREQN_CG, TCU_QACCEPTN_CG);
	if (ret) {
		tloge("TCU_QACCEPTN_CG failed !%s\n", __func__);
		goto free_source;
	}

free_source:
	hisi_sec_smmu_free_structures(smmu);
	smmu->status = hisi_sec_smmu_disable;

	lock_ret = pthread_mutex_unlock(&g_hisi_svmtlb_mutex);
	if (lock_ret) {
		tloge("%s: pthread_mutex_unlock fail\n", __func__);
		return lock_ret;
	}

	return ret;
}

static int hisi_svm_get_ssid(struct tee_svm_para_list *mcl)
{
	struct hisi_tee_svm *svm = mcl->tee_svm_p;

	if (!svm)
		return -EINVAL;

	if (!svm->smmu_domain)
		return -EINVAL;

	mcl->ssid = svm->smmu_domain->s1_cfg.cd.ssid;
	mcl->ttbr = svm->smmu_domain->s1_cfg.cd.ttbr;
	mcl->tcr = svm->smmu_domain->s1_cfg.cd.tcr;
	return 0;
}

void hisi_smmu_group_flush_tlb(void)
{
	struct hisi_sec_smmu_domain *smmu_domain = NULL;

	if (!g_hisi_svm_bind)
		return;

	smmu_domain = g_hisi_svm_bind->smmu_domain;

	if (!smmu_domain) {
		tloge("%s,smmu_domain is null\n", __func__);
		return;
	}
	hisi_smmu_group_tlb_inv_context(smmu_domain);
}

static int hisi_aicpu_irq_offset_register(struct tee_svm_para_list *mcl)
{
	g_pgfault_asid_addr = mcl->aicpu_irq.pgfault_asid_addr;
	g_pgfault_va_addr_g = mcl->aicpu_irq.pgfault_va_addr;
	tlogd("into %s, 0x%llx, 0x%llx\n", __func__,
		g_pgfault_asid_addr, g_pgfault_va_addr_g);
	return 0;
}

static void hisi_clear_global_svm(struct tee_svm_para_list *mcl)
{
	struct hisi_tee_svm *svm = mcl->tee_svm_p;
	int ret;
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *tmp = NULL;

	tlogd("into %s\n", __func__);

	if (!svm) {
		tloge("%s: svm NULL\n", __func__);
		return;
	}

	ret = pthread_mutex_lock(&g_hisi_svm_mutex);
	if (ret) {
		tloge("%s: pthread_mutex_lock fail\n", __func__);
		return;
	}
	if (!g_hisi_svm_bind || g_hisi_svm_bind != svm) {
		tloge("%s: svm invalid\n", __func__);
		(void)pthread_mutex_unlock(&g_hisi_svm_mutex);
		return;
	}

	/* Disable all enabled SMMUs, and free structures */
	list_for_each_safe(p, n, &g_hisi_tee_smmu_group->smmu_list) {
		tmp = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (tmp && tmp->status == hisi_sec_smmu_enable) {
			tmp->status = hisi_sec_smmu_disable;
			hisi_sec_smmu_free_structures(tmp);
		}
	}

	/* Release svm resources */
	hisi_sec_smmu_domain_draft(svm->smmu_domain);
	hisi_sec_smmu_domain_free(svm->smmu_domain);
	free(svm);
	mcl->tee_svm_p = NULL;

	g_hisi_svm_bind = NULL;
	ret = pthread_mutex_unlock(&g_hisi_svm_mutex);
	if (ret)
		tloge("%s: pthread_mutex_unlock fail\n", __func__);

	tlogd("out %s\n", __func__);
}

s32 __teesvm_ioctl(int svm_ta_tag, void *mcl)
{
	s32 ret = 0;

	if (!mcl)
		return -EINVAL;

	switch (svm_ta_tag) {
	case SVM_SEC_CMD_POWER_ON:
		ret = hisi_smmu_poweron((struct tee_svm_para_list *)mcl);
		break;
	case SVM_SEC_CMD_BIND:
		ret = hisi_svm_bind_task((struct tee_svm_para_list *)mcl);
		break;
	case SVM_SEC_CMD_UNBIND:
		hisi_svm_unbind_task((struct tee_svm_para_list *)mcl);
		break;
	case SVM_SEC_CMD_POWER_OFF:
		ret = hisi_smmu_poweroff((struct tee_svm_para_list *)mcl);
		break;
	case SVM_SEC_CMD_GET_SSID:
		ret = hisi_svm_get_ssid((struct tee_svm_para_list *)mcl);
		break;
	case SVM_SEC_CMD_FLUSH_TLB:
		hisi_smmu_group_flush_tlb();
		break;
	case SVM_SEC_CMD_AICPU_IRQ:
		ret = hisi_aicpu_irq_offset_register((struct tee_svm_para_list *)mcl);
		break;
	case SVM_SEC_CMD_CLEAR_RES:
		hisi_clear_global_svm((struct tee_svm_para_list *)mcl);
		break;
	default:
		tloge("incorrect svm_ta_tag\n");
		return -EFAULT;
	}

	tlogd("%s svm_ta_tag = %d finish\n", __func__, svm_ta_tag);
	return ret;
}

int teesvm_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
	uint32_t uwRet;
	if (params == NULL || params->args == 0)
		return -1;

	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_NPU_SMMU_SVM, permissions, AI_GROUP_PERMISSION);
		ACCESS_CHECK_A64(args[1], sizeof(struct tee_svm_para_list));
		ACCESS_READ_RIGHT_CHECK(args[1], sizeof(struct tee_svm_para_list));
		uwRet = (uint32_t)__teesvm_ioctl((int)args[0], (void *)(uintptr_t)args[1]);
		args[0] = uwRet;
		SYSCALL_END
		default :
			return -EINVAL;
	}
	return 0;
}

DECLARE_TC_DRV(
	tee_svm_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	tee_svm_init,
	NULL,
	teesvm_syscall,
	NULL,
	NULL
);
