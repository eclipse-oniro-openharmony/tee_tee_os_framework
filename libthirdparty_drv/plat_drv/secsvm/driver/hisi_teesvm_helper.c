/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: secure os teesvm module
 * Internal functions
 *
 * Author: hisilicon
 * Create: 2019-12-26
 */
#include <ipclib.h>
#include <irqmgr.h>
#include "securec.h"
#include "cc_bitops.h"
#include "pthread.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "secure_gic_common.h"
#include "drv_mem.h" /* sre_mmap */
#include "hm_unistd.h"
#include "hisi_debug.h"
#include "list.h"
#include "hisi_teesvm_internal.h"

#define hisi_udelay(usec)                                   \
	do {                                                    \
		/* excute 500 times nop instruction to delay 1us */ \
		for (int i = 0; i < 500 * (usec); i++) {            \
			asm("nop");                                     \
		};                                                  \
	} while (0)

#define MSTR_END_ACK(end) SMMU_MSTR_END_ACK_##end
#define CMDQ_0_SSEC (1ULL << 10)
#define ARM_LPAE_TTBR_ASID_SHIFT 48
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
#define TCU_CACHE_INVAL_REG CACHELINE_INV_ALL
#else
#define TCU_CACHE_INVAL_REG HISI_SEC_S_SMMU_TCU_INIT
#endif
#define ETBUON 1

struct hisi_tee_svm *g_hisi_svm_bind;
struct hisi_tee_smmu_group *g_hisi_tee_smmu_group;
struct hisi_sec_smmu_device *g_hisi_mmu_dev;
u64 g_pgfault_asid_addr;
u64 g_pgfault_va_addr_g;
pthread_mutex_t g_hisi_svm_mutex;
pthread_mutex_t g_hisi_svmtlb_mutex;
uintptr_t g_smmu_cmdq_base;
uintptr_t g_smmu_eventq_base;
uintptr_t g_smmu_ste_base;
uintptr_t g_smmu_cd_base;

void hisi_tee_svm_dump_reg(void)
{
	u32 i, reg;
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *smmu = NULL;

	list_for_each_safe(p, n, &g_hisi_tee_smmu_group->smmu_list) {
		smmu = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (!smmu || (smmu->status != hisi_sec_smmu_enable)) {
			tloge("%s smmu invalid,status:%d\n", __func__, smmu->status);
			continue;
		}

		/* dump tcu registers, range from 0 to 0xBC */
		for (i = 0; i <= 0xBC; i += ADDRESS_WIDTH) {
			reg = hisi_readl(smmu->platform_info.base +
				HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + i);
			tloge("0x%8x:0x%8x\n", smmu->platform_info.base +
				HISI_TCU_PG0_BASE + HISI_SEC_TCU_OFFSET + i, reg);
		}

		/* dump smmu top ctrl registers, range from 0 to 0x2C */
		for (i = 0; i <= 0x2C; i += ADDRESS_WIDTH) {
			reg = hisi_readl(smmu->platform_info.base +
				HISI_TOP_CTL_BASE + i);
			tloge("0x%8x:0x%8x\n", smmu->platform_info.base +
				HISI_TOP_CTL_BASE + i, reg);
		}

		/* dump secure interrupt registers, range from 0x80 to 0x8C */
		for (i = 0x80; i <= 0x8C; i += ADDRESS_WIDTH) {
			reg = hisi_readl(smmu->platform_info.base +
				HISI_TOP_CTL_BASE + i);
			tloge("0x%8x:0x%8x\n", smmu->platform_info.base +
				HISI_TOP_CTL_BASE + i, reg);
		}
	}
}

static int invalid_tcu_cache(struct hisi_sec_smmu_device *smmu)
{
	u32 reg;
	u32 check_times = 0;

	/* write 1 to TCU_CACHE_INVAL_REG to invalid tcu cache */
	hisi_writel(1, smmu->platform_info.base + TCU_CACHE_INVAL_REG);
	do {
		reg = hisi_readl(smmu->platform_info.base + TCU_CACHE_INVAL_REG);
		if (!(reg & 0x1))
			break;
		hisi_udelay(1);
		if (++check_times >= MAX_CHECK_TIMES) {
			tloge("CACHELINE_INV_ALL failed !%s\n", __func__);
			return -ETIMEDOUT;
		}
	} while (1);

	return 0;
}

/* Low-level queue manipulation functions */
static void queue_sync_cons(struct hisi_sec_smmu_queue *q)
{
	q->cons = hisi_readl(q->cons_reg);
}

static void queue_inc_cons(struct hisi_sec_smmu_queue *q)
{
	u32 cons = (Q_WRP(q, q->cons) | Q_IDX(q, q->cons)) + 1;

	q->cons = Q_OVF(q, q->cons) | Q_WRP(q, cons) | Q_IDX(q, cons);
	hisi_writel(q->cons, q->cons_reg);
}

int queue_sync_prod(struct hisi_sec_smmu_queue *q)
{
	int ret = 0;
	u32 prod;

	prod = hisi_readl(q->prod_reg);
	if (Q_OVF(q, prod) != Q_OVF(q, q->prod))
		ret = -EOVERFLOW;

	q->prod = prod;
	return ret;
}

static void queue_inc_prod(struct hisi_sec_smmu_queue *q)
{
	u32 prod = (Q_WRP(q, q->prod) | Q_IDX(q, q->prod)) + 1;

	q->prod = Q_OVF(q, q->prod) | Q_WRP(q, prod) | Q_IDX(q, prod);
	hisi_writel(q->prod, q->prod_reg);
}

/*
 * Wait for the SMMU to consume items.
 * If drain is true, wait until the queue is empty.
 * Otherwise, wait until there is at least one free slot.
 */
static int queue_poll_cons(struct hisi_sec_smmu_queue *q, bool drain)
{
	u64 timeout = 0;

	while (queue_sync_cons(q), (drain ? !queue_empty(q) : queue_full(q))) {
		if (timeout > HISI_SEC_SMMU_POLL_TIMEOUT_US)
			return -ETIMEDOUT;

		timeout++;
		hisi_udelay(1);
	}

	return 0;
}

static void queue_write(u64 *dst, u64 *src, size_t n_dwords)
{
	u32 i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = cpu_to_le64(*src++);
}

static int queue_insert_raw(struct hisi_sec_smmu_queue *q, u64 *ent, size_t len)
{
	if (queue_full(q))
		return -ENOSPC;
	queue_write(Q_ENT(q, q->prod), ent, len);

	queue_inc_prod(q);
	return 0;
}

static void queue_read(u64 *dst, u64 *src, size_t n_dwords)
{
	u32 i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = le64_to_cpu(*src++);
}

static int queue_remove_raw(struct hisi_sec_smmu_queue *q, u64 *ent, size_t len)
{
	if (queue_empty(q))
		return -EAGAIN;

	queue_read(ent, Q_ENT(q, q->cons), len);
	queue_inc_cons(q);
	return 0;
}

/* High-level queue accessors */
static int hisi_sec_smmu_cmdq_build_cmd(
	u64 *cmd, unsigned int len, struct hisi_sec_smmu_cmdq_ent *ent)
{
	memset_s(cmd, CMDQ_ENT_DWORDS << DWORD_BYTES_NUM, 0, CMDQ_ENT_DWORDS << DWORD_BYTES_NUM);

	cmd[0] |= (ent->opcode & CMDQ_0_OP_MASK) << CMDQ_0_OP_SHIFT;
	cmd[len - 1] |= CMDQ_0_SSEC;

	switch (ent->opcode) {
	case CMDQ_OP_TLBI_EL2_ALL:
	case CMDQ_OP_TLBI_NSNH_ALL:
		break;
	case CMDQ_OP_PREFETCH_CFG:
		cmd[0] |= (u64)ent->prefetch.sid << CMDQ_PREFETCH_0_SID_SHIFT;
		cmd[len - 1] |= ent->prefetch.size << CMDQ_PREFETCH_1_SIZE_SHIFT;
		cmd[len - 1] |= ent->prefetch.addr & CMDQ_PREFETCH_1_ADDR_MASK;
		break;
	case CMDQ_OP_CFGI_STE:
		cmd[0] |= (u64)ent->cfgi.sid << CMDQ_CFGI_0_SID_SHIFT;
		cmd[len - 1] |= ent->cfgi.leaf ? CMDQ_CFGI_1_LEAF : 0;
		break;
	case CMDQ_OP_CFGI_ALL:
		/* Cover the entire SID range */
		cmd[len - 1] |= CMDQ_CFGI_1_RANGE_MASK << CMDQ_CFGI_1_RANGE_SHIFT;
		break;
	/*
	 * Cover the specal cd desc of sid,
	 * and in our code only use this case.
	 */
	case CMDQ_OP_CFGI_CD:
		cmd[0] |= (u64)ent->cfgi.ssid << CMDQ_CFGI_0_CD_SHIFT;
		cmd[0] |= (u64)ent->cfgi.sid << CMDQ_CFGI_0_SID_SHIFT;
		cmd[len - 1] |= ent->cfgi.leaf ? CMDQ_CFGI_1_LEAF : 0;
		break;
	/* Cover the all cd descs of sid */
	case CMDQ_OP_CFGI_CD_ALL:
		cmd[0] |= (u64)ent->cfgi.sid << CMDQ_CFGI_0_SID_SHIFT;
		break;

	case CMDQ_OP_TLBI_NH_VA:
		cmd[0] |= (u64)ent->tlbi.asid << CMDQ_TLBI_0_ASID_SHIFT;
		cmd[len - 1] |= ent->tlbi.leaf ? CMDQ_TLBI_1_LEAF : 0;
		cmd[len - 1] |= ent->tlbi.addr & CMDQ_TLBI_1_VA_MASK;
		break;
	case CMDQ_OP_TLBI_S2_IPA:
		cmd[0] |= (u64)ent->tlbi.vmid << CMDQ_TLBI_0_VMID_SHIFT;
		cmd[len - 1] |= ent->tlbi.leaf ? CMDQ_TLBI_1_LEAF : 0;
		cmd[len - 1] |= ent->tlbi.addr & CMDQ_TLBI_1_IPA_MASK;
		break;
	case CMDQ_OP_TLBI_NH_ASID:
		cmd[0] |= (u64)ent->tlbi.asid << CMDQ_TLBI_0_ASID_SHIFT;
	/* Fallthrough */
	case CMDQ_OP_TLBI_S12_VMALL:
		cmd[0] |= (u64)ent->tlbi.vmid << CMDQ_TLBI_0_VMID_SHIFT;
		break;
	case CMDQ_OP_CMD_SYNC:
		cmd[0] |= CMDQ_SYNC_0_CS_SEV;
		break;
	default:
		return -ENOENT;
	}

	return 0;
}

void hisi_sec_smmu_cmdq_skip_err(struct hisi_sec_smmu_device *smmu)
{
	static const char *const cerror_str[] = {
		[CMDQ_ERR_CERROR_NONE_IDX] = "No error",
		[CMDQ_ERR_CERROR_ILL_IDX] = "Illegal command",
		[CMDQ_ERR_CERROR_ABT_IDX] = "Abort on command fetch",
	};

	u32 i;
	u64 cmd[CMDQ_ENT_DWORDS] = {0};
	struct hisi_sec_smmu_queue *q = &smmu->cmdq.q;
	u32 cons = hisi_readl(q->cons_reg);
	u32 idx = (cons >> CMDQ_ERR_SHIFT) & CMDQ_ERR_MASK;
	struct hisi_sec_smmu_cmdq_ent cmd_sync = {
		.opcode = CMDQ_OP_CMD_SYNC,
	};

	tloge("smmuid:%d CMDQ error (cons 0x%08x): %s\n",
		smmu->smmuid, cons, cerror_str[idx]);

	switch (idx) {
	case CMDQ_ERR_CERROR_ILL_IDX:
		break;
	case CMDQ_ERR_CERROR_ABT_IDX:
		tloge("smmuid:%d retrying command fetch\n", smmu->smmuid);
		return;
	case CMDQ_ERR_CERROR_NONE_IDX:
		return;
	}

	/*
	 * We may have concurrent producers, so we need to be careful
	 * not to touch any of the shadow cmdq state.
	 */
	queue_read(cmd, Q_ENT(q, cons), q->ent_dwords);
	tloge("smmuid:%d skipping command in error state:\n", smmu->smmuid);
	for (i = 0; i < ARRAY_SIZE(cmd); ++i)
		tloge("\t0x%016llx\n", (unsigned long long)cmd[i]);

	/* Convert the erroneous command into a CMD_SYNC */
	if (hisi_sec_smmu_cmdq_build_cmd(cmd, CMDQ_ENT_DWORDS, &cmd_sync)) {
		tloge("smmuid:%d failed to convert to CMD_SYNC\n",
			smmu->smmuid);
		return;
	}

	queue_write(Q_ENT(q, cons), cmd, q->ent_dwords);
}

static void hisi_sec_smmu_cmdq_issue_cmd(
	struct hisi_sec_smmu_device *smmu, struct hisi_sec_smmu_cmdq_ent *ent)
{
	u64 cmd[CMDQ_ENT_DWORDS];
	int times = 0;
	struct hisi_sec_smmu_queue *q = &smmu->cmdq.q;
	int ret;

	if (smmu->status != hisi_sec_smmu_enable) {
		tloge("%s,smmu is not enabled,id:%d\n", __func__,
				smmu->smmuid);
		return;
	}

	if (hisi_sec_smmu_cmdq_build_cmd(cmd, CMDQ_ENT_DWORDS, ent)) {
		tloge("smmuid:%d ignoring unknown CMDQ opcode 0x%x\n",
			smmu->smmuid, ent->opcode);
		return;
	}

	irq_lock();
	ret = pthread_mutex_lock(&smmu->cmdq.lock);
	if (ret) {
		tloge("%s:pthread_mutex_lock fail\n", __func__);
		irq_unlock();
		return;
	}
	while (queue_insert_raw(q, cmd, q->ent_dwords) == -ENOSPC) {
		if (queue_poll_cons(q, false)) {
			times++;
			if (times > CMDQ_MAX_TIMEOUT_TIMES) {
				tloge("error out issue cmd!smmuid:%d CMDQ 0x%x timeout\n",
					smmu->smmuid, ent->opcode);
				hisi_tee_svm_dump_reg();
				pthread_mutex_unlock(&smmu->cmdq.lock);
				irq_unlock();
				return;
			}
		}
	}

	if (ent->opcode == CMDQ_OP_CMD_SYNC && queue_poll_cons(q, true))
		tloge("smmuid:%d CMD_SYNC timeout\n", smmu->smmuid);
	ret = pthread_mutex_unlock(&smmu->cmdq.lock);
	if (ret) {
		tloge("%s: pthread_mutex_unlock fail\n", __func__);
		return;
	}
	irq_unlock();
}

/* Context descriptor manipulation functions */
static u64 hisi_sec_smmu_cpu_tcr_to_cd(u64 tcr)
{
	u64 val = 0;

	/* Repack the TCR. Just care about TTBR0 for now */
	val |= HISI_SEC_SMMU_TCR2CD(tcr, T0SZ);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, TG0);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, IRGN0);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, ORGN0);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, SH0);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, EPD0);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, EPD1);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, IPS);
	val |= HISI_SEC_SMMU_TCR2CD(tcr, TBI0);

	return val;
}

static void hisi_sec_smmu_write_ctx_desc(struct hisi_sec_smmu_s1_cfg *cfg)
{
	u64 val;

	/*
	 * We don't need to issue any invalidation here, as we'll invalidate
	 * the STE when installing the new entry anyway.
	 */
	val = hisi_sec_smmu_cpu_tcr_to_cd(cfg->cd.tcr) |
	      CTXDESC_CD_0_S | CTXDESC_CD_0_R | CTXDESC_CD_0_A |
	      CTXDESC_CD_0_ASET_PRIVATE | CTXDESC_CD_0_AA64 |
	      ((u64)cfg->cd.asid << CTXDESC_CD_0_ASID_SHIFT) | CTXDESC_CD_0_V;
	/* set cd ctr */
	cfg->cdptr[0] = cpu_to_le64(val);
	val = cfg->cd.ttbr & CTXDESC_CD_1_TTB0_MASK << CTXDESC_CD_1_TTB0_SHIFT;
	/* set cd tbb0 */
	cfg->cdptr[1] = cpu_to_le64(val);
	/* set cd mair */
	cfg->cdptr[3] = cpu_to_le64(cfg->cd.mair << CTXDESC_CD_3_MAIR_SHIFT);
}

static void hisi_sec_smmu_write_strtab_ent(u64 *dst,
	struct hisi_sec_smmu_strtab_ent *ste)
{
	/*
	 * This is hideously complicated, but we only really care about
	 * three cases at the moment:
	 *
	 * 1. Invalid (all zero) -> Bypass  (init)
	 * 2. Bypass -> translation (attach)
	 * 3. Translation -> bypass (detach)
	 */
	u64 val = le64_to_cpu(dst[0]);

	val &= ~(HISI_SEC_STRTAB_STE_0_CFG_MASK
		 << HISI_SEC_STRTAB_STE_0_CFG_SHIFT);
	if (ste->valid)
		val |= HISI_SEC_STRTAB_STE_0_V;
	else
		val &= ~HISI_SEC_STRTAB_STE_0_V;

	if (ste->bypass)
		val |= HISI_SEC_STRTAB_STE_0_CFG_BYPASS;
	else
		val |= HISI_SEC_STRTAB_STE_0_CFG_S1_TRANS;

	if (ste->cdtab_cfg)
		val |= ste->cdtab_cfg->cdtab_phy &
		       HISI_SEC_STRTAB_STE_0_S1CTXPTR_MASK
			       << HISI_SEC_STRTAB_STE_0_S1CTXPTR_SHIFT;
	/*
	 * number of CDs pointed to by
	 * S1ContextPtr,check cdmax
	 */
	val |= 6ULL << HISI_SEC_STRTAB_STE_0_S1CDMAX_SHIFT;
	dst[0] = cpu_to_le64(val);
}

/* IO_PGTABLE API */
static void __hisi_sec_smmu_tlb_sync(struct hisi_sec_smmu_device *smmu)
{
	struct hisi_sec_smmu_cmdq_ent cmd;

	cmd.opcode = CMDQ_OP_CMD_SYNC;
	hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
}

static int hisi_svm_lpae_switch_oas(
	struct hisi_sec_svm_pgtable_cfg *cfg, u64 *reg)
{
	switch (cfg->oas) {
	case HISI_SMMU_ADDR_SIZE_32:
		*reg |= (HISI_SEC_LPAE_TCR_PS_32_BIT
			<< HISI_SEC_LPAE_TCR_IPS_SHIFT);
		break;
	case HISI_SMMU_ADDR_SIZE_36:
		*reg |= (HISI_SEC_LPAE_TCR_PS_36_BIT
			<< HISI_SEC_LPAE_TCR_IPS_SHIFT);
		break;
	case HISI_SMMU_ADDR_SIZE_40:
		*reg |= (HISI_SEC_LPAE_TCR_PS_40_BIT
			<< HISI_SEC_LPAE_TCR_IPS_SHIFT);
		break;
	case HISI_SMMU_ADDR_SIZE_42:
		*reg |= (HISI_SEC_LPAE_TCR_PS_42_BIT
			<< HISI_SEC_LPAE_TCR_IPS_SHIFT);
		break;
	case HISI_SMMU_ADDR_SIZE_44:
		*reg |= (HISI_SEC_LPAE_TCR_PS_44_BIT
			<< HISI_SEC_LPAE_TCR_IPS_SHIFT);
		break;
	case HISI_SMMU_ADDR_SIZE_48:
		*reg |= (HISI_SEC_LPAE_TCR_PS_48_BIT
			<< HISI_SEC_LPAE_TCR_IPS_SHIFT);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static int hisi_svm_lpae_alloc_pgtable_s1(struct hisi_sec_svm_pgtable_cfg *cfg,
	struct hisi_tee_svm *svm)
{
	u64 asid;
	u64 reg = 0;

	/* TCR */
	if (hisi_svm_lpae_switch_oas(cfg, &reg))
		goto out;

	reg |= (64ULL - cfg->ias) << HISI_SEC_LPAE_TCR_T0SZ_SHIFT;

	/* Disable speculative walks through TTBR1 */
	reg |= HISI_SEC_LPAE_TCR_EPD1;
	cfg->hisi_sec_lpae_s1_cfg.tcr = reg;

	/* MAIRs */
	reg = (HISI_SEC_LPAE_MAIR_ATTR_NC << HISI_SEC_LPAE_MAIR_ATTR_SHIFT(
		       HISI_SEC_LPAE_MAIR_ATTR_IDX_NC)) |
	      (HISI_SEC_LPAE_MAIR_ATTR_WBRWA << HISI_SEC_LPAE_MAIR_ATTR_SHIFT(
		       HISI_SEC_LPAE_MAIR_ATTR_IDX_CACHE)) |
	      (HISI_SEC_LPAE_MAIR_ATTR_DEVICE << HISI_SEC_LPAE_MAIR_ATTR_SHIFT(
		       HISI_SEC_LPAE_MAIR_ATTR_IDX_DEV));

	cfg->hisi_sec_lpae_s1_cfg.mair[0] = reg;
	cfg->hisi_sec_lpae_s1_cfg.mair[1] = 0;

	tlogd("%s, pid:%d, pgd:%p\n", __func__, svm->pid, svm->pgd);
	asid = svm->asid;

	if (!svm->pgd)
		goto out;

	cfg->hisi_sec_lpae_s1_cfg.ttbr[0] = svm->pgd | (asid << ARM_LPAE_TTBR_ASID_SHIFT);
	cfg->hisi_sec_lpae_s1_cfg.ttbr[1] = 0;

	return 0;
out:
	tloge("err out %s\n", __func__);
	return -EINVAL;
}

void hisi_smmu_group_tlb_inv_context(struct hisi_sec_smmu_domain *cookie)
{
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *smmu = NULL;
	struct hisi_tee_smmu_group *smmu_grp = NULL;
	struct hisi_sec_smmu_domain *smmu_domain = cookie;
	int ret;

	if (!smmu_domain)
		return;

	smmu_grp = smmu_domain->smmu_grp;
	if (!smmu_grp)
		return;

	ret = pthread_mutex_lock(&g_hisi_svmtlb_mutex);
	if (ret) {
		tloge("%s: pthread_mutex_lock fail\n", __func__);
		return;
	}
	list_for_each_safe(p, n, &smmu_grp->smmu_list) {
		struct hisi_sec_smmu_cmdq_ent cmd;

		smmu = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (!smmu || smmu->status != hisi_sec_smmu_enable) {
			tloge("%s smmu is null or disable\n", __func__);
			pthread_mutex_unlock(&g_hisi_svmtlb_mutex);
			return;
		}

		cmd.opcode = CMDQ_OP_TLBI_NH_ASID;
		cmd.tlbi.asid = smmu_domain->s1_cfg.cd.asid;
		cmd.tlbi.vmid = 0;

		hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
		__hisi_sec_smmu_tlb_sync(smmu);

		ret = invalid_tcu_cache(smmu);
		if (ret)
			tloge("%s invalid_tcu_cache fail\n", __func__);
	}
	ret = pthread_mutex_unlock(&g_hisi_svmtlb_mutex);
	if (ret)
		tloge("%s: pthread_mutex_unlock fail\n", __func__);
}

struct hisi_sec_smmu_domain *hisi_sec_smmu_domain_alloc(void)
{
	struct hisi_sec_smmu_domain *smmu_domain = NULL;
	int ret;

	if (!g_hisi_tee_smmu_group) {
		tloge("g_hisi_tee_smmu_group is null %s\n", __func__);
		return NULL;
	}

	/*
	 * Allocate the domain and initialise some of its data structures.
	 * We can't really do anything meaningful until we've added a
	 * master.
	 */
	smmu_domain = malloc_coherent(sizeof(*smmu_domain));
	if (!smmu_domain) {
		tloge("%s alloc smmu_domain failed\n", __func__);
		return NULL;
	}

	/* Domain attach the smmu group */
	smmu_domain->smmu_grp = g_hisi_tee_smmu_group;
	ret = pthread_mutex_init(&smmu_domain->init_mutex, NULL);
	if (ret)
		tloge("%s: pthread_mutex_init fail\n", __func__);

	return smmu_domain;
}

static s32 find_first_bit(u32 word)
{
	s32 num = 0;

	if ((word & 0xffff) == 0) {
		num += 16;
		word >>= 16;
	}
	if ((word & 0xff) == 0) {
		num += 8;
		word >>= 8;
	}
	if ((word & 0xf) == 0) {
		num += 4;
		word >>= 4;
	}
	if ((word & 0x3) == 0) {
		num += 2;
		word >>= 2;
	}
	if ((word & 0x1) == 0)
		num += 1;
	return num;
}

static u32 find_next_bit(const unsigned long *addr,
	u32 end, u32 start, u32 invert)
{
	u32 tmp;

	if (!end || start >= end)
		return end;

	tmp = addr[start / BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = ALIGN_DOWN(start, BITS_PER_LONG);
	while (!tmp) {
		start += BITS_PER_LONG;
		if (start >= end)
			return end;

		tmp = addr[start / BITS_PER_LONG] ^ invert;
	}
	return min(start + find_first_bit(tmp), end);
}

static int hisi_sec_smmu_bitmap_alloc(unsigned long *map, int span)
{
	u32 idx;
	u32 size = 1 << (unsigned int)span;
	int start = 0;

	do {
		idx = find_next_bit(map, size, start, ~0UL);
		if (idx == size)
			return -ENOSPC;
		start = idx + 1;
	} while (test_and_set_bit(idx, map));

	return idx;
}

static void hisi_sec_smmu_bitmap_free(unsigned long *map, int idx)
{
	clear_bit(idx, map);
}

void hisi_sec_smmu_domain_free(struct hisi_sec_smmu_domain *smmu_domain)
{
	if (!smmu_domain)
		return;

	free(smmu_domain);
}

static int hisi_sec_smmu_domain_finalise_s1(
	struct hisi_sec_smmu_domain *smmu_domain,
	struct hisi_sec_svm_pgtable_cfg *pgtbl_cfg, struct hisi_tee_svm *svm)
{
	int ssid;
	unsigned long asid;
	struct hisi_sec_smmu_s1_cfg *cfg = &smmu_domain->s1_cfg;
	struct hisi_tee_smmu_group *smmu_group = smmu_domain->smmu_grp;

	asid = svm->asid;

	ssid = hisi_sec_smmu_bitmap_alloc(
		smmu_group->ssid_map, smmu_group->ssid_bits);
	if (ssid < 0) {
		tloge("%s,hisi_sec_smmu_bitmap_alloc failed!!\n", __func__);
		return -EINVAL;
	}

	cfg->cdptr = &smmu_group->cdtab_cfg.cdtab[(long)ssid * (1 << DWORD_BYTES_NUM)];
	cfg->cdptr_phy = smmu_group->cdtab_cfg.cdtab_phy +
			 (long)ssid * (CTXDESC_CD_DWORDS << DWORD_BYTES_NUM);

	cfg->cd.ssid = (u16)ssid;
	cfg->cd.asid = (u16)asid;
	cfg->cd.ttbr = pgtbl_cfg->hisi_sec_lpae_s1_cfg.ttbr[0];
	cfg->cd.tcr = pgtbl_cfg->hisi_sec_lpae_s1_cfg.tcr;
	cfg->cd.mair = pgtbl_cfg->hisi_sec_lpae_s1_cfg.mair[0];

	/* only build the cd desc */
	hisi_sec_smmu_write_ctx_desc(cfg);

	return 0;
}

int hisi_sec_smmu_domain_finalise(
	struct hisi_sec_smmu_domain *smmu_domain, struct hisi_tee_svm *svm)
{
	int ret;
	struct hisi_sec_svm_pgtable_cfg pgtbl_cfg;
	struct hisi_tee_smmu_group *grp = smmu_domain->smmu_grp;

	pgtbl_cfg = (struct hisi_sec_svm_pgtable_cfg){
		.ias = VA_BITS,
		.oas = grp->oas,
	};

	ret = hisi_svm_lpae_alloc_pgtable_s1(&pgtbl_cfg, svm);
	if (ret) {
		tloge("%s:hisi_svm_lpae_alloc_pgtable_s1 failed\n", __func__);
		return -ENOMEM;
	}

	ret = hisi_sec_smmu_domain_finalise_s1(smmu_domain, &pgtbl_cfg, svm);
	if (ret)
		tloge("error out %s\n", __func__);

	return ret;
}

static u64 *hisi_sec_smmu_get_step_for_sid(
	struct hisi_sec_smmu_device *smmu, u32 sid)
{
	u64 *step = NULL;
	struct hisi_sec_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	/* only support Simple linear lookup now */
	step = &cfg->strtab[(long)sid * HISI_SEC_STRTAB_STE_DWORDS];

	return step;
}

int hisi_sec_smmu_enable_cd(
	struct hisi_tee_smmu_group *grp, struct hisi_sec_smmu_domain *dom)
{
	u32 sid;
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *smmu = NULL;
	int ret;

	/* maybe can prefetch */
	list_for_each_safe(p, n, &grp->smmu_list) {
		smmu = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (!smmu || (smmu->status != hisi_sec_smmu_enable)) {
			tloge("%s smmu invalid,status:%d\n", __func__, smmu->status);
			return -EPERM;
		}

		ret = invalid_tcu_cache(smmu);
		if (ret)
			tloge("%s invalid_tcu_cache fail\n", __func__);
		for (sid = 0; sid < smmu->strtab_cfg.num_l1_ents; sid++) {
			struct hisi_sec_smmu_cmdq_ent cmd;

			cmd.opcode = CMDQ_OP_CFGI_CD;
			cmd.cfgi.ssid = dom->s1_cfg.cd.ssid;
			cmd.cfgi.sid = sid;
			cmd.cfgi.leaf = 1;
			hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
			cmd.opcode = CMDQ_OP_CMD_SYNC;
			hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
		}
	}
	return 0;
}

void hisi_sec_smmu_disable_cd(
	struct hisi_tee_smmu_group *grp, struct hisi_sec_smmu_domain *dom)
{
	u32 sid;
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *smmu = NULL;
	int ret;

	/* maybe can prefetch */
	list_for_each_safe(p, n, &grp->smmu_list) {
		smmu = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (!smmu) {
			tloge("%s smmu is null\n", __func__);
			return;
		}

		if (smmu->status != hisi_sec_smmu_enable) {
			tloge("%s smmu %d is not enabled:%d\n", __func__,
				smmu->smmuid, smmu->status);
			continue;
		}

		ret = invalid_tcu_cache(smmu);
		if (ret)
			tloge("%s invalid_tcu_cache fail\n", __func__);
		for (sid = 0; sid < smmu->strtab_cfg.num_l1_ents; sid++) {
			struct hisi_sec_smmu_cmdq_ent cmd;

			cmd.opcode = CMDQ_OP_CFGI_CD;
			cmd.cfgi.ssid = dom->s1_cfg.cd.ssid;
			cmd.cfgi.sid = sid;
			cmd.cfgi.leaf = 1;
			hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);

			cmd.opcode = CMDQ_OP_CMD_SYNC;
			hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
		}
	}
}

void hisi_sec_smmu_domain_draft(struct hisi_sec_smmu_domain *smmu_domain)
{
	struct hisi_sec_smmu_s1_cfg *cfg = &smmu_domain->s1_cfg;
	struct hisi_tee_smmu_group *smmu_group = smmu_domain->smmu_grp;

	hisi_sec_smmu_bitmap_free(smmu_group->ssid_map, cfg->cd.ssid);

	/* clear cd decs */
	memset_s(cfg->cdptr, CTXDESC_CD_DWORDS << DWORD_BYTES_NUM,
		0x0, CTXDESC_CD_DWORDS << DWORD_BYTES_NUM);
}

/* Probing and initialisation functions */
static int hisi_sec_smmu_init_one_queue(struct hisi_sec_smmu_device *smmu,
	struct hisi_sec_smmu_queue *q, unsigned long prod_off,
	unsigned long cons_off, size_t dwords, enum hisi_smmu_q q_type)
{
	size_t qsz = (((size_t)1 << q->max_n_shift) * dwords) << DWORD_BYTES_NUM;

	if (qsz > SZ_4K) {
		tloge("queue size more than 4K!qtype:%u, max_n_shift:%u, qsz:0x%zx\n",
			q_type, q->max_n_shift, qsz);
		return -ENOMEM;
	}

	switch (q_type) {
	case hisi_smmu_cmdq:
		q->base_phy = g_smmu_cmdq_base;
		break;
	case hisi_smmu_eventq:
		q->base_phy = g_smmu_eventq_base;
		break;
	default:
		tloge("q_type:%d unknown/unsupported q_type!\n",
			q_type);
		return -ENOMEM;
	}

	if (sre_mmap(q->base_phy, qsz, (u32 *)(uintptr_t)&(q->base), secure, non_cache) ||
		memset_s(q->base, qsz, 0, qsz)) {
		tloge("smmu queue mmap fail!!q_type:%d\n", q_type);
		return -ENOMEM;
	}

	q->q_size = qsz;
	q->prod_reg = smmu->platform_info.base + prod_off;
	q->cons_reg = smmu->platform_info.base + cons_off;
	q->ent_dwords = dwords;

	q->q_base_0 = (u32)(q->base_phy & Q_BASE_ADDR_MASK);
	q->q_base_0 |= (q->max_n_shift & Q_BASE_LOG2SIZE_MASK)
		       << Q_BASE_LOG2SIZE_SHIFT;
	q->q_base_1 = (u32)(q->base_phy >> Q_BASE_HIGH_ADDR_SHIFT);

	q->prod = q->cons = 0;
	return 0;
}

static void hisi_sec_smmu_free_one_queue(struct hisi_sec_smmu_queue *q)
{
	memset_s(q->base, q->q_size, 0, q->q_size);
	sre_unmap((unsigned int)(uintptr_t)q->base, q->q_size);
}

static void hisi_sec_smmu_free_queues(struct hisi_sec_smmu_device *smmu)
{
	hisi_sec_smmu_free_one_queue(&smmu->cmdq.q);
	hisi_sec_smmu_free_one_queue(&smmu->evtq.q);
}

static int hisi_sec_smmu_init_queues(struct hisi_sec_smmu_device *smmu)
{
	int ret;

	/* cmdq */
	ret = pthread_mutex_init(&smmu->cmdq.lock, NULL);
	if (ret) {
		tloge("smmuid:%d cmdq lock init failed\n", smmu->smmuid);
		goto out;
	}

	ret = hisi_sec_smmu_init_one_queue(smmu, &smmu->cmdq.q,
		HISI_SEC_SMMU_CMDQ_PROD_S, HISI_SEC_SMMU_CMDQ_CONS_S,
		CMDQ_ENT_DWORDS, hisi_smmu_cmdq);
	if (ret)
		goto out;

	/* evtq */
	ret = hisi_sec_smmu_init_one_queue(smmu, &smmu->evtq.q,
		HISI_SEC_SMMU_EVTQ_PROD_S, HISI_SEC_SMMU_EVTQ_CONS_S,
		EVTQ_ENT_DWORDS, hisi_smmu_eventq);
	if (ret)
		goto out_free_cmdq;

	return 0;

out_free_cmdq:
	hisi_sec_smmu_free_one_queue(&smmu->cmdq.q);
out:
	return ret;
}

static int hisi_sec_smmu_init_strtab_linear(struct hisi_sec_smmu_device *smmu)
{
	u64 reg;
	u32 size;
	struct hisi_sec_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	/* desc size is 64 bytes and we only surpport 0~43 id */
	size = (1 << smmu->sid_bits) * (HISI_SEC_STRTAB_STE_DWORDS << DWORD_BYTES_NUM);
	if (size > SZ_4K) {
		tloge("ste size more than 4K!sid_bits:%u\n", smmu->sid_bits);
		return -ENOMEM;
	}

	if (sre_mmap(g_smmu_ste_base, size, (u32 *)(uintptr_t)&(cfg->strtab), secure, non_cache) ||
		memset_s(cfg->strtab, size, 0, size)) {
		tloge("smmu ste mmap fail!!\n");
		return -ENOMEM;
	}

	cfg->strtab_phy = g_smmu_ste_base;
	cfg->num_l1_ents = 1 << smmu->sid_bits;
	cfg->strtab_size = size;

	/* Configure strtab_base_cfg for a linear table covering all SIDs */
	reg = HISI_SEC_STRTAB_BASE_CFG_FMT_LINEAR;
	reg |= (smmu->sid_bits & HISI_SEC_STRTAB_BASE_CFG_LOG2SIZE_MASK)
	       << HISI_SEC_STRTAB_BASE_CFG_LOG2SIZE_SHIFT;
	cfg->strtab_base_cfg = reg;

	return 0;
}

static int hisi_sec_smmu_init_strtab(struct hisi_sec_smmu_device *smmu)
{
	int ret;

	ret = hisi_sec_smmu_init_strtab_linear(smmu);
	if (ret)
		return ret;

	/* Set the strtab base address */
	smmu->strtab_cfg.strtab_base_0 =
		(u32)(smmu->strtab_cfg.strtab_phy & HISI_SEC_STRTAB_BASE_ADDR_MASK);
	smmu->strtab_cfg.strtab_base_1 =
		(u32)(smmu->strtab_cfg.strtab_phy >> Q_BASE_HIGH_ADDR_SHIFT);

	return 0;
}

static void hisi_sec_smmu_free_strtab(struct hisi_sec_smmu_device *smmu)
{
	struct hisi_sec_smmu_strtab_cfg *cfg = &smmu->strtab_cfg;

	memset_s(cfg->strtab, cfg->strtab_size, 0, cfg->strtab_size);
	sre_unmap((unsigned int)(uintptr_t)cfg->strtab, cfg->strtab_size);
}

static int hisi_sec_smmu_init_structures(struct hisi_sec_smmu_device *smmu)
{
	int ret;

	ret = hisi_sec_smmu_init_queues(smmu);
	if (ret)
		return ret;

	ret = hisi_sec_smmu_init_strtab(smmu);
	if (ret)
		goto out_free_queues;

	return 0;

out_free_queues:
	hisi_sec_smmu_free_queues(smmu);
	tloge("err out %s ret %d\n", __func__, ret);

	return ret;
}

void hisi_sec_smmu_free_structures(struct hisi_sec_smmu_device *smmu)
{
	hisi_sec_smmu_free_strtab(smmu);
	hisi_sec_smmu_free_queues(smmu);
}

static int hisi_sec_smmu_write_reg_sync(struct hisi_sec_smmu_device *smmu,
	u32 val, unsigned int reg_off, unsigned int ack_off)
{
	u32 reg = 0;

	hisi_writel(val, smmu->platform_info.base + reg_off);
	return hisi_readl_relaxed_poll_timeout(
		smmu->platform_info.base + ack_off, reg, reg == val,
		HISI_SEC_SMMU_POLL_TIMEOUT_US);
}

int hisi_smmu_reg_set(struct hisi_sec_smmu_device *smmu, unsigned int req_off,
	unsigned int ack_off, unsigned int req_bit, unsigned int ack_bit)
{
	u32 val;
	u32 reg = 0;

	val = hisi_readl(smmu->platform_info.base + req_off);
	val |= req_bit;
	hisi_writel(val, smmu->platform_info.base + req_off);
	return hisi_readl_relaxed_poll_timeout(
		smmu->platform_info.base + ack_off, reg, reg & ack_bit,
		HISI_SEC_SMMU_POLL_TIMEOUT_US);
}

int hisi_smmu_reg_unset(struct hisi_sec_smmu_device *smmu, unsigned int req_off,
	unsigned int ack_off, unsigned int req_bit, unsigned int ack_bit)
{
	u32 reg;

	reg = hisi_readl(smmu->platform_info.base + req_off);
	reg &= ~req_bit;
	hisi_writel(reg, smmu->platform_info.base + req_off);
	return hisi_readl_relaxed_poll_timeout(
		smmu->platform_info.base + ack_off, reg, !(reg & ack_bit),
		HISI_SEC_SMMU_POLL_TIMEOUT_US);
}

static void hisi_evt_irq_thread(void *data)
{
	u32 i;
	int ret;
	struct hisi_sec_smmu_device *smmu = (struct hisi_sec_smmu_device *)data;
	struct hisi_sec_smmu_queue *q = &smmu->evtq.q;
	u64 evt[EVTQ_ENT_DWORDS];
	u8 id;

	while (1) {
		ret = pthread_mutex_lock(&smmu->evt_lock);
		if (ret) {
			tloge("%s:pthread_mutex_lock fail\n", __func__);
			return;
		}

		/* wait for evt */
		while ((hisi_sec_smmu_enable != smmu->status) || !(smmu->event_flag))
			pthread_cond_wait(&smmu->evt_happen, &smmu->evt_lock);

		if (pthread_mutex_lock(&g_hisi_svmtlb_mutex)) {
			tloge("%s: pthread_mutex_lock fail\n", __func__);
			return;
		}

		while (!queue_remove_raw(q, evt, q->ent_dwords)) {
			id = (evt[0] >> EVTQ_0_ID_SHIFT) & EVTQ_0_ID_MASK;
			tloge("smmuid:%d event 0x%02x received:\n", smmu->smmuid, id);
			for (i = 0; i < ARRAY_SIZE(evt); ++i)
				tloge("\t smmuid:%d 0x%016llx\n", smmu->smmuid,
					(unsigned long long)evt[i]);
			if (EVTQ_TYPE_WITH_ADDR(id)) {
				ret = hm_dump_pagetable(hm_getpid(),
					evt[EVTQ_INPUT_ADDR_OFFSET], SZ_4K);
				if (!ret)
					tloge("\t error dump:smmuid:%d evt:0x%llx ret:0x%x\n",
						smmu->smmuid, evt[EVTQ_INPUT_ADDR_OFFSET], ret);
			}
		}

		if (pthread_mutex_unlock(&g_hisi_svmtlb_mutex)) {
			tloge("%s: pthread_mutex_unlock fail\n", __func__);
			return;
		}

		q->cons = Q_OVF(q, q->prod) | Q_WRP(q, q->cons) |
			  Q_IDX(q, q->cons);

		hisi_evt_flag_unset(smmu);
		hisi_tee_svm_dump_reg();

		if (pthread_mutex_unlock(&smmu->evt_lock)) {
			tloge("%s: pthread_mutex_unlock fail\n", __func__);
			return;
		}
	}
}

int hisi_evt_irq_setup(struct hisi_sec_smmu_device *smmu)
{
	pthread_create(&smmu->evt_thread, NULL, (void *)hisi_evt_irq_thread, smmu);

	return 0;
}

int hisi_sec_smmu_device_disable(struct hisi_sec_smmu_device *smmu)
{
	int ret;

	ret = hisi_sec_smmu_write_reg_sync(
		smmu, 0, HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret)
		tloge("smmuid:%d failed to clear cr0\n", smmu->smmuid);

	return ret;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
static int hisi_smmu_master_write(
	struct hisi_sec_smmu_device *smmu, u32 value, u32 offset)
{
	hisi_writel(value, smmu->platform_info.base + HISI_MASTER_0_BASE + offset);
	hisi_writel(value, smmu->platform_info.base + HISI_MASTER_1_BASE + offset);
	return 0;
}

static int hisi_smmu_master_init(struct hisi_sec_smmu_device *smmu)
{
	hisi_smmu_master_write(smmu, 0, SMMU_MSTR_GLB_BYPASS);
	hisi_smmu_master_write(smmu, HISI_VAL_MASK, SMMU_MSTR_SMRX_START_0);
	hisi_smmu_master_write(smmu, HISI_VAL_MASK, SMMU_MSTR_SMRX_START_1);
	hisi_smmu_master_write(smmu, HISI_VAL_MASK, SMMU_MSTR_SMRX_START_2);
	return 0;
}
#endif

static int hisi_smmu_intr_init(struct hisi_sec_smmu_device *smmu)
{
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
	u32 reg = (WDATA_BURST_CLR | WR_VA_ERR1_CLR | WR_VA_ERR0_CLR |
		   RD_VA_ERR1_CLR | RD_VA_ERR0_CLR);

	hisi_smmu_master_write(smmu, reg, SMMU_MSTR_INTCLR);
	hisi_smmu_master_write(smmu, 0, SMMU_MSTR_INTMASK);
#endif
	hisi_writel(IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN,
		smmu->platform_info.base + HISI_SEC_SMMU_IRQ_CTRL_S);
	hisi_writel(HISI_VAL_MASK, smmu->platform_info.base + SMMU_IRPT_CLR_S);
	hisi_writel(0, smmu->platform_info.base + SMMU_IRPT_MASK_S);
	return 0;
}

static void hisi_smmu_device_reset_writel_strtab(
	struct hisi_sec_smmu_device *smmu)
{
	/* Stream table */
	hisi_writel(smmu->strtab_cfg.strtab_base_0,
		smmu->platform_info.base + HISI_SEC_SMMU_STRTAB_BASE_S);
	hisi_writel(smmu->strtab_cfg.strtab_base_1,
		smmu->platform_info.base + HISI_SEC_SMMU_STRTAB_BASE_H_S);
	hisi_writel(smmu->strtab_cfg.strtab_base_cfg,
		smmu->platform_info.base + HISI_SEC_SMMU_STRTAB_BASE_CFG_S);
}

static void hisi_smmu_device_reset_writel_cmdq(
	struct hisi_sec_smmu_device *smmu)
{
	hisi_writel(smmu->cmdq.q.q_base_0,
		smmu->platform_info.base + HISI_SEC_SMMU_CMDQ_BASE_S);
	hisi_writel(smmu->cmdq.q.q_base_1,
		smmu->platform_info.base + HISI_SEC_SMMU_CMDQ_BASE_H_S);
	hisi_writel(smmu->cmdq.q.prod,
		smmu->platform_info.base + HISI_SEC_SMMU_CMDQ_PROD_S);
	hisi_writel(smmu->cmdq.q.cons,
		smmu->platform_info.base + HISI_SEC_SMMU_CMDQ_CONS_S);
}

static void hisi_smmu_device_reset_writel_eventq(
	struct hisi_sec_smmu_device *smmu)
{
	hisi_writel(smmu->evtq.q.q_base_0,
		smmu->platform_info.base + HISI_SEC_SMMU_EVTQ_BASE_S);
	hisi_writel(smmu->evtq.q.q_base_1,
		smmu->platform_info.base + HISI_SEC_SMMU_EVTQ_BASE_H_S);
	hisi_writel(smmu->evtq.q.prod,
		smmu->platform_info.base + HISI_SEC_SMMU_EVTQ_PROD_S);
	hisi_writel(smmu->evtq.q.cons,
		smmu->platform_info.base + HISI_SEC_SMMU_EVTQ_CONS_S);
}

static void hisi_sec_smmu_invalidate_cfg_tlb(struct hisi_sec_smmu_device *smmu)
{
	struct hisi_sec_smmu_cmdq_ent cmd;

	/* Invalidate any cached configuration */
	cmd.opcode = CMDQ_OP_CFGI_ALL;
	hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
	cmd.opcode = CMDQ_OP_CMD_SYNC;
	hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);

	/* Invalidate any stale TLB entries */
	if (smmu->features & HISI_SEC_SMMU_FEAT_HYP) {
		cmd.opcode = CMDQ_OP_TLBI_EL2_ALL;
		hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
	}

	cmd.opcode = CMDQ_OP_TLBI_NSNH_ALL;
	hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
	cmd.opcode = CMDQ_OP_CMD_SYNC;
	hisi_sec_smmu_cmdq_issue_cmd(smmu, &cmd);
}

static int hisi_sec_smmu_device_reset(struct hisi_sec_smmu_device *smmu)
{
	int ret;
	u32 reg, enables;

	/* Clear CR0 and sync (disables SMMU and queue processing) */
	reg = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_CR0_S);
	if (reg & CR0_SMMUEN)
		tloge("smmuid:%d SMMU currently enabled! Resetting...\n",
			smmu->smmuid);

	ret = hisi_sec_smmu_device_disable(smmu);
	if (ret)
		return ret;
	/* CR2 (random crap) */
	reg = CR2_PTM | CR2_RECINVSID;
	hisi_writel(reg, smmu->platform_info.base + HISI_SEC_SMMU_CR2_S);

	hisi_smmu_device_reset_writel_strtab(smmu);

	/* Command queue */
	hisi_smmu_device_reset_writel_cmdq(smmu);

	enables = CR0_CMDQEN;
	ret = hisi_sec_smmu_write_reg_sync(
		smmu, enables, HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret) {
		tloge("smmuid:%d failed to enable command queue\n",
			smmu->smmuid);
		return ret;
	}

	hisi_sec_smmu_invalidate_cfg_tlb(smmu);
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
	hisi_smmu_master_init(smmu);
#endif
	hisi_smmu_intr_init(smmu);
	/* Event queue */
	hisi_smmu_device_reset_writel_eventq(smmu);

	enables |= CR0_EVTQEN;
	ret = hisi_sec_smmu_write_reg_sync(
		smmu, enables, HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret) {
		tloge("smmuid:%d failed to enable event queue\n", smmu->smmuid);
		return ret;
	}

	/* Enable the SMMU interface */
	enables |= CR0_SMMUEN;
	ret = hisi_sec_smmu_write_reg_sync(
		smmu, enables, HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret) {
		tloge("failed to enable SMMU interface\n", smmu->smmuid);
		return ret;
	}

	return 0;
}

static int hisi_sec_smmu_switch_idr0_ttendain(u32 reg,
	struct hisi_sec_smmu_device *smmu)
{
	switch (reg &
		HISI_SEC_IDR0_TTENDIAN_MASK << HISI_SEC_IDR0_TTENDIAN_SHIFT) {
	case HISI_SEC_IDR0_TTENDIAN_MIXED:
		smmu->features |=
			HISI_SEC_SMMU_FEAT_TT_LE | HISI_SEC_SMMU_FEAT_TT_BE;
		break;
#ifdef __BIG_ENDIAN
	case HISI_SEC_IDR0_TTENDIAN_BE:
		smmu->features |= HISI_SEC_SMMU_FEAT_TT_BE;
		break;
#else
	case HISI_SEC_IDR0_TTENDIAN_LE:
		smmu->features |= HISI_SEC_SMMU_FEAT_TT_LE;
		break;
#endif
	default:
		tloge("smmuid:%d unknown/unsupported TT endianness!\n",
			smmu->smmuid);
		return -ENXIO;
	}

	return 0;
}

static int hisi_sec_smmu_set_feature_by_idr0(u32 reg, u32 reg_s,
	struct hisi_sec_smmu_device *smmu)
{
	if (reg & HISI_SEC_IDR0_SEV)
		smmu->features |= HISI_SEC_SMMU_FEAT_SEV;

	if (reg_s & HISI_SEC_IDR0_MSI)
		smmu->features |= HISI_SEC_SMMU_FEAT_MSI;

	if (reg & HISI_SEC_IDR0_HYP)
		smmu->features |= HISI_SEC_SMMU_FEAT_HYP;

	if (reg_s & HISI_SEC_IDR0_STALL_MODEL)
		smmu->features |= HISI_SEC_SMMU_FEAT_STALLS;

	if (reg & HISI_SEC_IDR0_S1P)
		smmu->features |= HISI_SEC_SMMU_FEAT_TRANS_S1;

	if (reg & HISI_SEC_IDR0_S2P)
		smmu->features |= HISI_SEC_SMMU_FEAT_TRANS_S2;

	if (!(reg & (HISI_SEC_IDR0_S1P | HISI_SEC_IDR0_S2P))) {
		tloge("smmuid:%d no translation support!\n", smmu->smmuid);
		return -ENXIO;
	}

	return 0;
}

static void hisi_sec_smmu_switch_idr5_oas(u32 reg,
	struct hisi_sec_smmu_device *smmu)
{
	switch (reg & HISI_SEC_IDR5_OAS_MASK << HISI_SEC_IDR5_OAS_SHIFT) {
	case HISI_SEC_IDR5_OAS_32_BIT:
		smmu->oas = HISI_SMMU_ADDR_SIZE_32;
		break;
	case HISI_SEC_IDR5_OAS_36_BIT:
		smmu->oas = HISI_SMMU_ADDR_SIZE_36;
		break;
	case HISI_SEC_IDR5_OAS_40_BIT:
		smmu->oas = HISI_SMMU_ADDR_SIZE_40;
		break;
	case HISI_SEC_IDR5_OAS_42_BIT:
		smmu->oas = HISI_SMMU_ADDR_SIZE_42;
		break;
	case HISI_SEC_IDR5_OAS_44_BIT:
		smmu->oas = HISI_SMMU_ADDR_SIZE_44;
		break;
	case HISI_SEC_IDR5_OAS_48_BIT:
		smmu->oas = HISI_SMMU_ADDR_SIZE_48;
		break;
	default:
		tloge("smmuid:%d unknown output address size. Truncating to 48-bit\n",
			smmu->smmuid);
		smmu->oas = HISI_SMMU_ADDR_SIZE_48;
	}
}

static int hisi_sec_smmu_set_table_format(u32 reg,
	struct hisi_sec_smmu_device *smmu)
{
	/* We only support the AArch64 table format at present */
	switch (reg & HISI_SEC_IDR0_TTF_MASK << HISI_SEC_IDR0_TTF_SHIFT) {
	case HISI_SEC_IDR0_TTF_AARCH32_64:
		smmu->ias = HISI_SMMU_ADDR_SIZE_40;
	/* Fallthrough */
	case HISI_SEC_IDR0_TTF_AARCH64:
		break;
	default:
		tloge("smmuid:%d AArch64 table format not supported!\n",
			smmu->smmuid);
		return -ENXIO;
	}
	return 0;
}

static int hisi_sec_smmu_device_probe(struct hisi_sec_smmu_device *smmu)
{
	u32 reg;
	u32 reg_s;

	/* HISI_SEC_IDR0 */
	reg = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_IDR0);
	/* IDR0_S only for IDR0_MSI & IDR0_STALL_MODEL */
	reg_s = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_IDR0_S);

	/*
	 * Translation table endianness.
	 * We currently require the same endianness as the CPU, but this
	 * could be changed later by adding a new IO_PGTABLE_QUIRK.
	 */
	if (hisi_sec_smmu_switch_idr0_ttendain(reg, smmu))
		return -ENXIO;

	if (hisi_sec_smmu_set_feature_by_idr0(reg, reg_s, smmu))
		return -ENXIO;

	if (hisi_sec_smmu_set_table_format(reg, smmu))
		return -ENXIO;

	/* ASID/VMID sizes */
	smmu->asid_bits = reg & HISI_SEC_IDR0_ASID16 ?
		HISI_SMMU_ID_SIZE_16 : HISI_SMMU_ID_SIZE_8;
	smmu->vmid_bits = reg & HISI_SEC_IDR0_VMID16 ?
		HISI_SMMU_ID_SIZE_16 : HISI_SMMU_ID_SIZE_8;

	/* HISI_SEC_IDR1 */
	reg = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_IDR1);
	if (reg & (HISI_SEC_IDR1_TABLES_PRESET | HISI_SEC_IDR1_QUEUES_PRESET |
			  HISI_SEC_IDR1_REL)) {
		tloge("smmuid:%d embedded implementation not supported\n",
			smmu->smmuid);
		return -ENXIO;
	}
	/* Queue sizes, capped at 4k */
	smmu->cmdq.q.max_n_shift = min((u32)CMDQ_MAX_SZ_SHIFT,
		(reg >> HISI_SEC_IDR1_CMDQ_SHIFT) & HISI_SEC_IDR1_CMDQ_MASK);
	if (!smmu->cmdq.q.max_n_shift) {
		/* Odd alignment restrictions on the base, so ignore for now */
		tloge("smmuid:%d unit-length command queue not supported\n",
			smmu->smmuid);
		return -ENXIO;
	}

	smmu->evtq.q.max_n_shift = min((u32)EVTQ_MAX_SZ_SHIFT,
		(reg >> HISI_SEC_IDR1_EVTQ_SHIFT) & HISI_SEC_IDR1_EVTQ_MASK);

	/* SID/SSID sizes */
	smmu->ssid_bits =
		(reg >> HISI_SEC_IDR1_SSID_SHIFT) & HISI_SEC_IDR1_SSID_MASK;
	/*we only need 64 cd entries now*/
	if (smmu->sid_bits > HISI_SSID_MAX_BITS)
		smmu->sid_bits = HISI_SSID_MAX_BITS;

	reg = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_IDR1_S);
	smmu->sid_bits =
		(reg >> HISI_SEC_IDR1_SID_SHIFT) & HISI_SEC_IDR1_SID_MASK;
	/*we only need 64 ste entries now*/
	if (smmu->sid_bits > HISI_SID_MAX_BITS)
		smmu->sid_bits = HISI_SID_MAX_BITS;

	/* HISI_SEC_IDR5 */
	reg = hisi_readl(smmu->platform_info.base + HISI_SEC_SMMU_IDR5);
	/* Maximum number of outstanding stalls */
	smmu->evtq.max_stalls = (reg >> HISI_SEC_IDR5_STALL_MAX_SHIFT) &
				HISI_SEC_IDR5_STALL_MAX_MASK;

	/* Output address size */
	hisi_sec_smmu_switch_idr5_oas(reg, smmu);

	smmu->ias = max(smmu->ias, smmu->oas);

	tlogd("out %s ias %lu-bit, oas %lu-bit (features 0x%08x)\n", __func__,
		smmu->ias, smmu->oas, smmu->features);

	return 0;
}

static void hisi_smmu_group_add_device(
	struct hisi_tee_smmu_group *grp, struct hisi_sec_smmu_device *smmu)
{
	u32 sid;
	u64 *step = NULL;

	if (!grp) {
		tloge("smmuid:%d gp is null smmu add to group is failed\n",
			smmu->smmuid);
		return;
	}

	for (sid = 0; sid < smmu->strtab_cfg.num_l1_ents; sid++) {
		struct hisi_sec_smmu_strtab_ent ste = {
			.valid = true,
			.bypass = false,
			.cdtab_cfg = &grp->cdtab_cfg,
		};

		if ((sid == smmu->platform_info.sid_bypass_wr_ai) ||
			(sid == smmu->platform_info.sid_bypass_rd_ai) ||
			(sid == smmu->platform_info.sid_bypass_wr_sdma) ||
			(sid == smmu->platform_info.sid_bypass_rd_sdma)) {
#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
			hisi_smmu_master_write(smmu,
				(SSID_V_MASK_EN | MSTR_BYPASS),
				SMMU_MSTR_SMRX_0(sid));
#endif
			ste.bypass = true;
			tlogd("%s:set sid %d bypass\n", __func__, sid);
		}
		/*
		 * This func is diff with smmu supporting 2lvl strtab, but we
		 * only consider linear strtab now
		 */
		step = hisi_sec_smmu_get_step_for_sid(smmu, sid);

		hisi_sec_smmu_write_strtab_ent(step, &ste);
	}
}

int hisi_sec_smmu_hw_set(struct hisi_sec_smmu_device *smmu)
{
	int ret;

	if (!smmu) {
		tloge("%s:invalid params!\n", __func__);
		return -ENOMEM;
	}
	ret = hisi_sec_smmu_device_probe(smmu);
	if (ret) {
		tloge("%s:hisi_sec_smmu_device_probe failed (%d)\n", __func__,
			ret);
		return ret;
	}
	ret = hisi_sec_smmu_init_structures(smmu);
	if (ret) {
		tloge("%s:hisi_sec_smmu_init_structures failed (%d)\n",
			__func__, ret);
		return ret;
	}
	ret = hisi_sec_smmu_device_reset(smmu);
	if (ret) {
		tloge("%s:hisi_sec_smmu_device_reset failed (%d)\n", __func__,
			ret);
		return ret;
	}

	hisi_smmu_group_add_device(g_hisi_tee_smmu_group, smmu);
	return ret;
}

int hisi_aicpu_intr_addr_remap(void)
{
	unsigned int asid_mem_base;
	unsigned int va_mem_base;
	int ret;

	if (g_pgfault_asid_addr) {
		ret = sre_mmap(g_pgfault_asid_addr, sizeof(u32), &asid_mem_base,
			non_secure, non_cache);
		if (ret || (!asid_mem_base)) {
			tloge("%s,failed to asid sre_mmap!ret:0x%x\n", __func__, ret);
			return -EINVAL;
		}
		if (g_hisi_mmu_dev)
			g_hisi_mmu_dev->asid_mem_base = (void *)asid_mem_base;
	}

	if (g_pgfault_va_addr_g) {
		ret = sre_mmap(g_pgfault_va_addr_g, sizeof(u32), &va_mem_base,
			non_secure, non_cache);
		if (ret || (!va_mem_base)) {
			tloge("%s,failed to va sre_mmap!ret:0x%x\n", __func__, ret);
			return -EINVAL;
		}
		if (g_hisi_mmu_dev)
			g_hisi_mmu_dev->va_mem_base = (void *)(uintptr_t)va_mem_base;
	}

	return 0;
}

int hisi_smmu_poweron_reg_set(struct hisi_sec_smmu_device *smmu)
{
	u32 reg;
	int ret;

	ret = hisi_smmu_reg_set(
		smmu, SMMU_LP_REQ, SMMU_LP_ACK, TCU_QREQN_CG, TCU_QACCEPTN_CG);
	if (ret) {
		tloge("TCU_QACCEPTN_CG failed !%s\n", __func__);
		return -EINVAL;
	}
	ret = hisi_smmu_reg_set(
		smmu, SMMU_LP_REQ, SMMU_LP_ACK, TCU_QREQN_PD, TCU_QACCEPTN_PD);
	if (ret) {
		tloge("TCU_QACCEPTN_PD failed !%s\n", __func__);
		return -EINVAL;
	}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
	hisi_writel(0, smmu->platform_info.base + SMMU_TBU_CR_S);

	ret = hisi_smmu_reg_set(
		smmu, SMMU_TBU_CR, SMMU_TBU_CRACK, TBU_EN_REQ, TBU_EN_ACK);
	if (ret) {
		tloge("TBU_EN_ACK failed !%s\n", __func__);
		return -EINVAL;
	}
	reg = hisi_readl(smmu->platform_info.base + SMMU_TBU_CRACK);
	if (!(reg & TBU_CONNECTED)) {
		tloge("TBU_CONNECTED failed!%s\n", __func__);
		return -EINVAL;
	}
#endif
	return 0;
}

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
static int __smmu_master_end_check(
	u32 smmubase, unsigned long mstrbase, u32 end, u32 val)
{
	u32 reg;
	u32 check_times = 0;

	do {
		reg = hisi_readl(smmubase + mstrbase + end);
		if (reg == val)
			break;
		hisi_udelay(1);
		if (++check_times >= MAX_CHECK_TIMES) {
			tloge("%s:MSTR_END_CHECK failed,reg:0x%x\n", __func__,
				reg);
			return -EINVAL;
		}
	} while (1);

	return 0;
}

int hisi_smmu_master_end_check(struct hisi_sec_smmu_device *smmu)
{
	if (__smmu_master_end_check(smmu->platform_info.base,
		    HISI_MASTER_0_BASE, MSTR_END_ACK(0),
		    smmu->platform_info.sid_mstr0_end0_val))
		return -EINVAL;

	if (__smmu_master_end_check(smmu->platform_info.base,
		    HISI_MASTER_0_BASE, MSTR_END_ACK(1),
		    smmu->platform_info.sid_mstr0_end1_val))
		return -EINVAL;

	if (__smmu_master_end_check(smmu->platform_info.base,
		    HISI_MASTER_1_BASE, MSTR_END_ACK(0),
		    smmu->platform_info.sid_mstr1_end0_val))
		return -EINVAL;

	if (__smmu_master_end_check(smmu->platform_info.base,
		    HISI_MASTER_1_BASE, MSTR_END_ACK(1),
		    smmu->platform_info.sid_mstr1_end1_val))
		return -EINVAL;

	return 0;
}
#endif

struct hisi_sec_smmu_device *hisi_smmu_poweroff_find_smmu(unsigned int smmuid)
{
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *tmp = NULL;

	list_for_each_safe(p, n, &g_hisi_tee_smmu_group->smmu_list) {
		tmp = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (tmp && (tmp->smmuid == smmuid) &&
			(tmp->status != hisi_sec_smmu_disable)) {
			break;
		}
	}
	return tmp;
}

int hisi_smmu_check_tbu_disconnected(struct hisi_sec_smmu_device *smmu)
{
	u32 reg = 0;

#if (TRUSTEDCORE_CHIP_CHOOSE != WITH_CHIP_DENVER)
	int ret;
	u32 val;

	val = hisi_readl(smmu->platform_info.base + SMMU_TBU_CR);
	val &= ~TBU_EN_REQ;
	hisi_writel(val, smmu->platform_info.base + SMMU_TBU_CR);
	ret = hisi_readl_relaxed_poll_timeout(
		smmu->platform_info.base + SMMU_TBU_CRACK, reg,
		reg & TBU_EN_ACK, HISI_SEC_SMMU_POLL_TIMEOUT_US);
	if (ret) {
		tloge("TBU_EN_ACK failed !%s\n", __func__);
		return -ETBUON;
	}

	reg = hisi_readl(smmu->platform_info.base + SMMU_TBU_CRACK);
	if (reg & TBU_CONNECTED) {
		tloge("TBU is still connected !%s\n", __func__);
		return -ETBUON;
	}

	hisi_writel(1, smmu->platform_info.base + SMMU_TBU_CR_S);
#else
	u32 check_times = 0;

	for (int i = 0; i < TBU_MAX_NUM; i++) {
		check_times = 0;
		do {
			hisi_udelay(1);
			reg = hisi_readl(smmu->platform_info.base + HISI_SEC_TCU_NODE_STATUS + i * ADDRESS_WIDTH);
			reg &= TBU_IS_CONNECTED;

			if (!reg)
				break;
			if (++check_times >= MAX_CHECK_TIMES) {
				tloge("there are some TBU is connected!%s,i:%d,reg:0x%x\n",
					__func__, i, reg);
				return -ETBUON;
			}
		} while (1);
	}
#endif
	return 0;
}

#ifdef TEE_SVM_DEBUG
static int hisi_svm_instance_dbgfs_check_input(
	struct hisi_tee_svm *svm, unsigned int **desc,
	struct hisi_sec_smmu_s1_cfg **s1_cfg,
	struct hisi_tee_smmu_group **smmu_group)
{
	struct hisi_sec_smmu_domain *smmu_domain = NULL;

	if (!svm)
		return -EINVAL;

	smmu_domain = svm->smmu_domain;
	if (!smmu_domain)
		return -EINVAL;

	*smmu_group = smmu_domain->smmu_grp;
	if (!(*smmu_group))
		return -EINVAL;

	*s1_cfg = &smmu_domain->s1_cfg;
	if (!(*s1_cfg))
		return -EINVAL;

	*desc = (unsigned int *)smmu_domain->s1_cfg.cdptr;
	if (!(*desc))
		return -EINVAL;

	return 0;
}

static void hisi_svm_instance_dbgfs_show(struct hisi_tee_svm *svm)
{
	unsigned int *desc = NULL;
	struct hisi_sec_smmu_s1_cfg *s1_cfg = NULL;
	struct hisi_tee_smmu_group *smmu_group = NULL;
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *smmu = NULL;
	u64 *step = NULL;
	struct hisi_sec_smmu_strtab_cfg *cfg = NULL;
	unsigned int *ste = NULL;

	if (hisi_svm_instance_dbgfs_check_input(svm,
		&desc, &s1_cfg, &smmu_group))
		return;

	tloge("into %s\n", __func__);

	tloge("%16s\t%16s\t%16s\t%16s\t%16s\t%16s\n", "pid", "ssid", "asid",
		"ttbr", "tcr", "mair");

	tloge("%16x\t%16x\t%16x\t%16llx\t%16llx\t%16llx\n", svm->pid,
		s1_cfg->cd.ssid, s1_cfg->cd.asid, s1_cfg->cd.ttbr,
		s1_cfg->cd.tcr, s1_cfg->cd.mair);

	/* dump the former 32bytes in cd entry */
	tloge("%16s\t%16x\t%16x\t%16x\t%16x\n", "context desc[0]", desc[0],
		desc[1], desc[2], desc[3]);
	tloge("%16s\t%16x\t%16x\t%16x\t%16x\n", "context desc[1]", desc[4],
		desc[5], desc[6], desc[7]);

	list_for_each_safe(p, n, &smmu_group->smmu_list) {
		smmu = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		cfg = &smmu->strtab_cfg;
		step = &cfg->strtab[0]; /* all ste entry are the same */
		ste = (unsigned int *)step;
		tloge("smmuid:%d\n", smmu->smmuid);
		/* dump the former 32bytes ste entry */
		tloge("%16s\t%16x\t%16x\t%16x\t%16x\n", "ste[0]", ste[0],
			ste[1], ste[2], ste[3]);
		tloge("%16s\t%16x\t%16x\t%16x\t%16x\n", "ste[1]", ste[4],
			ste[5], ste[6], ste[7]);
		tloge("bypass sid:ai_w:%d,ai_r:%d,sdma_w:%d,sdma_r:%d\n",
			smmu->platform_info.sid_bypass_wr_ai,
			smmu->platform_info.sid_bypass_rd_ai,
			smmu->platform_info.sid_bypass_wr_sdma,
			smmu->platform_info.sid_bypass_rd_sdma);
	}

	tloge("out %s\n", __func__);
}

static void hisi_sec_smmu_structures_dump(struct hisi_sec_smmu_device *smmu)
{
	tloge("smmuid:%d +++++++++++ dump smmu body start +++++++++++\n", smmu->smmuid);

	tloge("smmu ias      : 0x%08lx\n", smmu->ias);
	tloge("smmu oas      : 0x%08lx\n", smmu->oas);
	tloge("smmu feature  : 0x%08x\n", smmu->features);
	tloge("smmu options  : 0x%08x\n", smmu->options);
	tloge("smmu asid_bits: 0x%08x\n", smmu->asid_bits);
	tloge("smmu vmid_bits: 0x%08x\n", smmu->vmid_bits);
	tloge("smmu ssid_bits: 0x%08x\n", smmu->ssid_bits);
	tloge("smmu sid_bits : 0x%08x\n", smmu->sid_bits);
	tloge("smmu status   : 0x%08x\n", smmu->status);
	tloge("smmu err irq  : 0x%08x\n", smmu->gerr_irq);

	tloge("smmu cmdq irq        : 0x%08x\n", smmu->cmdq.q.irq);
	tloge("smmu cmdq base_phy   : 0x%016llx\n", smmu->cmdq.q.base_phy);
	tloge("smmu cmdq base       : %pK\n", smmu->cmdq.q.base);
	tloge("smmu cmdq q_base_0   : 0x%08x\n", smmu->cmdq.q.q_base_0);
	tloge("smmu cmdq q_base_1   : 0x%08x\n", smmu->cmdq.q.q_base_1);
	tloge("smmu cmdq max_n_shift: 0x%x\n", smmu->cmdq.q.max_n_shift);
	tloge("smmu cmdq cons       : 0x%x\n", smmu->cmdq.q.cons);
	tloge("smmu cmdq prod       : 0x%x\n", smmu->cmdq.q.prod);
	tloge("smmu cmdq *prod_reg  : 0x%08x\n", smmu->cmdq.q.prod_reg);
	tloge("smmu cmdq *cons_reg  : 0x%08x\n", smmu->cmdq.q.cons_reg);
	tloge("smmu cmdq ent_dwords : 0x%016lx\n", smmu->cmdq.q.ent_dwords);

	tloge("smmu eventq irq        : 0x%08x\n", smmu->evtq.q.irq);
	tloge("smmu eventq base_phy   : 0x%016llx\n", smmu->evtq.q.base_phy);
	tloge("smmu eventq base       : %pK\n", smmu->evtq.q.base);
	tloge("smmu eventq q_base_0   : 0x%08x\n", smmu->evtq.q.q_base_0);
	tloge("smmu eventq q_base_1   : 0x%08x\n", smmu->evtq.q.q_base_1);
	tloge("smmu eventq max_n_shift: 0x%x\n", smmu->evtq.q.max_n_shift);
	tloge("smmu eventq cons       : 0x%x\n", smmu->evtq.q.cons);
	tloge("smmu eventq prod       : 0x%x\n", smmu->evtq.q.prod);
	tloge("smmu eventq *prod_reg  : 0x%08x\n", smmu->evtq.q.prod_reg);
	tloge("smmu eventq *cons_reg  : 0x%08x\n", smmu->evtq.q.cons_reg);
	tloge("smmu eventq ent_dwords : 0x%016lx\n", smmu->evtq.q.ent_dwords);

	tloge("smmu str config phy : 0x%016llx\n", smmu->strtab_cfg.strtab_phy);
	tloge("smmu str config vir : %pK\n", smmu->strtab_cfg.strtab);
	tloge("smmu str config sid : 0x%08x\n", smmu->strtab_cfg.num_l1_ents);
	tloge("smmu str config strbase_0 : 0x%08x\n", smmu->strtab_cfg.strtab_base_0);
	tloge("smmu str config strbase_1 : 0x%08x\n", smmu->strtab_cfg.strtab_base_1);
	tloge("smmu str config strbase_cfg: 0x%08x\n", smmu->strtab_cfg.strtab_base_cfg);

	tloge("smmuid:%d +++++++++++ dump smmu body end +++++++++++\n", smmu->smmuid);
}

void hisi_smmu_group_dump(void)
{
	struct list_head *p = NULL;
	struct list_head *n = NULL;
	struct hisi_sec_smmu_device *smmu = NULL;
	struct hisi_tee_smmu_group *grp = g_hisi_tee_smmu_group;

	tloge("======== %s start========\n", __func__);
	if (!grp)
		return;

	tloge("ias       : %lu\n", grp->ias);
	tloge("oas       : %lu\n", grp->oas);
	tloge("status    : 0x%08x\n", grp->status);
	tloge("ssid bits : %d\n", grp->ssid_bits);

	tloge("cdtab     : %pK\n", grp->cdtab_cfg.cdtab);
	tloge("cdtab_phy : 0x%016llx\n", grp->cdtab_cfg.cdtab_phy);
	tloge("size      : 0x%016lx\n", grp->cdtab_cfg.sz);

	list_for_each_safe(p, n, &grp->smmu_list) {
		smmu = list_entry(p, struct hisi_sec_smmu_device, smmu_node);
		if (!smmu) {
			tloge("%s smmu is null\n", __func__);
			return;
		}
		if (smmu->status == hisi_sec_smmu_enable)
			hisi_sec_smmu_structures_dump(smmu);
	}

	tloge("================= %s end===============\n", __func__);
}
#endif
