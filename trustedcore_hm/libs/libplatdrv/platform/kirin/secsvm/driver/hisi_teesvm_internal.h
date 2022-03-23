/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: secure os teesvm module
 * This header is only used within the teesvm module
 * Outer modules should include svm.h to use teesvm's api
 * Create: 2019-12-26
 */
#ifndef __TEESVM_INNER_H
#define __TEESVM_INNER_H

#include "pthread.h"
#include "list.h"
#include "hmdrv_stub.h"
#include "smmuv3.h"
#include "svm.h"

/* copy from ta_framework.h */
#define BITS_PER_LONG sizeof(unsigned long)
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(unsigned long))
#define BIT_MASK(nr) (1UL << ((nr) % BITS_PER_LONG))

#define BITS_PER_BYTE 8
#define BIT_WORD(nr) ((nr) / BITS_PER_LONG)
#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (BITS_PER_LONG - 1)))
#define BITMAP_LAST_WORD_MASK(end) (~0UL >> (-(end) & (BITS_PER_LONG - 1)))
#define ALIGN_DOWN(x, align) ((x) & ~((align)-1))
#define min(a, b) (((a) < (b)) ? (a) : (b))
#define max(a, b) (((a) > (b)) ? (a) : (b))

#define VA_BITS 39
#define SZ_4K 0x00001000
#define SZ_2K 0x00000800
#define HISI_SMMU_CMDQ_SIZE SZ_4K
#define HISI_SMMU_EVTQ_SIZE SZ_4K
#define HISI_SMMU_STE_SIZE SZ_4K
#define HISI_SMMU_CD_SIZE SZ_2K
#define HISI_SMMU_RSV_TOTAL_SIZE (HISI_SMMU_CMDQ_SIZE + \
		HISI_SMMU_EVTQ_SIZE + \
		HISI_SMMU_STE_SIZE + \
		HISI_SMMU_CD_SIZE)
#define DWORD_BYTES_NUM 3
#define EVTQ_INPUT_ADDR_OFFSET 2
#define ADDRESS_WIDTH 4
#define CMDQ_MAX_TIMEOUT_TIMES 10

extern struct hisi_tee_svm *g_hisi_svm_bind;
extern struct hisi_tee_smmu_group *g_hisi_tee_smmu_group;
extern struct hisi_sec_smmu_device *g_hisi_mmu_dev;
extern u64 g_pgfault_asid_addr;
extern u64 g_pgfault_va_addr_g;
extern pthread_mutex_t g_hisi_svm_mutex;
extern pthread_mutex_t g_hisi_svmtlb_mutex;
extern uintptr_t g_smmu_cmdq_base;
extern uintptr_t g_smmu_eventq_base;
extern uintptr_t g_smmu_ste_base;
extern uintptr_t g_smmu_cd_base;
extern void irq_lock(void);
extern void irq_unlock(void);
extern void *malloc_coherent(size_t n);
extern int get_secure_flag_tmp(void);
extern int npu_get_res_mem_of_smmu(uintptr_t *phy_addr, u32 *len);

#define hisi_readx_poll_timeout(op, addr, val, cond, timeout_us)   \
	({                                      \
		int looptime = 0;                   \
		for (;; looptime++) {               \
			(val) = op(addr);               \
			if (cond)                       \
				break;                      \
			if (timeout_us < looptime) {    \
				(val) = op(addr);           \
				break;                      \
			}                               \
		}                                   \
		(cond) ? 0 : -ETIMEDOUT;            \
	})

#define hisi_readl_relaxed_poll_timeout(addr, val, cond, timeout_us) \
	hisi_readx_poll_timeout(hisi_readl, addr, val, cond, timeout_us)

enum hisi_sec_smmu_status {
	hisi_sec_smmu_init = 0,
	hisi_sec_smmu_enable,
	hisi_sec_smmu_disable,
};

enum hisi_smmu_q {
	hisi_smmu_cmdq = 0,
	hisi_smmu_eventq,
	hisi_smmu_q_max,
};

#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_KIRIN990 || TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
enum hisi_svm_id {
	svm_sdma = 0,
	svm_ai,
#if defined(WITH_KIRIN990_CS2)
	svm_ai1,
#endif
	svm_max,
};
#elif (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_ORLANDO || \
	TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_DENVER || \
	TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_LAGUNA || \
	TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BURBANK)
enum hisi_svm_id {
	svm_sdma = 0,
	svm_max,
};
#endif

struct hisi_sec_smmu_cmdq_ent {
	union {
		struct {
			u16 asid;
			u16 vmid;
			bool leaf;
			u64 addr;
		} tlbi;

		struct {
			u32 sid;
			u8 size;
			u64 addr;
		} prefetch;

		struct {
			u32 ssid;
			u32 sid;
			union {
				bool leaf;
				u8 span;
			};
		} cfgi;
	};
	u8 opcode;
};

struct hisi_sec_smmu_queue {
	u64 *base;
	u64 base_phy;
	int irq;
	u32 q_base_0;
	u32 q_base_1;
	u32 prod_reg;
	u32 cons_reg;
	u32 prod;
	u32 cons;
	u32 max_n_shift;
	size_t ent_dwords;
	size_t q_size;
};

struct hisi_sec_smmu_cmdq {
	struct hisi_sec_smmu_queue q;
	pthread_mutex_t lock;
};

struct hisi_sec_smmu_evtq {
	struct hisi_sec_smmu_queue q;
	u32 max_stalls;
};

/* High-level stream table and context descriptor structures */
struct hisi_sec_smmu_strtab_l1_desc {
	u64 *l2ptr;
	u64 l2ptr_phy;
	u8 span;
};

struct hisi_sec_smmu_s1_cfg {
	struct hisi_sec_smmu_ctx_desc {
		u64 ttbr;
		u64 tcr;
		u64 mair;
		u16 ssid;
		u16 asid;
	} cd;

	u64 *cdptr;
	u64 cdptr_phy;
};

struct hisi_sec_smmu_cdtab_cfg {
	u64 *cdtab;
	u64 cdtab_phy;
	size_t sz;
};

struct hisi_sec_smmu_strtab_ent {
	struct hisi_sec_smmu_cdtab_cfg *cdtab_cfg;
	bool valid;
	bool bypass;
};

struct hisi_sec_smmu_strtab_cfg {
	struct hisi_sec_smmu_strtab_l1_desc *l1_desc;
	u64 *strtab;
	u64 strtab_phy;
	u32 num_l1_ents;
	u32 strtab_base_0;
	u32 strtab_base_1;
	u32 strtab_base_cfg;
	u32 strtab_size;
};

struct hisi_sec_smmu_platform_info {
	u32 base;
	u32 sid_bypass_wr_ai;
	u32 sid_bypass_rd_ai;
	u32 sid_bypass_wr_sdma;
	u32 sid_bypass_rd_sdma;
	u32 sid_mstr0_end0_val;
	u32 sid_mstr0_end1_val;
	u32 sid_mstr1_end0_val;
	u32 sid_mstr1_end1_val;
	int smmu_irq;
};

struct hisi_sec_smmu_device {
	struct hisi_sec_smmu_cmdq cmdq;
	struct hisi_sec_smmu_evtq evtq;
	struct hisi_sec_smmu_strtab_cfg strtab_cfg;
	struct list_head smmu_node;
	struct hisi_sec_smmu_platform_info platform_info;
	void *asid_mem_base;
	void *va_mem_base;
	u64 ias; /* IPA */
	u64 oas; /* PA */
	u32 asid_bits;
	u32 vmid_bits;
	u32 ssid_bits;
	u32 sid_bits;
	u32 features;
	u32 options;
	int gerr_irq;
	int event_flag;
	enum hisi_sec_smmu_status status;
	enum hisi_svm_id smmuid;
	pthread_t evt_thread;
	pthread_mutex_t evt_lock;
	pthread_cond_t evt_happen;
};

struct hisi_sec_smmu_domain {
	struct hisi_tee_smmu_group *smmu_grp;
	struct hisi_sec_smmu_s1_cfg s1_cfg;
	pthread_mutex_t init_mutex;
};

struct hisi_sec_svm_pgtable_cfg {
	struct {
		u64 ttbr[2]; /* cd contains two 8-bytes TTB Regs */
		u64 tcr;
		u64 mair[2]; /* cd contains two 8-bytes MAIR Regs */
	} hisi_sec_lpae_s1_cfg;

	u32 ias;
	u32 oas;
};

struct hisi_tee_smmu_group {
	struct hisi_sec_smmu_cdtab_cfg cdtab_cfg;
	struct list_head smmu_list;
	DECLARE_BITMAP(ssid_map, CTXDESC_CD_MAX_SSIDS);
	u64 ias;
	u64 oas;
	u32 ssid_bits;
	enum hisi_sec_smmu_status status;
	pthread_mutex_t sgrp_mtx;
};

static inline int test_and_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK((unsigned int)nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	unsigned long old;

	old = *p;
	*p = old | mask;

	return (old & mask) != 0;
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK((unsigned int)nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p &= ~mask;
}

static inline void hisi_evt_flag_set(struct hisi_sec_smmu_device *smmu)
{
	if (smmu)
		smmu->event_flag = 1;
}

static inline void hisi_evt_flag_unset(struct hisi_sec_smmu_device *smmu)
{
	if (smmu)
		smmu->event_flag = 0;
}

static inline bool queue_full(struct hisi_sec_smmu_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) != Q_WRP(q, q->cons);
}

static inline bool queue_empty(struct hisi_sec_smmu_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) == Q_WRP(q, q->cons);
}

int queue_sync_prod(struct hisi_sec_smmu_queue *q);
int hisi_sec_smmu_device_disable(struct hisi_sec_smmu_device *smmu);
void hisi_sec_smmu_cmdq_skip_err(struct hisi_sec_smmu_device *smmu);
int hisi_aicpu_intr_addr_remap(void);
int hisi_smmu_poweron_reg_set(struct hisi_sec_smmu_device *smmu);
int hisi_sec_smmu_hw_set(struct hisi_sec_smmu_device *smmu);
struct hisi_sec_smmu_domain *hisi_sec_smmu_domain_alloc(void);
void hisi_sec_smmu_domain_free(struct hisi_sec_smmu_domain *smmu_domain);
void hisi_tee_svm_dump_reg(void);
int hisi_smmu_master_end_check(struct hisi_sec_smmu_device *smmu);
int hisi_smmu_reg_unset(struct hisi_sec_smmu_device *smmu, unsigned int req_off,
	unsigned int ack_off, unsigned int req_bit, unsigned int ack_bit);
void hisi_sec_smmu_free_structures(struct hisi_sec_smmu_device *smmu);
void hisi_smmu_group_tlb_inv_context(struct hisi_sec_smmu_domain *cookie);
int hisi_evt_irq_setup(struct hisi_sec_smmu_device *smmu);
void hisi_sec_smmu_domain_draft(struct hisi_sec_smmu_domain *smmu_domain);
int hisi_sec_smmu_domain_finalise(struct hisi_sec_smmu_domain *smmu_domain, struct hisi_tee_svm *svm);
int hisi_sec_smmu_enable_cd(struct hisi_tee_smmu_group *grp, struct hisi_sec_smmu_domain *dom);
void hisi_sec_smmu_disable_cd(struct hisi_tee_smmu_group *grp, struct hisi_sec_smmu_domain *dom);
int hisi_smmu_check_tbu_disconnected(struct hisi_sec_smmu_device *smmu);
struct hisi_sec_smmu_device *hisi_smmu_poweroff_find_smmu(unsigned int smmuid);

#endif

