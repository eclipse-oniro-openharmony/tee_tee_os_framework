/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sec smmu
 * Create: 2020-3-1
 */

#ifndef __HISI_SEC_SMMU_H
#define __HISI_SEC_SMMU_H

#include <sys/hm_types.h>
#include <stdbool.h>

#define MAX_SSID_NUM   64
#define SMMU_STRUCT_LEN 8

enum sec_smmu_q {
	SMMU_CMQ,
	SMMU_EVENTQ,
	SMMU_MAXQ
};

enum sec_smmu_status {
	SMMU_DISABLE,
	SMMU_ENABLE
};

struct sec_smmu_queue {
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

struct sec_smmu_cmdq {
	struct sec_smmu_queue q;
	pthread_mutex_t lock;
};

struct sec_smmu_evtq {
	struct sec_smmu_queue q;
	u32 max_stalls;
};

struct sec_smmu_cmdq_ent {
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

struct sec_smmu_ste {
	u64 entry[SMMU_STRUCT_LEN];
};

struct sec_smmu_cd {
	u64 entry[SMMU_STRUCT_LEN];
};

struct sec_smmu_base {
	uintptr_t ste_base;
	u64 ste_virt;
	uintptr_t cd_base;
	u64 cd_virt;
	uintptr_t cmd_base;
	u64 cmd_virt;
	uintptr_t evt_base;
	u64 evt_virt;
	uintptr_t pgd_base;
	u64 pgd_virt;
};

struct sec_smmu_device {
	u64 features;
	char *name;
	u32 base;
	struct sec_smmu_ste *ste;
	struct sec_smmu_base base_addr;
	u64 strtab_base;
	u32 strtab_base_cfg;
	u32 strtab_size;
	u32 ssid_bits;
	u32 sid_bits;
	u32 vmid_bits;
	u32 asid_bits;
	u32 pgsize_bitmap;
	u32 oas;
	u32 ias;
	u32 combined_irq;
	u32 stat;
	u32 smmuid;
	u32 pw_ref;
	int event_flag;
	struct sec_smmu_cmdq cmdq;
	struct sec_smmu_evtq evtq;
	int ssid_map[MAX_SSID_NUM];
	pthread_mutex_t mutex;
	pthread_t evt_thread;
	pthread_mutex_t evt_lock;
	pthread_cond_t evt_happen;
};

struct sec_smmu_struct_info {
	u32 struct_phys;
	u32 struct_virt;
	u32 struct_size;
};
/* STE */
#define HISI_STRTAB_STE_S1_CD_MAX	(0x6ULL << 59)
#define HISI_STRTAB_STE_S1_DSS	3
#define HISI_STRTAB_STE_0_V	(1ULL << 0)
#define HISI_STRTAB_STE_0_CFG_SHIFT	1
#define HISI_STRTAB_STE_0_CFG_BYPASS	(4ULL << HISI_STRTAB_STE_0_CFG_SHIFT)
#define HISI_STRTAB_STE_0_CFG_S1_TRANS	(5ULL << HISI_STRTAB_STE_0_CFG_SHIFT)
#define HISI_STRTAB_STE_0_S1CTXPTR_SHIFT 6
#define HISI_STRTAB_STE_0_S1CTXPTR_MASK	0x3ffffffffffULL
#define HISI_STRTAB_STE_1_STRW_NSEL1	0ULL
#define HISI_STRTAB_STE_1_STRW_SHIFT	30

#define HISI_STRTAB_STE_2_S2VMID_SHIFT	0
#define HISI_STRTAB_STE_2_S2VMID_MASK	0xffffUL
#define HISI_STRTAB_STE_2_S2VMID_OFFSET	2

/* CD CONTEXT */
#define HISI_CTXDESC_CD_0_V	(1ULL << 31)
#define HISI_CTXDESC_CD_0_TCR_IPS_SHIFT	32
#define HISI_CTXDESC_CD_0_AA64	(1ULL << 41)
#define HISI_CTXDESC_CD_0_S     (1ULL << 44)
#define HISI_CTXDESC_CD_0_R	(1ULL << 45)
#define HISI_CTXDESC_CD_0_A	(1ULL << 46)
#define HISI_CTXDESC_CD_0_ASET_SHIFT	47
#define HISI_CTXDESC_CD_0_ASET_PRIVATE	(1ULL << HISI_CTXDESC_CD_0_ASET_SHIFT)
#define HISI_CTXDESC_CD_0_ASID_SHIFT	48
/* can support 3 level page table */
#define HISI_CTXDESC_CD_0_T0SZ	(0x19ULL << 0)
/* 48bits */
#define HISI_CTXDESC_CD_IPS	(0x5ULL << HISI_CTXDESC_CD_0_TCR_IPS_SHIFT)
#define HISI_CTXDESC_CD_1_TTB0_SHIFT	4
#define HISI_CTXDESC_CD_1_TTB0_MASK	0xfffffffffffUL
#define HISI_CTXDESC_CD_1_EPD1	(1ULL << 30)

#define hisi_lpae_mair_attr_shift(n)	((n) << 3)
#define HISI_LPAE_MAIR_ATTR_MASK	0xff
#define HISI_LPAE_MAIR_ATTR_DEVICE	0x04
#define HISI_LPAE_MAIR_ATTR_NC	0x44
#define HISI_LPAE_MAIR_ATTR_WBRWA	0xff
#define HISI_LPAE_MAIR_ATTR_IDX_NC	0
#define HISI_LPAE_MAIR_ATTR_IDX_CACHE	1
#define HISI_LPAE_MAIR_ATTR_IDX_DEV	2

#define HISI_EVENTQ_MAX_STALLS   0x10
#define HISI_STRTAB_BASE_ADDR_SHIFT	6
#define HISI_STRTAB_BASE_ADDR_MASK	0x3ffffffffffULL

#define STRTAB_STE_2_S2VMID_SHIFT	0
#define SMMU_TCU_SIRQ_MEDIA1	467
#define SMMU_TCU_SIRQ_MEDIA2	469
#define SMMU_TCU_SIRQ_NPU	476
#define MAX_CMD_TIMEOUT		3
#define SMMU_TCU_CTRL_ENABLE	0x3
#define REG_EQUAL	0
#define REG_AND		1
#define REG_AND_NOT	2
#define SEC_SMMU_UDEALY  1000
#define DWORD_BYTES_SHIFT  3
#define CD_MAIR_INDEX   3
#define SMMU_STREM_ENABLE 0
#define SMMU_STREM_BYPASS 1

#define pw_ref(smmu) ((smmu)->pw_ref)
#define pw_ref_inc(smmu) (pw_ref(smmu)++)
#define pw_ref_dec(smmu) (pw_ref(smmu) ? pw_ref(smmu)-- : 0)

extern void irq_lock();
extern void irq_unlock();
extern u64 *hisi_sion_get_pgd_virt(unsigned int protect_id);
extern int npu_get_res_mem_of_smmu(uintptr_t *phy_addr_ptr,
				uintptr_t *virt_addr_ptr, u32 *len_ptr);

#endif
