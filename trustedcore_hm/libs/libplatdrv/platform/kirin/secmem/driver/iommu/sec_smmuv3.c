/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: sec smmuv3 driver
 * Create: 2020-3-1
 */

#include "sec_smmu_com.h"
#include <sre_typedef.h>
#include <drv_cache_flush.h>
#include <drv_mem.h>
#include <ipclib.h>
#include <irqmgr.h>
#include <plat_cfg.h>
#include <sre_hwi.h>
#include "drv_module.h"
#include "mem_page_ops.h"
#include "legacy_mem_ext.h"
#include "register_ops.h"
#include "sre_syscall.h"
#include "tee_log.h"
#include "securec.h"
#include "cc_bitops.h"
#include "pthread.h"
#include "sre_access_control.h"
#include "sre_syscalls_id_ext.h"
#include "secure_gic_common.h"
#include "hm_unistd.h"
#include "hisi_debug.h"
#include "list.h"
#include "drv_module.h"
#include "smmuv3.h"
#include "svm.h"
#include "secmem.h"
#include "secmem_priv.h"
#include "sec_smmu.h"
#include "drv_param_type.h"
#include "global_ddr_map.h"
#include "soc_media1_crg_interface.h"
#include "soc_media2_crg_interface.h"
#include "soc_dmss_interface.h"

#define SMMU_STRUCT_BASE	HISI_RESERVED_TCU_CFG_PHYMEM_BASE
#define SMMU_STRUCT_SIZE	HISI_RESERVED_TCU_CFG_PHYMEM_SIZE
#define DMSS_REG_STEP           0x800
#define REG_NAME_LEN            30

struct sec_smmu_device sec_smmu[] = {
	[SMMU_MEDIA1] = {
		.name	= "media1_smmu",
		.base	= SMMUV3_MEDIA1_TCU_BASE_ADDR,
		.smmuid	= SMMU_MEDIA1,
		.stat	= 0,
		.pw_ref = 0,
		.combined_irq = SMMU_TCU_SIRQ_MEDIA1,
		.crg_vbase = MEDIA_CRG_BASE_ADDR,
	},

	[SMMU_MEDIA2] = {
		.name	= "media2_smmu",
		.base	= SMMUV3_MEDIA2_TCU_BASE_ADDR,
		.smmuid	= SMMU_MEDIA2,
		.stat	= 0,
		.pw_ref = 0,
		.combined_irq = SMMU_TCU_SIRQ_MEDIA2,
		.crg_vbase = SOC_ACPU_MEDIA2_CRG_BASE_ADDR,
	},

	[SMMU_NPU] = {
		.name	= "npu_smmu",
		.base	= SMMUV3_NPU_TCU_BASE_ADDR,
		.smmuid	= SMMU_NPU,
		.stat	= 0,
		.pw_ref = 0,
		.combined_irq = SMMU_TCU_SIRQ_NPU,
	},
};

struct sec_reg_info {
	char name[REG_NAME_LEN];
	uint32_t offset;
};

static struct sec_reg_info media1_crg[] = {
	{ "PERCLKEN0",  SOC_MEDIA1_CRG_PERCLKEN0_ADDR(0) },
	{ "PERSTAT0", SOC_MEDIA1_CRG_PERSTAT0_ADDR(0) },
	{ "PERCLKEN1", SOC_MEDIA1_CRG_PERCLKEN1_ADDR(0) },
	{ "PERSTAT1", SOC_MEDIA1_CRG_PERSTAT1_ADDR(0) },
	{ "PERCLKEN2",  SOC_MEDIA1_CRG_PERCLKEN2_ADDR(0) },
	{ "PERSTAT2",  SOC_MEDIA1_CRG_PERSTAT2_ADDR(0) },
	{ "PERRSTSTAT0", SOC_MEDIA1_CRG_PERRSTSTAT0_ADDR(0) },
	{ "PERRSTSTAT1", SOC_MEDIA1_CRG_PERRSTSTAT1_ADDR(0) },
	{ "PERI_STAT1", SOC_MEDIA1_CRG_PERI_STAT1_ADDR(0) },
	{ "PERI_STAT2", SOC_MEDIA1_CRG_PERI_STAT2_ADDR(0) },

	/* QIC REG INFO */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
	{ "IPCLKRST_BYPASS", SOC_MEDIA1_CRG_IPCLKRST_BYPASS_ADDR(0) },
	{ "QIC_INTR_BUS_DSS", SOC_MEDIA1_CRG_QIC_INTR_BUS_DSS_ADDR(0) },
	{ "QIC_INTR_BUS0_VIVO", SOC_MEDIA1_CRG_QIC_INTR_BUS0_VIVO_ADDR(0) },
	{ "QIC_INTR_BUS1_VIVO", SOC_MEDIA1_CRG_QIC_INTR_BUS1_VIVO_ADDR(0) },
	{ "QIC_BUSY_ISP", SOC_MEDIA1_CRG_QIC_BUSY_ISP_ADDR(0) },
	{ "QIC_BUSY_DSS", SOC_MEDIA1_CRG_QIC_BUSY_DSS_ADDR(0) },
	{ "QIC_BUSY0_VIVO", SOC_MEDIA1_CRG_QIC_BUSY0_VIVO_ADDR(0) },
	{ "QIC_BUSY1_VIVO", SOC_MEDIA1_CRG_QIC_BUSY1_VIVO_ADDR(0) },
	{ "QIC_NONIDLE_PEND",
			SOC_MEDIA1_CRG_INTR_QIC_BUS_NONIDLE_PEND_ADDR(0) },
	{ "QIC_STAT_NONIDLE_PEND",
			SOC_MEDIA1_CRG_INTR_STAT_QIC_BUS_NONIDLE_PEND_ADDR(0) },
#endif
};

static struct sec_reg_info media2_crg[] = {
	{ "PERCLKEN0", SOC_MEDIA2_CRG_PERCLKEN0_ADDR(0) },
	{ "PERSTAT0", SOC_MEDIA2_CRG_PERSTAT0_ADDR(0) },
	{ "PERCLKEN1", SOC_MEDIA2_CRG_PERCLKEN1_ADDR(0) },
	{ "PERSTAT1", SOC_MEDIA2_CRG_PERSTAT1_ADDR(0) },
	{ "PERRSTSTAT0", SOC_MEDIA2_CRG_PERRSTSTAT0_ADDR(0) },
	{ "PERRSTSTAT1", SOC_MEDIA2_CRG_PERRSTSTAT1_ADDR(0) },
	{ "PERI_STAT1", SOC_MEDIA2_CRG_PERI_STAT1_ADDR(0) },
	{ "PERI_STAT2", SOC_MEDIA2_CRG_PERI_STAT2_ADDR(0) },
	{ "STAT_BUS_NONIDLE_PEND",
			SOC_MEDIA2_CRG_INTR_STAT_BUS_NONIDLE_PEND_ADDR(0) },
	{ "BUS_NONIDLE_PEND", SOC_MEDIA2_CRG_INTR_BUS_NONIDLE_PEND_ADDR(0) },
	{ "IPCLKRST_BYPASS", SOC_MEDIA2_CRG_IPCLKRST_BYPASS_ADDR(0) },

	/* QIC REG INFO */
#if (TRUSTEDCORE_CHIP_CHOOSE == WITH_CHIP_BALTIMORE)
	{ "BUS_RT0", SOC_MEDIA2_CRG_QIC_INTR_BUS_RT0_ADDR(0) },
	{ "BUS_RT1", SOC_MEDIA2_CRG_QIC_INTR_BUS_RT1_ADDR(0) },
	{ "BUS_RT2", SOC_MEDIA2_CRG_QIC_INTR_BUS_RT2_ADDR(0) },
	{ "BUS_VCODEC", SOC_MEDIA2_CRG_QIC_INTR_BUS_VCODEC_ADDR(0) },
	{ "BUS_VCODEC_WA0", SOC_MEDIA2_CRG_QIC_INTR_BUS_VCODEC_WA0_ADDR(0) },
	{ "BUS_VCODEC_WA1", SOC_MEDIA2_CRG_QIC_INTR_BUS_VCODEC_WA0_ADDR(0) },
	{ "BUS_BUSY0", SOC_MEDIA2_CRG_QIC_INTR_BUS_BUSY0_ADDR(0) },
	{ "BUS_BUSY1", SOC_MEDIA2_CRG_QIC_INTR_BUS_BUSY1_ADDR(0) },
	{ "BUS_BUSY2", SOC_MEDIA2_CRG_QIC_INTR_BUS_BUSY2_ADDR(0) },
#endif
};

static struct sec_reg_info dmss_asi_dfx[] = {
	{ "ASI_DFX_MODULE", SOC_DMSS_ASI_DFX_MODULE_ADDR(0, 0) },
	{ "ASI_DFX_FIFO", SOC_DMSS_ASI_DFX_FIFO_ADDR(0, 0) },
	{ "ASI_DFX_FSM", SOC_DMSS_ASI_DFX_FSM_ADDR(0, 0) },
	{ "ASI_DFX_OSTD", SOC_DMSS_ASI_DFX_OSTD_ADDR(0, 0) },
	{ "ASI_DFX_RDR0", SOC_DMSS_ASI_DFX_RDR0_ADDR(0, 0) },
	{ "ASI_DFX_RDR1", SOC_DMSS_ASI_DFX_RDR1_ADDR(0, 0) },
	{ "ASI_DFX_WOOO", SOC_DMSS_ASI_DFX_WOOO_ADDR(0, 0) },
	{ "ASI_DFX_INT_EN", SOC_DMSS_ASI_DFX_INT_EN_ADDR(0, 0) },
	{ "ASI_DFX_INT_STATUS", SOC_DMSS_ASI_DFX_INT_STATUS_ADDR(0, 0) },
	{ "ASI_DFX_ABNM_INF0", SOC_DMSS_ASI_DFX_ABNM_INF0_ADDR(0, 0) },
	{ "ASI_DFX_ABNM_INF1", SOC_DMSS_ASI_DFX_ABNM_INF1_ADDR(0, 0) },
	{ "ASI_DFX_ABNM_INF2", SOC_DMSS_ASI_DFX_ABNM_INF2_ADDR(0, 0) },
	{ "ASI_DFX_SEC0", SOC_DMSS_ASI_DFX_SEC0_ADDR(0, 0) },
	{ "ASI_DFX_SEC1", SOC_DMSS_ASI_DFX_SEC1_ADDR(0, 0) },
	{ "ASI_DFX_SEC2", SOC_DMSS_ASI_DFX_SEC2_ADDR(0, 0) },
	{ "ASI_DFX_SEC3", SOC_DMSS_ASI_DFX_SEC3_ADDR(0, 0) },
	{ "ASI_DFX_SEC4", SOC_DMSS_ASI_DFX_SEC4_ADDR(0, 0) },
	{ "ASI_DFX_LOAD", SOC_DMSS_ASI_DFX_LOAD_ADDR(0, 0) },
};

static struct sec_reg_info dmss_dmi_dfx[] = {
	{ "DMI_DFX_MODULE", SOC_DMSS_DMI_DFX_MODULE_ADDR(0, 0) },
	{ "DMI_DFX_FIFO", SOC_DMSS_DMI_DFX_FIFO_ADDR(0, 0) },
	{ "DMI_DFX_WD_FIFO", SOC_DMSS_DMI_DFX_WD_FIFO_ADDR(0, 0) },
	{ "DMI_DFX_ST", SOC_DMSS_DMI_DFX_ST_ADDR(0, 0) },
};

static struct sec_reg_info dmss_ami_dfx[] = {
	{ "AMI_DFX_MODULE", SOC_DMSS_AMI_DFX_MODULE_ADDR(0, 0) },
	{ "AMI_DFX_FIFO0", SOC_DMSS_AMI_DFX_FIFO0_ADDR(0, 0) },
	{ "AMI_DFX_FIFO1", SOC_DMSS_AMI_DFX_FIFO1_ADDR(0, 0) },
	{ "AMI_DFX_ST", SOC_DMSS_AMI_DFX_ST_ADDR(0, 0) },
};

static struct sec_reg_info dmss_glb_dfx[] = {
	{ "GLB_INT_STATUS0", SOC_DMSS_GLB_INT_STATUS0_ADDR(0) },
	{ "GLB_INT_CLEAR0", SOC_DMSS_GLB_INT_CLEAR0_ADDR(0) },
	{ "GLB_INT_STATUS1", SOC_DMSS_GLB_INT_STATUS1_ADDR(0) },
	{ "GLB_INT_CLEAR1", SOC_DMSS_GLB_INT_CLEAR1_ADDR(0) },
	{ "GLB_EXCLU", SOC_DMSS_GLB_EXCLU_ADDR(0) },
	{ "GLB_DFX_MODULE", SOC_DMSS_GLB_DFX_MODULE_ADDR(0) },
	{ "GLB_DFX_FIFO", SOC_DMSS_GLB_DFX_FIFO_ADDR(0) },
	{ "GLB_DFX_RBUF_FIFO", SOC_DMSS_GLB_DFX_RBUF_FIFO_ADDR(0) },
	{ "GLB_DFX_PTRN_RT0", SOC_DMSS_GLB_DFX_PTRN_RT0_ADDR(0) },
	{ "GLB_DFX_PTRN_RT1", SOC_DMSS_GLB_DFX_PTRN_RT1_ADDR(0) },
	{ "GLB_DFX_PTRN_RT2", SOC_DMSS_GLB_DFX_PTRN_RT2_ADDR(0) },
	{ "GLB_DFX_LOAD", SOC_DMSS_GLB_DFX_LOAD_ADDR(0) },
};

static struct sec_reg_info tcu_cfg_regs[] = {
	{ "SMMU_S_CR0",             HISI_SEC_SMMU_CR0_S  },
	{ "SMMU_S_CR0ACK",          HISI_SEC_SMMU_CR0ACK_S  },
	{ "SMMU_S_STRTAB_BASE0",    HISI_SEC_SMMU_STRTAB_BASE_S  },
	{ "SMMU_S_STRTAB_BASE1",    HISI_SEC_SMMU_STRTAB_BASE_H_S  },
	{ "SMMU_S_STRTAB_BASE_CFG", HISI_SEC_SMMU_STRTAB_BASE_CFG_S  },
	{ "SMMU_S_CMDQ_BASE0",      HISI_SEC_SMMU_CMDQ_BASE_S  },
	{ "SMMU_S_CMDQ_BASE1",      HISI_SEC_SMMU_CMDQ_BASE_H_S  },
	{ "SMMU_S_CMDQ_PROD",       HISI_SEC_SMMU_CMDQ_PROD_S  },
	{ "SMMU_S_CMDQ_CONS",       HISI_SEC_SMMU_CMDQ_CONS_S  },
	{ "SMMU_S_EVENTQ_BASE0",    HISI_SEC_SMMU_EVTQ_BASE_S  },
	{ "SMMU_S_EVENTQ_BASE1",    HISI_SEC_SMMU_EVTQ_BASE_H_S  },
	{ "SMMU_S_EVENTQ_PROD",     HISI_SEC_SMMU_EVTQ_PROD_S  },
	{ "SMMU_S_EVENTQ_CONS",     HISI_SEC_SMMU_EVTQ_CONS_S  },
};

static struct sec_smmu_struct_info struct_info;
static int sec_smmu_ste_fill(struct sec_smmu_device *smmu, u32 sid, int bypass);

/* Low-level queue manipulation functions */
static bool queue_full(struct sec_smmu_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) != Q_WRP(q, q->cons);
}

static bool queue_empty(struct sec_smmu_queue *q)
{
	return Q_IDX(q, q->prod) == Q_IDX(q, q->cons) &&
	       Q_WRP(q, q->prod) == Q_WRP(q, q->cons);
}

static void queue_sync_cons(struct sec_smmu_queue *q)
{
	q->cons = hisi_readl(q->cons_reg);
}

static void queue_inc_cons(struct sec_smmu_queue *q)
{
	u32 cons = (Q_WRP(q, q->cons) | Q_IDX(q, q->cons)) + 1;

	q->cons = Q_OVF(q, q->cons) | Q_WRP(q, cons) | Q_IDX(q, cons);
	hisi_writel(q->cons, q->cons_reg);
}

static int queue_sync_prod(struct sec_smmu_queue *q)
{
	int ret = 0;
	u32 prod = hisi_readl(q->prod_reg);

	if (Q_OVF(q, prod) != Q_OVF(q, q->prod))
		ret = -EOVERFLOW;

	q->prod = prod;
	return ret;
}

static void queue_inc_prod(struct sec_smmu_queue *q)
{
	u32 prod = (Q_WRP(q, q->prod) | Q_IDX(q, q->prod)) + 1;

	q->prod = Q_OVF(q, q->prod) | Q_WRP(q, prod) | Q_IDX(q, prod);
	hisi_writel(q->prod, q->prod_reg);
}

/*
 * Wait for the SMMU to consume items. If drain is true, wait until the queue
 * is empty. Otherwise, wait until there is at least one free slot.
 */
static int queue_poll_cons(struct sec_smmu_queue *q, bool drain)
{
	int i;
	u32 timeout = 0;

	while (queue_sync_cons(q), (drain ? !queue_empty(q) : queue_full(q))) {
		if (timeout > HISI_SEC_SMMU_POLL_TIMEOUT_US)
			return -ETIMEDOUT;

		timeout++;
		/* udelay */
		for (i = 0; i < SEC_SMMU_UDEALY; i++)
			asm("nop");
	}
	return 0;
}

static void queue_write(u64 *dst, u64 *src, size_t n_dwords)
{
	u32 i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = cpu_to_le64(*src++);
}

static int queue_insert_raw(struct sec_smmu_queue *q, u64 *ent)
{
	if (queue_full(q))
		return -ENOSPC;
	queue_write(Q_ENT(q, q->prod), ent, q->ent_dwords);

	queue_inc_prod(q);
	return 0;
}

static void queue_read(u64 *dst, u64 *src, size_t n_dwords)
{
	u32 i;

	for (i = 0; i < n_dwords; ++i)
		*dst++ = le64_to_cpu(*src++);
}

static int queue_remove_raw(struct sec_smmu_queue *q, u64 *ent)
{
	if (queue_empty(q))
		return -EAGAIN;

	queue_read(ent, Q_ENT(q, q->cons), q->ent_dwords);
	queue_inc_cons(q);
	return 0;
}

/* High-level queue accessors */
static int sec_smmu_cmdq_build_cmd(
	u64 *cmd, struct sec_smmu_cmdq_ent *ent)
{
	memset_s(cmd, CMDQ_ENT_DWORDS << DWORD_BYTES_SHIFT, 0,
				CMDQ_ENT_DWORDS << DWORD_BYTES_SHIFT);

	cmd[0] |= (ent->opcode & CMDQ_0_OP_MASK) << CMDQ_0_OP_SHIFT;

	switch (ent->opcode) {
	case CMDQ_OP_TLBI_NSNH_ALL:
		break;
	case CMDQ_OP_CFGI_STE:
		cmd[0] |= CMDQ_0_SSEC;
		cmd[0] |= (u64)ent->cfgi.sid << CMDQ_CFGI_0_SID_SHIFT;
		cmd[1] |= ent->cfgi.leaf ? CMDQ_CFGI_1_LEAF : 0;
		break;
	case CMDQ_OP_CFGI_ALL:
		/* Cover the entire SID range */
		cmd[1] |= CMDQ_CFGI_1_RANGE_MASK << CMDQ_CFGI_1_RANGE_SHIFT;
		break;
	/*
	 * Cover the specal cd desc of sid,
	 * and in our code only use this case.
	 */
	case CMDQ_OP_CFGI_CD:
		cmd[0] |= CMDQ_0_SSEC;
		cmd[0] |= (u64)ent->cfgi.ssid << CMDQ_CFGI_0_CD_SHIFT;
		cmd[0] |= (u64)ent->cfgi.sid << CMDQ_CFGI_0_SID_SHIFT;
		cmd[1] |= ent->cfgi.leaf ? CMDQ_CFGI_1_LEAF : 0;
		break;
	/* Cover the all cd descs of sid */
	case CMDQ_OP_CFGI_CD_ALL:
		cmd[0] |= CMDQ_0_SSEC;
		cmd[0] |= (u64)ent->cfgi.sid << CMDQ_CFGI_0_SID_SHIFT;
		break;
	case CMDQ_OP_TLBI_NH_VA:
		cmd[0] |= (u64)ent->tlbi.asid << CMDQ_TLBI_0_ASID_SHIFT;
		cmd[1] |= ent->tlbi.leaf ? CMDQ_TLBI_1_LEAF : 0;
		cmd[1] |= ent->tlbi.addr & CMDQ_TLBI_1_VA_MASK;
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

static void arm_smmu_dmss_asi_dump(uintptr_t base)
{
	uint32_t i, j;
	uint32_t reg, addr;
	const uint32_t asi_cnt = 19;

	tloge("dmss asi info:\n");

	for (i = 0; i < ARRAY_SIZE(dmss_asi_dfx); i++) {
		for (j = 0; j < asi_cnt; j++) {
			addr = base +
				dmss_asi_dfx[i].offset + DMSS_REG_STEP * j;
			reg = hisi_readl(addr);
			tloge("reg:%s, addr: 0x%x, val:0x%x\n",
				dmss_asi_dfx[i].name, addr, reg);
		}
	}
}

static void arm_smmu_dmss_dmi_dump(uintptr_t base)
{
	uint32_t i, j;
	uint32_t reg, addr;
	const uint32_t dmi_cnt = 2;

	tloge("dmss dmi info:\n");

	for (i = 0; i < ARRAY_SIZE(dmss_dmi_dfx); i++) {
		for (j = 0; j < dmi_cnt; j++) {
			addr = base +
				dmss_dmi_dfx[i].offset + DMSS_REG_STEP * j;
			reg = hisi_readl(addr);
			tloge("reg:%s, addr: 0x%x, val:0x%x\n",
				dmss_dmi_dfx[i].name, addr, reg);
		}
	}
}

static void arm_smmu_dmss_ami_dump(uintptr_t base)
{
	uint32_t i, j;
	uint32_t reg, addr;
	const uint32_t ami_cnt = 1;

	tloge("dmss ami info:\n");

	for (i = 0; i < ARRAY_SIZE(dmss_ami_dfx); i++) {
		for (j = 0; j < ami_cnt; j++) {
			addr = base +
				dmss_ami_dfx[i].offset + DMSS_REG_STEP * j;
			reg = hisi_readl(addr);
			tloge("reg:%s, addr: 0x%x, val:0x%x\n",
				dmss_ami_dfx[i].name, addr, reg);
		}
	}
}

static void arm_smmu_dmss_glb_dump(uintptr_t base)
{
	uint32_t i;
	uint32_t reg, addr;
	const uint32_t chans = 4;
	const uint32_t sbuf_src = 9;

	tloge("dmss glb info:\n");
	for (i = 0; i < ARRAY_SIZE(dmss_glb_dfx); i++) {
		addr = base + dmss_glb_dfx[i].offset;
		reg = hisi_readl(addr);
		tloge("reg:%s, addr: 0x%x, val:0x%x\n",
			dmss_glb_dfx[i].name, addr, reg);
	}
	for (i = 0; i < chans; i++) {
		addr = base + SOC_DMSS_GLB_DFX_DCQ_ST_ADDR(0, i);
		reg = hisi_readl(addr);
		tloge("reg:GLB_DFX_DCQ_ST, addr: 0x%x, val:0x%x\n",
			addr, reg);
	}

	for (i = 0; i < sbuf_src; i++) {
		addr = base + SOC_DMSS_GLB_DFX_RBUF0_ADDR(0, i);
		reg = hisi_readl(addr);
		tloge("reg:GLB_DFX_RBUF0, addr: 0x%x, val:0x%x\n",
			addr, reg);

		addr = base + SOC_DMSS_GLB_DFX_RBUF1_ADDR(0, i);
		reg = hisi_readl(addr);
		tloge("reg:GLB_DFX_RBUF1, addr: 0x%x, val:0x%x\n",
			addr, reg);
	}
}

static uint64_t arm_smmu_dmss_info_dump(uint32_t smmuid)
{
	tloge("smmuid:%u, dmss info blow:\n", smmuid);
	arm_smmu_dmss_asi_dump(SOC_ACPU_DMSS_BASE_ADDR);
	arm_smmu_dmss_dmi_dump(SOC_ACPU_DMSS_BASE_ADDR);
	arm_smmu_dmss_ami_dump(SOC_ACPU_DMSS_BASE_ADDR);
	arm_smmu_dmss_glb_dump(SOC_ACPU_DMSS_BASE_ADDR);
	return 0;
}

static void arm_smmu_crg_info_dump(struct sec_smmu_device *smmu)
{
	u32 i;
	u32 reg;

	if (!smmu->crg_vbase) {
		tloge("%s, crg_vbase is null!\n", __func__);
		return;
	}

	tloge("subsys crg info:\n");
	if (smmu->smmuid == SMMU_MEDIA1) {
		for (i = 0; i < ARRAY_SIZE(media1_crg); i++) {
			reg = hisi_readl(smmu->crg_vbase +
					media1_crg[i].offset);
			tloge("reg:%s, val:0x%x\n", media1_crg[i].name, reg);
		}
	} else if (smmu->smmuid == SMMU_MEDIA2) {
		for (i = 0; i < ARRAY_SIZE(media2_crg); i++) {
			reg = hisi_readl(smmu->crg_vbase +
					media2_crg[i].offset);
			tloge("reg:%s, val:0x%x\n", media2_crg[i].name, reg);
		}
	}
}

static void sec_smmu_tcu_dump(struct sec_smmu_device *smmu)
{
	int i;
	u32 reg;
	u32 ret = 0;
	const u32 reg_width = 4;
	const int max_tbu_num = 14;

	tloge("%s:smmuid:%u config:\n", __func__, smmu->smmuid);

	reg = hisi_readl(smmu->base + SMMU_LP_REQ);
	tloge("SMMU_LP_REQ:0x%x\n", reg);
	reg = hisi_readl(smmu->base + SMMU_LP_ACK);
	tloge("SMMU_LP_ACK:0x%x\n", reg);

	reg = hisi_readl(smmu->base + HISI_SEC_SMMU_CR0ACK_S);
	tloge("HISI_SEC_SMMU_CR0ACK_S:0x%x\n", reg);

	reg = hisi_readl(smmu->base + HISI_SEC_SMMU_CMDQ_PROD_S);
	tloge("HISI_SEC_SMMU_CMDQ_PROD_S:0x%x\n", reg);

	reg = hisi_readl(smmu->base + HISI_SEC_SMMU_CMDQ_CONS_S);
	tloge("HISI_SEC_SMMU_CMDQ_CONS_S:0x%x\n", reg);

	reg = hisi_readl(smmu->base + SMMU_IRPT_RAW_S);
	tloge("SMMU_IRPT_RAW_S:0x%x\n", reg);

	tloge("cmd prod:0x%x, cons:0x%x\n",
		smmu->cmdq.q.prod, smmu->cmdq.q.cons);

	for (i = 0; i < max_tbu_num; i++) {
		reg = hisi_readl(smmu->base +
			HISI_SEC_SMMU_NODE_STATUS + i * reg_width);
		if (reg & 1)
			ret |= 1 << i;
	}
	tloge("HISI_SEC_SMMU_NODE_STATUS:0x%x\n", ret);
}

static void sec_smmu_config_dump(struct sec_smmu_device *smmu)
{
	sec_smmu_tcu_dump(smmu);
	arm_smmu_crg_info_dump(smmu);
	arm_smmu_dmss_info_dump(smmu->smmuid);
}

static void sec_smmu_cmdq_issue_cmd(
	struct sec_smmu_device *smmu, struct sec_smmu_cmdq_ent *ent)
{
	u64 cmd[CMDQ_ENT_DWORDS];
	int times = 0;
	struct sec_smmu_queue *q = &smmu->cmdq.q;
	int ret;

	if (smmu->stat != SMMU_ENABLE)
		return;

	if (sec_smmu_cmdq_build_cmd(cmd, ent)) {
		tloge("smmuid:%u opcode 0x%x build cmd fail!\n",
			smmu->smmuid, ent->opcode);
		return;
	}

	irq_lock();
	ret = pthread_mutex_lock(&smmu->cmdq.lock);
	if (ret)
		tloge("%s:pthread_mutex_lock fail\n", __func__);

	while (queue_insert_raw(q, cmd) == -ENOSPC) {
		if (queue_poll_cons(q, false)) {
			if (times++ >= MAX_CMD_TIMEOUT) {
				tloge("smmuid:%u CMDQ 0x%x timeout\n",
					smmu->smmuid, ent->opcode);
				sec_smmu_config_dump(smmu);
				pthread_mutex_unlock(&smmu->cmdq.lock);
				irq_unlock();
				return;
			}
		}
	}

	if (ent->opcode == CMDQ_OP_CMD_SYNC && queue_poll_cons(q, true)) {
		tloge("smmuid:%u CMD_SYNC timeout\n", smmu->smmuid);
		sec_smmu_config_dump(smmu);
	}

	ret = pthread_mutex_unlock(&smmu->cmdq.lock);
	if (ret)
		tloge("%s:pthread_mutex_unlock fail\n", __func__);
	irq_unlock();
}

static void sec_smmu_evt_flag_set(struct sec_smmu_device *smmu)
{
	if (smmu)
		smmu->event_flag = 1;
}

static void sec_smmu_evt_flag_unset(struct sec_smmu_device *smmu)
{
	if (smmu)
		smmu->event_flag = 0;
}

static void sec_smmu_dump_ste(struct sec_smmu_device *smmu, u32 sid)
{
	u32 i;
	struct sec_smmu_ste *ste = NULL;

	if (sid >= (1 << smmu->sid_bits)) {
		tloge("%s, sid %u invalid, sid_bits: %u\n",
			__func__, sid, smmu->sid_bits);
		return;
	}

	ste = &smmu->ste[sid];

	tloge("Dump sid %u STE:\n", sid);

	for (i = 0; i < HISI_SEC_STRTAB_STE_DWORDS; i++)
		tloge("0x%016llx\n", ste->entry[i]);
}

static void sec_smmu_dump_cd(struct sec_smmu_device *smmu,
				u32 ssid, u32 evt_id)

{
	u32 i;
	struct sec_smmu_cd *cd = NULL;
	struct sec_smmu_cd *cdp = NULL;

	if (EVTQ_TYPE_WITHOUT_SSID(evt_id)) {
		tloge("%s,event_id:%u not support\n", __func__, evt_id);
		return;
	}

	if (ssid >= (1UL << smmu->ssid_bits)) {
		tloge("%s, bad ssid:%u\n", __func__, ssid);
	}

	cd = (struct sec_smmu_cd *)(uintptr_t)smmu->base_addr.cd_virt;
	cdp = &cd[ssid];

	tloge("%s,dump ssid:%u cd context\n", __func__, ssid);
	for (i = 0; i < CTXDESC_CD_DWORDS; i++)
		tloge("0x%016llx\n", cdp->entry[i]);
}

static void sec_smmu_struct_dump(struct sec_smmu_device *smmu,
					u64 *evt, int evt_len)
{
	u32 evt_id;
	u32 sid, ssid;

	if (evt_len > EVTQ_ENT_DWORDS)
		return;

	evt_id = (evt[0] >> EVTQ_0_ID_SHIFT) & EVTQ_0_ID_MASK;
	sid = (evt[0] >> EVTQ_0_SID_SHIFT) & EVTQ_0_SID_MASK;
	ssid = (evt[0] >> EVTQ_0_SSID_SHIFT) & EVTQ_0_SSID_MASK;
	if (!evt_id) {
		tloge("%s: evt_id is null\n", __func__);
		return;
	}

	sec_smmu_dump_ste(smmu, sid);
	sec_smmu_dump_cd(smmu, ssid, evt_id);
}

static void sec_smmu_cfgregs_dump(struct sec_smmu_device *smmu)
{
	u32 i;
	u32 reg;

	tloge("smmuid:%u tcu regs dump:\n", smmu->smmuid);
	for (i = 0; i < ARRAY_SIZE(tcu_cfg_regs); i++) {
		reg = hisi_readl(smmu->base +
			tcu_cfg_regs[i].offset);
		tloge("reg:%s, val:0x%x\n", tcu_cfg_regs[i].name, reg);
	}
}

static void sec_smmu_evt_irq_thread(void *data)
{
	u32 i;
	u64 evt[EVTQ_ENT_DWORDS];
	struct sec_smmu_device *smmu = (struct sec_smmu_device *)data;
	struct sec_smmu_queue *q = &smmu->evtq.q;

	while (1) {
		pthread_mutex_lock(&smmu->evt_lock);

		/* wait for event */
		while ((smmu->stat != SMMU_ENABLE) || !(smmu->event_flag))
			pthread_cond_wait(&smmu->evt_happen, &smmu->evt_lock);

		pthread_mutex_lock(&smmu->mutex);
		while (!queue_remove_raw(q, evt)) {
			u8 id = (evt[0] >> EVTQ_0_ID_SHIFT) & EVTQ_0_ID_MASK;

			tloge("smmuid:%u event 0x%02x received:\n",
				smmu->smmuid, id);
			for (i = 0; i < ARRAY_SIZE(evt); ++i)
				tloge("\t smmuid:%u 0x%016llx\n", smmu->smmuid,
					(unsigned long long)evt[i]);

			sec_smmu_struct_dump(smmu, evt, EVTQ_ENT_DWORDS);
			sec_smmu_cfgregs_dump(smmu);
		}
		pthread_mutex_unlock(&smmu->mutex);

		q->cons = Q_OVF(q, q->prod) | Q_WRP(q, q->cons) |
			  Q_IDX(q, q->cons);

		sec_smmu_evt_flag_unset(smmu);
		pthread_mutex_unlock(&smmu->evt_lock);
	}
}

static int sec_smmu_evt_irq_setup(struct sec_smmu_device *smmu)
{
	int ret;

	ret = pthread_create(&smmu->evt_thread,
		NULL, (void *)sec_smmu_evt_irq_thread, smmu);
	if (ret) {
		tloge("%s: pthread create failed. ret=%d", __func__, ret);
		return ret;
	}

	return 0;
}

/* IRQ and event handlers */
static void sec_smmu_evtq_handler(struct sec_smmu_device *smmu)
{
	struct sec_smmu_queue *q = &smmu->evtq.q;

	/*
	 * Not much we can do on overflow, so scream and pretend we're
	 * trying harder.
	 */
	if (queue_sync_prod(q) == -EOVERFLOW) {
		tloge("smmuid:%u EVTQ overflow detected -- events lost\n",
			smmu->smmuid);
	} else if (queue_empty(q)) {
		tloge("smmuid:%u EVTQ empty!\n", smmu->smmuid);
		return;
	}

	sec_smmu_evt_flag_set(smmu);
	pthread_cond_signal(&smmu->evt_happen);
}

static void sec_smmu_global_handler(HWI_ARG_T data)
{
	u32 irq_status;
	u32 raw_irq_status;
	u32 reg = (TCU_EVENT_Q_IRQ_CLR | TCU_CMD_SYNC_IRQ_CLR |
		   TCU_GERROR_IRQ_CLR);
	struct sec_smmu_device *smmu =
		(struct sec_smmu_device *)(uintptr_t)data;

	if (!smmu || (smmu->stat != SMMU_ENABLE))
		return;

	irq_status = hisi_readl(smmu->base + SMMU_IRPT_STAT_S);
	raw_irq_status = hisi_readl(smmu->base + SMMU_IRPT_RAW_S);
	tloge("into %s,status:0x%x,raw_status:0x%x\n", __func__,
		irq_status, raw_irq_status);
	hisi_writel(reg, smmu->base + SMMU_IRPT_CLR_S);
	if (irq_status & TCU_EVENT_Q_IRQ)
		sec_smmu_evtq_handler(smmu);
}

static int sec_smmu_setup_irqs(struct sec_smmu_device *smmu)
{
	int ret;
	u32 irq;

	irq = smmu->combined_irq;
	ret = SRE_HwiCreate(irq, 0x0, INT_SECURE,
			sec_smmu_global_handler, (HWI_ARG_T)(uintptr_t)smmu);
	if (ret) {
		tloge("smmuid:%u SRE_HwiCreate fail!\n", smmu->smmuid);
		return ret;
	}

	ret = SRE_HwiEnable(irq);
	if (ret) {
		tloge("smmuid:%u failed to SRE_HwiEnable!\n", smmu->smmuid);
		return ret;
	}

	ret = sec_smmu_evt_irq_setup(smmu);
	if (ret) {
		tloge("smmuid:%u fail to setup evt irq!\n", smmu->smmuid);
		return ret;
	}
	tloge("%s smmuid:%u, irq: %u ok!\n", __func__, smmu->smmuid, irq);
	return 0;
}

static int sec_smmu_intr_init(struct sec_smmu_device *smmu)
{
	hisi_writel(IRQ_CTRL_EVTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN,
		smmu->base + HISI_SEC_SMMU_IRQ_CTRL_S);
	hisi_writel(HISI_VAL_MASK, smmu->base + SMMU_IRPT_CLR_S);
	hisi_writel(0, smmu->base + SMMU_IRPT_MASK_S);

	return 0;
}

static void sec_smmu_inv_cfg_tlb(struct sec_smmu_device *smmu)
{
	hisi_writel(INIT_INVALD_ALL, smmu->base + HISI_SEC_SMMU_INIT_S);
}

static struct sec_smmu_device *sec_find_smmu(u32 smmuid)
{
	u32 i;

	for (i = 0; i < ARRAY_SIZE(sec_smmu); i++) {
		if (sec_smmu[i].smmuid == smmuid)
			return &sec_smmu[i];
	}
	return NULL;
}

static int readl_poll_timeout(u32 addr, int op, u32 val)
{
	u32 reg;
	int looptime = 0;

	for (;; looptime++) {
		reg = hisi_readl(addr);
		if (op == REG_EQUAL) {
			if (reg == val)
				return 0;
		} else if (op == REG_AND) {
			if (reg & val)
				return 0;
		} else if (op == REG_AND_NOT) {
			if (!(reg & val))
				return 0;
		} else {
			return -ETIMEDOUT;
		}

		if (looptime > HISI_SEC_SMMU_POLL_TIMEOUT_US)
			return -ETIMEDOUT;
	}
	return -ETIMEDOUT;
}

static int sec_smmu_reg_set(struct sec_smmu_device *smmu,
				u32 req_off, u32 ack_off,
				u32 req_bit, u32 ack_bit)
{
	u32 reg;

	reg = hisi_readl(smmu->base + req_off);
	reg |= req_bit;
	hisi_writel(reg, smmu->base + req_off);
	return readl_poll_timeout(smmu->base + ack_off, REG_AND, ack_bit);
}

static int sec_smmu_reg_unset(struct sec_smmu_device *smmu,
				u32 req_off, u32 ack_off,
				u32 req_bit, u32 ack_bit)
{
	u32 reg;

	reg = hisi_readl(smmu->base + req_off);
	reg &= ~req_bit;
	hisi_writel(reg, smmu->base + req_off);
	return readl_poll_timeout(smmu->base + ack_off, REG_AND_NOT, ack_bit);
}

static int sec_smmu_write_reg_sync(struct sec_smmu_device *smmu,
				u32 val, unsigned int reg_off,
				unsigned int ack_off)
{
	hisi_writel(val, smmu->base + reg_off);
	return readl_poll_timeout(smmu->base + ack_off, REG_EQUAL, val);
}

/* Probing and initialisation functions */
static int sec_smmu_init_one_queue(struct sec_smmu_device *smmu,
				struct sec_smmu_queue *q,
				unsigned long prod_off,
				unsigned long cons_off,
				enum sec_smmu_q q_type)
{
	switch (q_type) {
	case SMMU_CMQ:
		q->base_phy = smmu->base_addr.cmd_base;
		q->base = (u64 *)(uintptr_t)smmu->base_addr.cmd_virt;
		q->ent_dwords = CMDQ_ENT_DWORDS;
		break;
	case SMMU_EVENTQ:
		q->base_phy = smmu->base_addr.evt_base;
		q->base = (u64 *)(uintptr_t)smmu->base_addr.evt_virt;
		q->ent_dwords = EVTQ_ENT_DWORDS;
		break;
	default:
		tloge("q_type:%d unknown/unsupported q_type!\n", q_type);
		return -ENOMEM;
	}

	q->q_size = (((size_t)1 << q->max_n_shift) * q->ent_dwords)
				<< DWORD_BYTES_SHIFT;
	q->prod_reg = smmu->base + prod_off;
	q->cons_reg = smmu->base + cons_off;

	q->q_base_0 = (u32)(q->base_phy & Q_BASE_ADDR_MASK);
	q->q_base_0 |= (q->max_n_shift & Q_BASE_LOG2SIZE_MASK)
		       << Q_BASE_LOG2SIZE_SHIFT;
	q->q_base_1 = (u32)(q->base_phy >> Q_BASE_HIGH_ADDR_SHIFT);

	q->prod = q->cons = 0;
	return 0;
}

static void sec_smmu_free_one_queue(struct sec_smmu_queue *q)
{
	memset_s(q->base, q->q_size, 0, q->q_size);
}

static int sec_smmu_init_queues(struct sec_smmu_device *smmu)
{
	int ret;

	/* cmdq */
	ret = pthread_mutex_init(&smmu->cmdq.lock, NULL);
	if (ret) {
		tloge("smmuid:%u cmdq lock init failed\n", smmu->smmuid);
		goto out;
	}

	ret = sec_smmu_init_one_queue(smmu, &smmu->cmdq.q,
		HISI_SEC_SMMU_CMDQ_PROD_S,
		HISI_SEC_SMMU_CMDQ_CONS_S,
		SMMU_CMQ);
	if (ret)
		goto out;

	/* evtq */
	ret = sec_smmu_init_one_queue(smmu, &smmu->evtq.q,
		HISI_SEC_SMMU_EVTQ_PROD_S,
		HISI_SEC_SMMU_EVTQ_CONS_S,
		SMMU_EVENTQ);
	if (ret)
		goto out_free_cmdq;

	return 0;

out_free_cmdq:
	sec_smmu_free_one_queue(&smmu->cmdq.q);
out:
	return ret;
}

static int sec_smmu_init_strtab(struct sec_smmu_device *smmu)
{
	u64 reg;
	u64 ste_phy;
	struct sec_smmu_ste *pste = NULL;
	u64 size = (1 << smmu->sid_bits) *
		(HISI_SEC_STRTAB_STE_DWORDS << DWORD_BYTES_SHIFT);

	tloge("into %s, base:0x%x\n", __func__, smmu->base_addr.ste_base);

	pste = (struct sec_smmu_ste *)(uintptr_t)smmu->base_addr.ste_virt;
	/* Configure strtab_base_cfg for a linear table covering all SIDs */
	reg  = HISI_SEC_STRTAB_BASE_CFG_FMT_LINEAR;
	reg |= (smmu->sid_bits & HISI_SEC_STRTAB_BASE_CFG_LOG2SIZE_MASK)
		<< HISI_SEC_STRTAB_BASE_CFG_LOG2SIZE_SHIFT;
	smmu->strtab_base_cfg = reg;
	smmu->strtab_size = size;
	ste_phy = (u64)smmu->base_addr.ste_base;
	/* Set the strtab base address */
	reg  = ste_phy & HISI_STRTAB_BASE_ADDR_MASK <<
				HISI_STRTAB_BASE_ADDR_SHIFT;
	smmu->strtab_base = reg;
	smmu->ste = pste;
	return 0;
}

static int sec_smmu_device_disable(struct sec_smmu_device *smmu)
{
	int ret;

	ret = sec_smmu_write_reg_sync(smmu, 0,
		HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret)
		tloge("smmuid:%u failed to clear cr0\n", smmu->smmuid);

	return ret;
}

static int sec_smmu_struct_info_init(u32 addr, u32 size)
{
	u32 vaddr;

	/* map smmu structure section to secos */
	if (sre_mmap(addr, size, &vaddr, secure, non_cache)) {
		tloge("%s map add failed!\n", __func__);
		return -EFAULT;
	}
	(void)memset_s((void *)(uintptr_t)vaddr, size, 0, size);

	struct_info.struct_phys = addr;
	struct_info.struct_virt = vaddr;
	struct_info.struct_size = size;
	return 0;
}

static u64 sec_smmu_get_struct_offset(struct sec_smmu_device *smmu)
{
	u64 offset;

	switch (smmu->smmuid) {
	case SMMU_MEDIA1:
		offset = 0;
		break;
	case SMMU_MEDIA2:
		offset = SZ_16K;
		break;
	case SMMU_NPU:
		offset = SZ_32K;
		break;
	default:
		return 0;
	}
	return offset;
}

static int sec_smmu_struct_phys_fill(struct sec_smmu_device *smmu)
{
	u32 base;

	base = struct_info.struct_phys;
	smmu->base_addr.ste_base = (uintptr_t)base +
		sec_smmu_get_struct_offset(smmu);
	smmu->base_addr.cd_base = smmu->base_addr.ste_base + SZ_4K;
	smmu->base_addr.cmd_base = smmu->base_addr.cd_base + SZ_4K;
	smmu->base_addr.evt_base = smmu->base_addr.cmd_base + SZ_4K;

	return 0;
}

static int sec_smmu_struct_virt_fill(struct sec_smmu_device *smmu)
{
	u32 base;

	base = struct_info.struct_virt;
	smmu->base_addr.ste_virt = (uintptr_t)base +
		sec_smmu_get_struct_offset(smmu);
	smmu->base_addr.cd_virt = smmu->base_addr.ste_virt + SZ_4K;
	smmu->base_addr.cmd_virt = smmu->base_addr.cd_virt + SZ_4K;
	smmu->base_addr.evt_virt = smmu->base_addr.cmd_virt + SZ_4K;

	return 0;
}

static int sec_smmu_pgd_addr_fill(struct sec_smmu_device *smmu, u32 type)
{
	void *pgd = NULL;
	unsigned int pgdbase;

	pgdbase = hisi_sion_get_pgtable(type);
	if (!pgdbase) {
		tloge("smmuid:%u get pgd base fail\n", smmu->smmuid);
		return -EFAULT;
	}
	smmu->base_addr.pgd_base = (uintptr_t)pgdbase;

	pgd = hisi_sion_get_pgd_virt(type);
	if (!pgd) {
		tloge("smmuid:%u get pgd virt fail\n", smmu->smmuid);
		return -EFAULT;
	}
	smmu->base_addr.pgd_virt = (uintptr_t)pgd;

	return 0;
}


static int sec_smmu_npu_struct_fill(struct sec_smmu_device *smmu)
{
	u32 len = 0;
	int ret;
	uintptr_t rsv_start;
	uintptr_t virt;

	ret = npu_get_res_mem_of_smmu(&rsv_start, &virt, &len);
	if (ret || (len < SZ_16K)) {
		tloge("%s:get rsv fail!len:%u, ret:%d\n", __func__, len, ret);
		return -ENOMEM;
	}

	smmu->base_addr.ste_base = rsv_start;
	smmu->base_addr.cd_base = smmu->base_addr.ste_base + SZ_4K;
	smmu->base_addr.cmd_base = smmu->base_addr.cd_base + SZ_4K;
	smmu->base_addr.evt_base = smmu->base_addr.cmd_base + SZ_4K;
	smmu->base_addr.pgd_base = smmu->base_addr.evt_base + SZ_4K;
	memset_s((void *)virt, len, 0, len);

	smmu->base_addr.ste_virt = (uintptr_t)virt;
	smmu->base_addr.cd_virt = smmu->base_addr.ste_virt + SZ_4K;
	smmu->base_addr.cmd_virt = smmu->base_addr.cd_virt + SZ_4K;
	smmu->base_addr.evt_virt = smmu->base_addr.cmd_virt + SZ_4K;
	smmu->base_addr.pgd_virt = smmu->base_addr.evt_virt + SZ_4K;

	return 0;
}

static int sec_smmu_pgd_fill(u32 smmuid, u32 sid)
{
	int ret;
	struct sec_smmu_device *smmu = NULL;

	smmu = sec_find_smmu(smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, smmuid);
		return -EFAULT;
	}

	if (sid == SECSMMU_STREAMID_ISP || sid == SECSMMU_STREAMID_IVP) {
		ret = sec_smmu_pgd_addr_fill(smmu, SEC_TASK_SEC);
		if (ret) {
			tloge("%s, smmuid[%u] isp pgd fill failed!\n",
				__func__, smmuid);
			return -EFAULT;
		}
	} else { /* DRM */
		ret = sec_smmu_pgd_addr_fill(smmu, SEC_TASK_DRM);
		if (ret) {
			tloge("%s, smmuid[%u] drm pgd fill failed!\n",
				__func__, smmuid);
			return -EFAULT;
		}
	}
	tloge("%s, smmuid[%u] ok!\n", __func__, smmuid);
	return 0;
}

static int sec_smmu_base_init(struct sec_smmu_device *smmu)
{
	int ret;

	if (smmu->smmuid == SMMU_NPU) {
		ret = sec_smmu_npu_struct_fill(smmu);
		if (ret) {
			tloge("%s npu pgd fill failed!\n", __func__);
			return -EFAULT;
		}
		return 0;
	}

	ret = sec_smmu_struct_phys_fill(smmu);
	if (ret) {
		tloge("%s struct phys failed!\n", __func__);
		return -EFAULT;
	}

	ret = sec_smmu_struct_virt_fill(smmu);
	if (ret) {
		tloge("%s struct virt failed!\n", __func__);
		return -EFAULT;
	}

	return 0;
}

static int hisi_sec_smmu_bitmap_alloc(int *map)
{
	int idx;

	for (idx = 0; idx < MAX_SSID_NUM; idx++)
		if (!map[idx])
			return idx;

	return -1;
}

static int hisi_sec_smmu_bitmap_free(int *map, int idx)
{
	if (idx < 0 || idx >= MAX_SSID_NUM)
		return -1;

	map[idx] = 0;
	return 0;
}

static int sec_smmu_cmdq_enable(struct sec_smmu_device *smmu, u32 *enables)
{
	int ret;

	hisi_writel(smmu->cmdq.q.q_base_0,
		smmu->base + HISI_SEC_SMMU_CMDQ_BASE_S);
	hisi_writel(smmu->cmdq.q.q_base_1,
		smmu->base + HISI_SEC_SMMU_CMDQ_BASE_H_S);
	hisi_writel(0, smmu->base + HISI_SEC_SMMU_CMDQ_PROD_S);
	hisi_writel(0, smmu->base + HISI_SEC_SMMU_CMDQ_CONS_S);

	smmu->cmdq.q.prod = 0;
	smmu->cmdq.q.cons = 0;
	*enables |= CR0_CMDQEN;
	ret = sec_smmu_write_reg_sync(
		smmu, *enables, HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret) {
		tloge("smmuid:%u failed to enable cmdq\n", smmu->smmuid);
		return ret;
	}

	return ret;
}

static int sec_smmu_eventq_enable(struct sec_smmu_device *smmu, u32 *enables)
{
	int ret;

	hisi_writel(smmu->evtq.q.q_base_0,
		smmu->base + HISI_SEC_SMMU_EVTQ_BASE_S);
	hisi_writel(smmu->evtq.q.q_base_1,
		smmu->base + HISI_SEC_SMMU_EVTQ_BASE_H_S);
	hisi_writel(0, smmu->base + HISI_SEC_SMMU_EVTQ_PROD_S);
	hisi_writel(0, smmu->base + HISI_SEC_SMMU_EVTQ_CONS_S);

	smmu->evtq.q.prod = 0;
	smmu->evtq.q.cons = 0;
	*enables |= CR0_EVTQEN;
	ret = sec_smmu_write_reg_sync(smmu, *enables,
		HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret) {
		tloge("smmuid:%u failed to enable event queue\n",
			smmu->smmuid);
		return ret;
	}

	return 0;
}

static int sec_smmu_device_reset(struct sec_smmu_device *smmu)
{
	int ret;
	u32 reg;
	u32 enables = 0;

	/* Check CR0: smmu is already enable? */
	reg = hisi_readl(smmu->base + HISI_SEC_SMMU_CR0_S);
	if (reg & CR0_SMMUEN) {
		tlogd("smmuid:%u already enabled! SEC_SMMU_CR0_S:0x%lx\n", smmu->smmuid, reg);
		return 0;
	}

	/* CR2 (random crap) */
	reg = CR2_PTM | CR2_RECINVSID;
	hisi_writel(reg, smmu->base + HISI_SEC_SMMU_CR2_S);

	/* Stream table */
	hisi_writel(smmu->strtab_base & HISI_SEC_STRTAB_BASE_ADDR_MASK,
		smmu->base + HISI_SEC_SMMU_STRTAB_BASE_S);
	hisi_writel(smmu->strtab_base >> Q_BASE_HIGH_ADDR_SHIFT,
		smmu->base + HISI_SEC_SMMU_STRTAB_BASE_H_S);
	hisi_writel(smmu->strtab_base_cfg,
		smmu->base + HISI_SEC_SMMU_STRTAB_BASE_CFG_S);

	ret = sec_smmu_cmdq_enable(smmu, &enables);
	if (ret) {
		tloge("%s, smmuid:%u enable cmdq fail\n",
			__func__, smmu->smmuid);
		return ret;
	}

	ret = sec_smmu_eventq_enable(smmu, &enables);
	if (ret) {
		tloge("%s, smmuid:%u enable eventq fail\n",
			__func__, smmu->smmuid);
		return ret;
	}

	sec_smmu_intr_init(smmu);

	/* Enable the SMMU interface */
	enables |= CR0_SMMUEN;
	ret = sec_smmu_write_reg_sync(
		smmu, enables, HISI_SEC_SMMU_CR0_S, HISI_SEC_SMMU_CR0ACK_S);
	if (ret) {
		tloge("%s, smmuid:%u failed to enable SMMU interface\n",
			__func__, smmu->smmuid);
		return ret;
	}
	return 0;
}

static void sec_smmu_flush_cd(struct sec_smmu_device *smmu, u32 sid, u32 ssid)
{
	struct sec_smmu_cmdq_ent cmd;

	cmd.opcode = CMDQ_OP_CFGI_CD;
	cmd.cfgi.ssid = ssid;
	cmd.cfgi.sid = sid;
	cmd.cfgi.leaf = 1;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);

	cmd.opcode = CMDQ_OP_CMD_SYNC;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);
}

static void sec_smmu_flush_ste(struct sec_smmu_device *smmu, u32 sid)
{
	struct sec_smmu_cmdq_ent cmd = {
		.opcode	= CMDQ_OP_CFGI_STE,
		.cfgi	= {
			.sid	= sid,
			.leaf	= true,
		},
	};

	sec_smmu_cmdq_issue_cmd(smmu, &cmd);
	cmd.opcode = CMDQ_OP_CMD_SYNC;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);
}

void secsmmu_tlb_inv_asid(u32 smmu_id, u32 sid, u32 ssid)
{
	struct sec_smmu_device *smmu = NULL;
	struct sec_smmu_cmdq_ent cmd = {
		.tlbi = {
			.asid	= (u16)ssid,
			.vmid	= (u16)sid,
		},
	};

	smmu = sec_find_smmu(smmu_id);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, smmu_id);
		return;
	}
	pthread_mutex_lock(&smmu->mutex);
	if (smmu->stat != SMMU_ENABLE) {
		pthread_mutex_unlock(&smmu->mutex);
		return;
	}
	cmd.opcode = CMDQ_OP_TLBI_NH_ASID;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);

	cmd.opcode = CMDQ_OP_CMD_SYNC;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);
	pthread_mutex_unlock(&smmu->mutex);
}

void secsmmu_tlb_inv_va_range(u32 smmuid, unsigned long iova,
				size_t size, bool leaf)
{
	const size_t granule = SZ_4K;
	struct sec_smmu_device *smmu = NULL;
	struct sec_smmu_cmdq_ent cmd = {
		.tlbi = {
			.leaf	= leaf,
			.addr	= iova,
		},
	};

	smmu = sec_find_smmu(smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, smmuid);
		return;
	}
	pthread_mutex_lock(&smmu->mutex);
	if (smmu->stat != SMMU_ENABLE) {
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid[%u] not enable!\n", __func__, smmuid);
		return;
	}
	cmd.opcode = CMDQ_OP_TLBI_NH_VA;
	do {
		sec_smmu_cmdq_issue_cmd(smmu, &cmd);
		cmd.tlbi.addr += granule;
	} while (size -= granule);
	cmd.opcode = CMDQ_OP_CMD_SYNC;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);
	pthread_mutex_unlock(&smmu->mutex);
}

void secsmmu_tlb_inv_all(u32 smmuid)
{
	struct sec_smmu_device *smmu = NULL;
	struct sec_smmu_cmdq_ent cmd;

	smmu = sec_find_smmu(smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, smmuid);
		return;
	}
	pthread_mutex_lock(&smmu->mutex);
	if (smmu->stat != SMMU_ENABLE) {
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid[%u] not enable!\n", __func__, smmuid);
		return;
	}
	cmd.opcode = CMDQ_OP_TLBI_NH_ASID;
	cmd.tlbi.asid = 0;
	cmd.tlbi.vmid = 0;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);

	cmd.opcode = CMDQ_OP_CMD_SYNC;
	sec_smmu_cmdq_issue_cmd(smmu, &cmd);
	pthread_mutex_unlock(&smmu->mutex);
}

static int sec_smmu_hw_probe(struct sec_smmu_device *smmu)
{
	/* HISI_SEC_IDR0 */
	smmu->features |= HISI_SEC_SMMU_FEAT_TT_LE |
			HISI_SEC_SMMU_FEAT_TT_BE;
	smmu->features |= HISI_SEC_SMMU_FEAT_SEV;
	smmu->features |= HISI_SEC_SMMU_FEAT_MSI;
	smmu->features |= HISI_SEC_SMMU_FEAT_HYP;
	smmu->features |= HISI_SEC_SMMU_FEAT_TRANS_S1;
	smmu->features |= HISI_SEC_SMMU_FEAT_TRANS_S2;

	/* We only support the AArch64 table format at present */
	smmu->ias = HISI_SMMU_ADDR_SIZE_40;

	/* ASID/VMID sizes */
	smmu->asid_bits = HISI_SMMU_ID_SIZE_16;
	smmu->vmid_bits = HISI_SMMU_ID_SIZE_16;

	/* HISI_SEC_IDR1 */
	/* Queue sizes, capped at 4k */
	smmu->cmdq.q.max_n_shift = CMDQ_MAX_SZ_SHIFT;
	smmu->evtq.q.max_n_shift = EVTQ_MAX_SZ_SHIFT;

	/* SID/SSID sizes */
	smmu->sid_bits = HISI_SSID_MAX_BITS;
	smmu->ssid_bits = HISI_SSID_MAX_BITS;

	/* HISI_SEC_IDR5 */
	/* Maximum number of outstanding stalls */
	smmu->evtq.max_stalls = HISI_EVENTQ_MAX_STALLS;

	/* Output address size */
	smmu->oas = HISI_SMMU_ADDR_SIZE_40;

	tloge("out %s ias %u-bit, oas %u-bit (features 0x%08llx)\n",
		__func__, smmu->ias, smmu->oas, smmu->features);

	return 0;
}

static void sec_smmu_ssidmap_init(struct sec_smmu_device *smmu)
{
	size_t size = sizeof(int) * MAX_SSID_NUM;

	(void)memset_s(smmu->ssid_map, size, 0, size);
}

static int hisi_smmu_mutex_init(struct sec_smmu_device *smmu)
{
	int ret;

	ret = pthread_mutex_init(&smmu->mutex, NULL);
	if (ret) {
		tloge("%s, smmu->mutex init failed!\n", __func__);
		return ret;
	}

	ret = pthread_mutex_init(&smmu->evt_lock, NULL);
	if (ret) {
		tloge("%s, smmu->evt_lock init failed!\n", __func__);
		(void)pthread_mutex_destroy(&smmu->mutex);
		return ret;
	}

	return 0;
}

static int sec_smmu_devices_init(struct sec_smmu_device *smmu)
{
	int ret;

	ret = hisi_smmu_mutex_init(smmu);
	if (ret) {
		tloge("%s: hisi_smmu_mutex_init fail\n", __func__);
		return ret;
	}

	ret = sec_smmu_hw_probe(smmu);
	if (ret) {
		tloge("%s, sec_smmu_hw_probe failed!\n", __func__);
		return -ENOENT;
	}

	ret = sec_smmu_base_init(smmu);
	if (ret) {
		tloge("%s, sec_smmu_base_init failed!\n", __func__);
		return -ENOENT;
	}

	ret = sec_smmu_init_strtab(smmu);
	if (ret) {
		tloge("%s, sec_smmu_init_strtab failed!\n", __func__);
		return -ENOENT;
	}

	ret = sec_smmu_init_queues(smmu);
	if (ret) {
		tloge("%s, sec_smmu_init_queues failed!\n", __func__);
		return -ENOENT;
	}

	ret = sec_smmu_setup_irqs(smmu);
	if (ret) {
		tloge("%s, sec_smmu_setup_irqs failed!\n", __func__);
		return ret;
	}

	sec_smmu_ssidmap_init(smmu);
	return 0;
}

static int sec_smmu_init(void)
{
	u32 i;
	int ret;

	ret = sec_smmu_struct_info_init(SMMU_STRUCT_BASE, SMMU_STRUCT_SIZE);
	if (ret) {
		tloge("%s, init smmu struct failed!\n", __func__);
		return -ENOENT;
	}

	for (i = 0; i < ARRAY_SIZE(sec_smmu); i++) {
		ret = sec_smmu_devices_init(&sec_smmu[i]);
		if (ret) {
			tloge("smmu_init[%u] ret = %d", i, ret);
			return -ENOENT;
		}
	}
	tloge("%s ok!\n", __func__);
	return 0;
}

static int sec_smmu_open_tcu(struct sec_smmu_device *smmu)
{
	int ret;
	u32 reg;

	reg = hisi_readl(smmu->base + SMMU_LP_ACK);
	if ((reg & SMMU_TCU_CTRL_ENABLE) == SMMU_TCU_CTRL_ENABLE) {
		tloge("TCU already open!!\n");
		return 0;
	}
	/* Enable TCU internal clk */
	ret = sec_smmu_reg_set(smmu, SMMU_LP_REQ, SMMU_LP_ACK,
			TCU_QREQN_CG, TCU_QACCEPTN_CG);
	if (ret) {
		tloge("Enable TCU clk failed!\n");
		return -EINVAL;
	}
	/* Enable TCU internal power */
	ret = sec_smmu_reg_set(smmu, SMMU_LP_REQ, SMMU_LP_ACK,
			TCU_QREQN_PD, TCU_QACCEPTN_PD);
	if (ret) {
		tloge("Enable TCU power failed!\n");
		return -EINVAL;
	}
	tloge("out %s\n", __func__);
	return 0;
}

static int sec_smmu_close_tcu(struct sec_smmu_device *smmu)
{
	sec_smmu_reg_unset(smmu, SMMU_LP_REQ, SMMU_LP_ACK,
			TCU_QREQN_PD, TCU_QACCEPTN_PD);

	sec_smmu_reg_unset(smmu, SMMU_LP_REQ, SMMU_LP_ACK,
			TCU_QREQN_CG, TCU_QACCEPTN_CG);

	tloge("out %s\n", __func__);
	return 0;
}

int sec_smmu_poweron(u32 smmuid)
{
	int ret;
	struct sec_smmu_device *smmu = NULL;

	tloge("into %s, smmuid:%u\n", __func__, smmuid);
	smmu = sec_find_smmu(smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, smmuid);
		return -EFAULT;
	}

	pthread_mutex_lock(&smmu->mutex);
	if (pw_ref(smmu)) {
		pw_ref_inc(smmu);
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid:%u, ref:%u return directly\n", __func__,
			smmuid, pw_ref(smmu));
		return 0;
	}
	ret = sec_smmu_open_tcu(smmu);
	if (ret) {
		tloge("%s, smmuid[%u] open tcu failed!\n", __func__, smmuid);
		pthread_mutex_unlock(&smmu->mutex);
		return -EFAULT;
	}

	ret = sec_smmu_device_reset(smmu);
	if (ret) {
		tloge("%s, smmuid[%u] device reset!\n", __func__, smmuid);
		pthread_mutex_unlock(&smmu->mutex);
		return -EFAULT;
	}

	ret = sec_smmu_ste_fill(smmu,
		SECSMMU_STREAMID_BYPASS, SMMU_STREM_BYPASS);
	if (ret) {
		tloge("%s, smmuid[%u] streambypass fail!\n",
			__func__, smmuid);
		pthread_mutex_unlock(&smmu->mutex);
		return -EFAULT;
	}

	smmu->stat = SMMU_ENABLE;
	pw_ref_inc(smmu);
	pthread_mutex_unlock(&smmu->mutex);

	sec_smmu_inv_cfg_tlb(smmu); /* after poweron, invalid all tlb */
	tloge("out %s, smmuid:%u, ref:%u\n", __func__, smmuid, pw_ref(smmu));
	return 0;
}

static void sec_smmu_intr_deinit(struct sec_smmu_device *smmu)
{
	/* disable all interrupts */
	sec_smmu_reg_unset(smmu,
		HISI_SEC_SMMU_IRQ_CTRL_S, HISI_SEC_SMMU_IRQ_CTRLACK_S,
		HISI_VAL_ALL, HISI_VAL_ALL);

	/* mask all interrupts */
	hisi_writel(HISI_VAL_ALL, smmu->base + SMMU_IRPT_MASK_S);

	/* clear all interrupts */
	hisi_writel(HISI_VAL_ALL, smmu->base + SMMU_IRPT_CLR_S);
}

int sec_smmu_poweroff(u32 smmuid)
{
	struct sec_smmu_device *smmu = NULL;

	tloge("into %s, smmuid:%u\n", __func__, smmuid);
	smmu = sec_find_smmu(smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, smmuid);
		return -EFAULT;
	}

	pthread_mutex_lock(&smmu->mutex);
	if (!pw_ref(smmu)) {
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid:%u, ref:%u ref is zero\n", __func__,
			smmuid, pw_ref(smmu));
		return 0;
	}

	if (pw_ref(smmu) > 1) {
		pw_ref_dec(smmu);
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid:%u, ref:%u ref dec\n", __func__,
			smmuid, pw_ref(smmu));
		return 0;
	}

	if (smmu->smmuid == SMMU_NPU) {
		sec_smmu_intr_deinit(smmu);
		sec_smmu_device_disable(smmu);
		sec_smmu_close_tcu(smmu);
	}

	smmu->stat = SMMU_DISABLE;
	pw_ref_dec(smmu);
	pthread_mutex_unlock(&smmu->mutex);

	tloge("out %s, smmuid:%u, ref:%u\n", __func__, smmuid, pw_ref(smmu));
	return 0;
}

static int sec_smmu_ste_fill(struct sec_smmu_device *smmu, u32 sid, int bypass)
{
	uintptr_t cd_base;
	struct sec_smmu_ste *ste = NULL;
	u64 trans = bypass ? HISI_STRTAB_STE_0_CFG_BYPASS :
					HISI_STRTAB_STE_0_CFG_S1_TRANS;

	ste = &smmu->ste[sid];
	cd_base = smmu->base_addr.cd_base;
	if (!cd_base) {
		tloge("%s, cd alloc fail!\n", __func__);
		return -EFAULT;
	}

	ste->entry[0] = HISI_STRTAB_STE_0_V |
		trans | HISI_STRTAB_STE_S1_CD_MAX |
		((u64)cd_base & HISI_STRTAB_STE_0_S1CTXPTR_MASK <<
		HISI_STRTAB_STE_0_S1CTXPTR_SHIFT);

	ste->entry[1] = HISI_STRTAB_STE_S1_DSS |
		(HISI_STRTAB_STE_1_STRW_NSEL1 <<
		HISI_STRTAB_STE_1_STRW_SHIFT);

	ste->entry[HISI_STRTAB_STE_2_S2VMID_OFFSET] = sid <<
		STRTAB_STE_2_S2VMID_SHIFT;

	sec_smmu_flush_ste(smmu, sid);
	tloge("%s ste:0x%llx, 0x%llx, cdbase:0x%llx!\n", __func__,
		ste->entry[0], ste->entry[1], cd_base);

	return 0;
}

static int sec_smmu_cd_fill(struct sec_smmu_device *smmu,
				u32 sid, u32 ssid, u64 pgd)
{
	struct sec_smmu_cd *cd = NULL;
	struct sec_smmu_cd *cdp = NULL;

	cd = (struct sec_smmu_cd *)(uintptr_t)smmu->base_addr.cd_virt;
	cdp = &cd[ssid];
	/* Build cd */
	cdp->entry[0] = HISI_CTXDESC_CD_0_R | HISI_CTXDESC_CD_0_A |
		HISI_CTXDESC_CD_0_ASET_PRIVATE |
		HISI_CTXDESC_CD_0_AA64 |
		((u64)ssid << HISI_CTXDESC_CD_0_ASID_SHIFT) |
		HISI_CTXDESC_CD_0_V;

	cdp->entry[0] |= HISI_CTXDESC_CD_0_T0SZ |
		HISI_CTXDESC_CD_1_EPD1 | HISI_CTXDESC_CD_IPS;
	cdp->entry[1] = pgd & HISI_CTXDESC_CD_1_TTB0_MASK <<
				HISI_CTXDESC_CD_1_TTB0_SHIFT;
	cdp->entry[CD_MAIR_INDEX] = (HISI_LPAE_MAIR_ATTR_NC <<
	       hisi_lpae_mair_attr_shift(HISI_LPAE_MAIR_ATTR_IDX_NC)) |
	      (HISI_LPAE_MAIR_ATTR_WBRWA <<
	      hisi_lpae_mair_attr_shift(HISI_LPAE_MAIR_ATTR_IDX_CACHE)) |
	      (HISI_LPAE_MAIR_ATTR_DEVICE <<
	       hisi_lpae_mair_attr_shift(HISI_LPAE_MAIR_ATTR_IDX_DEV));

	sec_smmu_flush_cd(smmu, sid, ssid);
	tloge("%s cd:[0]0x%llx, [1]0x%llx, [3]0x%llx!\n", __func__,
			cdp->entry[0], cdp->entry[1],
			cdp->entry[CD_MAIR_INDEX]);

	return 0;
}

int sec_smmu_bind(u32 smmuid, u32 sid, u32 ssid, pid_t pid)
{
	int ret;
	u64 pgd;
	struct vsroot_info_t tee_task_info;
	struct sec_smmu_device *smmu = NULL;

	if (sid >= MAX_SSID_NUM || ssid >= MAX_SSID_NUM) {
		tloge("%s, smmuid:%u, sid:%u, ssid:%u invalid!\n",
			__func__, smmuid, sid, ssid);
		return -EFAULT;
	}

	smmu = sec_find_smmu(smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, smmuid);
		return -EFAULT;
	}

	pthread_mutex_lock(&smmu->mutex);
	if (smmu->stat != SMMU_ENABLE) {
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid[%u] not enable!\n", __func__, smmuid);
		return -EFAULT;
	}

	ret = sec_smmu_ste_fill(smmu, sid, SMMU_STREM_ENABLE);
	if (ret) {
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid[%u] ste fill fail!\n", __func__, smmuid);
		return -EFAULT;
	}

	if (!pid) {
		ret = sec_smmu_pgd_fill(smmuid, sid);
		if (ret) {
			pthread_mutex_unlock(&smmu->mutex);
			tloge("%s, fill pgd failed!\n", __func__);
			return -EFAULT;
		}
		pgd = smmu->base_addr.pgd_base;
	} else {
		ret = hm_get_vsrootinfo(pid, &tee_task_info);
		if (ret) {
			pthread_mutex_unlock(&smmu->mutex);
			tloge("%s hm_get_vsrootinfo failed!\n", __func__);
			return -EFAULT;
		}
		pgd = tee_task_info.pud;
	}

	sec_smmu_cd_fill(smmu, sid, ssid, pgd);
	pthread_mutex_unlock(&smmu->mutex);

	tloge("%s, sid:%u, ssid:%u, pid:%u\n", __func__, sid, ssid, pid);
	return 0;
}

int sec_smmu_unbind(u32 smmuid, u32 sid, u32 ssid)
{
	struct sec_smmu_cd *cd = NULL;
	struct sec_smmu_ste *ste = NULL;
	struct sec_smmu_device *smmu = NULL;
	struct sec_smmu_cd *cdp = NULL;

	if (sid >= MAX_SSID_NUM || ssid >= MAX_SSID_NUM) {
		tloge("%s, smmuid:%u, sid:%u, ssid:%u invalid!\n",
			__func__, smmuid, sid, ssid);
		return -EFAULT;
	}

	smmu = sec_find_smmu(smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid\n", __func__, smmuid);
		return -EFAULT;
	}

	(void)pthread_mutex_lock(&smmu->mutex);
	if (smmu->stat != SMMU_ENABLE) {
		(void)pthread_mutex_unlock(&smmu->mutex);
		tloge("%s, smmuid[%u] not enable!\n", __func__, smmuid);
		return -EFAULT;
	}
	ste = &smmu->ste[sid];
	cd = (struct sec_smmu_cd *)(uintptr_t)smmu->base_addr.cd_virt;
	if (cd) {
		ste->entry[0] = 0;
		ste->entry[1] = 0;
	} else {
		tloge("%s, cd is null\n", __func__);
		(void)pthread_mutex_unlock(&smmu->mutex);
		return -EINVAL;
	}

	cdp = &cd[ssid];
	cdp->entry[0] = 0;
	cdp->entry[1] = 0;
	cdp->entry[CD_MAIR_INDEX] = 0;
	(void)pthread_mutex_unlock(&smmu->mutex);
	tloge("%s, sid:%u, ssid:%u\n", __func__, sid, ssid);
	return 0;
}

int sec_svm_bind_task(struct sec_smmu_para *mcl)
{
	int ssid;
	int ret;
	struct sec_smmu_device *smmu = NULL;

	smmu = sec_find_smmu(mcl->smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, mcl->smmuid);
		return -EFAULT;
	}

	pthread_mutex_lock(&smmu->mutex);
	ssid = hisi_sec_smmu_bitmap_alloc(smmu->ssid_map);
	if (ssid < 0) {
		tloge("%s,hisi_sec_smmu_bitmap_alloc failed!!\n", __func__);
		pthread_mutex_unlock(&smmu->mutex);
		return -EINVAL;
	}
	pthread_mutex_unlock(&smmu->mutex);
	tloge("%s ssid:%d!\n", __func__, ssid);

	ret = sec_smmu_bind(mcl->smmuid, mcl->sid, (u32)ssid, mcl->pid);
	if (ret) {
		tloge("%s sec_smmu_bind failed!\n", __func__);
		return -EFAULT;
	}
	mcl->ssid = ssid;

	return 0;
}

int sec_svm_unbind_task(struct sec_smmu_para *mcl)
{
	int ret;
	struct sec_smmu_device *smmu = NULL;

	smmu = sec_find_smmu(mcl->smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__, mcl->smmuid);
		return -EFAULT;
	}

	ret = sec_smmu_unbind(mcl->smmuid, mcl->sid, mcl->ssid);
	if (ret) {
		tloge("%s sec_smmu_bind failed!\n", __func__);
		return -EFAULT;
	}

	pthread_mutex_lock(&smmu->mutex);
	hisi_sec_smmu_bitmap_free(smmu->ssid_map, mcl->ssid);
	pthread_mutex_unlock(&smmu->mutex);
	return 0;
}

static void sec_svm_clear_global_config(struct sec_smmu_para *sec_mcl)
{
	int ret;
	struct sec_smmu_device *smmu = NULL;

	smmu = sec_find_smmu(sec_mcl->smmuid);
	if (!smmu) {
		tloge("%s, smmuid[%u] is invalid!\n", __func__,
				sec_mcl->smmuid);
		return;
	}

	pthread_mutex_lock(&smmu->mutex);
	if (!pw_ref(smmu)) {
		pthread_mutex_unlock(&smmu->mutex);
		tloge("%s smmu not poweron, return directly!\n", __func__);
		return;
	}
	pthread_mutex_unlock(&smmu->mutex);

	ret = sec_svm_unbind_task(sec_mcl);
	if (ret) {
		tloge("%s sec_smmu unbind failed!\n", __func__);
		return;
	}

	pthread_mutex_lock(&smmu->mutex);
	smmu->stat = SMMU_DISABLE;
	smmu->pw_ref = 0;
	pthread_mutex_unlock(&smmu->mutex);

	tlogd("%s clear global config done!\n", __func__);
}

static void sec_smmu_invalid_tcu_cache(struct sec_smmu_device *smmu)
{
	u32 reg;
	u32 check_times = 0;

	(void)pthread_mutex_lock(&smmu->mutex);
	if (smmu->stat != SMMU_ENABLE) {
		tloge("%s, smmuid[%u] not enable!\n", __func__, smmu->smmuid);
		(void)pthread_mutex_unlock(&smmu->mutex);
		return;
	}

	reg = hisi_readl(smmu->base + TTW_OPT_FUNC_BYPASS);
	if (reg & 0x1) { /* 0x1: disable tcu_ttw_opt function; */
		tloge("%s, smmuid[%u] tcp cache bypass!\n", __func__, smmu->smmuid);
		(void)pthread_mutex_unlock(&smmu->mutex);
		return;
	}
	hisi_writel(CACHELINE_SOFT_INV, smmu->base + CACHELINE_INV_ALL);
	do {
		reg = hisi_readl(smmu->base + CACHELINE_INV_ALL);
		if (!(reg & 0x1)) /* cacheline_apb_inv_all: [0x1:invalidate;] */
			break;
		hisi_udelay(1);
		if (++check_times >= MAX_CHECK_TIMES) {
			tloge("%s: CACHELINE_INV_ALL failed !\n", __func__);
			pthread_mutex_unlock(&smmu->mutex);
			return;
		}
	} while (1);
	(void)pthread_mutex_unlock(&smmu->mutex);
}

static void sec_smmu_flush_tlb_npu(struct sec_smmu_para *sec_mcl)
{
	struct sec_smmu_device *smmu = NULL;

	smmu = sec_find_smmu(sec_mcl->smmuid);
	if (!smmu) {
		tloge("%s, smmuid is invalid!\n", __func__);
		return;
	}

	secsmmu_tlb_inv_asid(sec_mcl->smmuid, sec_mcl->sid, sec_mcl->ssid);
	sec_smmu_invalid_tcu_cache(smmu);
}

s32 __teesvm_ioctl(int smmu_ta_tag, struct sec_smmu_para *sec_mcl)
{
	s32 ret = 0;

	if (!sec_mcl) {
		tloge("%s, invalid params!!\n", __func__);
		return -EINVAL;
	}

	switch (smmu_ta_tag) {
	case SVM_SEC_CMD_POWER_ON:
		ret = sec_smmu_poweron(sec_mcl->smmuid);
		break;
	case SVM_SEC_CMD_POWER_OFF:
		ret = sec_smmu_poweroff(sec_mcl->smmuid);
		break;
	case SVM_SEC_CMD_BIND:
		ret = sec_svm_bind_task(sec_mcl);
		break;
	case SVM_SEC_CMD_UNBIND:
		ret = sec_svm_unbind_task(sec_mcl);
		break;
	case SVM_SEC_CMD_FLUSH_TLB:
		sec_smmu_flush_tlb_npu(sec_mcl);
		break;
	case SVM_SEC_CMD_CLEAR_RES:
		sec_svm_clear_global_config(sec_mcl);
		break;
	default:
		tloge("invalid smmu_ta_tag\n");
		return -EFAULT;
	}

	return ret;
}

#include <hmdrv_stub.h>
int sec_smmu_syscall(int swi_id, struct drv_param *params, uint64_t permissions)
{
	uint32_t ret;

	if (params == NULL || params->args == 0)
		return -EFAULT;

	uint64_t *args = (uint64_t *)(uintptr_t)params->args;

	HANDLE_SYSCALL(swi_id) {
		SYSCALL_PERMISSION(SW_SYSCALL_NPU_SMMU_SVM,
			permissions, AI_GROUP_PERMISSION);
		ACCESS_CHECK_A64(args[1],
			sizeof(struct sec_smmu_para));
		ACCESS_READ_RIGHT_CHECK(args[1],
			sizeof(struct sec_smmu_para));
		ret = (uint32_t)__teesvm_ioctl((int)args[0],
			(struct sec_smmu_para *)(uintptr_t)args[1]);
		args[0] = ret;
		SYSCALL_END

		default:
			return -EINVAL;
	}
	return 0;
}

DECLARE_TC_DRV(
	tee_smmuv3_driver,
	0,
	0,
	0,
	TC_DRV_MODULE_INIT,
	sec_smmu_init,
	NULL,
	sec_smmu_syscall,
	NULL,
	NULL
);
