#ifndef __HISI_SVM_H
#define __HISI_SVM_H
#include <endian.h>
#include <byteswap.h>
#include <sys/hm_types.h> /* pid_t */

#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#else /* __LITTLE_ENDIAN */
#define cpu_to_le64(x) x
#define le64_to_cpu(x) x
#endif /* __BYTE_ORDER */

enum svm_ta_tag{
	SVM_SEC_CMD_POWER_ON = 0,
	SVM_SEC_CMD_BIND,
	SVM_SEC_CMD_UNBIND,
	SVM_SEC_CMD_POWER_OFF,
	SVM_SEC_CMD_GET_SSID,
	SVM_SEC_CMD_FLUSH_TLB,
	SVM_SEC_CMD_AICPU_IRQ,
	SVM_SEC_CMD_CLEAR_RES,
	SVM_SEC_CMD_MAX,
};

struct hisi_tee_svm {
	uint64_t pgd;
	uint16_t asid;
	pid_t pid;
	struct hisi_sec_smmu_domain *smmu_domain;
};

struct hisi_aicpu_irq_info {
	u64 pgfault_asid_addr;
	u64 pgfault_va_addr;
	int (*callback)(void *); /* reserved */
	u64 cookie; /* reserved */
};

struct tee_svm_para_list {
	u16 ssid;
	pid_t pid;
	unsigned int smmuid;
	u64 ttbr;
	u64 tcr;
	struct hisi_tee_svm *tee_svm_p;
	struct hisi_aicpu_irq_info aicpu_irq;
};

static inline void HISI_DWB(void) /* drain write buffer */
{
	asm volatile("dsb");
}

static inline void hisi_writel(unsigned val, unsigned addr)
{
	HISI_DWB();
	(*(volatile unsigned *)(addr)) = (val);
	HISI_DWB();
}

static inline unsigned hisi_readl(unsigned addr)
{
	return (*(volatile unsigned *)(addr));
}

void hisi_smmu_group_flush_tlb(void);

#endif
