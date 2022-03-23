/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: add acc device for kunpeng
 * Author: zhanglinhao zhanglinhao@huawei.com
 * Create: 2020-10
 */

#ifndef ACC_COMMON_H
#define ACC_COMMON_H

#include <stdint.h>
#include <stdbool.h>
#include <register_ops.h>
#include <tee_log.h>
#include <timer.h>
#include <stdlib.h>
#include "securec.h"

#define QM_VF_MB_0 (0x300)
#define QM_VF_MB_1 (0x304)
#define QM_VF_MB_2 (0x308)
#define QM_VF_MB_3 (0x30C)

#define QM_VFT_CFG_TYPE_REG 0x005C
#define QM_VFT_CFG_ADDRESS_REG 0x0060
#define QM_VFT_CFG_DATA_L_REG 0x0064
#define QM_VFT_CFG_DATA_H_REG 0x0068
#define QM_VFT_CFG_RDY_REG 0x006C
#define QM_VFT_CFG_RDY_MASK (1<<0)
#define QM_VFT_CFG_RDY_CLR (0)

#define QM_VFT_CFG_OP_EN_REG 0x0054
#define QM_VFT_CFG_OP_EN_MASK (1<<0)
#define QM_VFT_CFG_OP_WR_REG 0x0058
#define QM_VFT_CFG_OP_READ (1)
#define QM_VFT_CFG_OP_WRITE (0)

#define QM_VF_SQ_CQ_DB_0 (0x1000)
#define QM_VF_EQ_AEQ_DB_0 (0x2000)

#define SC_SEC_ICG_EN_REG	0x390
#define SC_SEC_ICG_DIS_REG	0x394
#define SC_SEC_RESET_REQ_REG	0xA28
#define SC_SEC_RESET_DREQ_REG	0xA2C
#define SC_SEC_ICG_ST_REG	0x5390
#define SC_SEC_RESET_ST_REG	0x5A28

#define SEC_RESET_MASK	GENMASK(1, 0)

#define SEC_ACC_COMMON_REG_OFF	0x1000

#define SEC_PF_ABNORMAL_INT_ENABLE_REG	0x000
#define SEC_PF_INT_MSK	0x1ff
#define SEC_PF_ABNORMAL_INT_STATUS_REG	0x0008
#define SEC_PF_ABNORMAL_INT_SOURCE_REG	0x0010
#define SEC_PF_ABNORMAL_INT_SET_REG	0x0018
#define SEC_RAS_CE_INT_COUNT_REG	0x0030
#define SEC_RAS_INT_WIDTH_PLUS_REG	0x0034
#define SEC_RAS_CE_ENABLE_REG		0x50
#define SEC_RAS_FE_ENABLE_REG		0x54
#define SEC_RAS_NFE_ENABLE_REG	0x58
#define SEC_RAS_CE_ENB_MSK			0x88
#define SEC_RAS_FE_ENB_MSK			0x0
#define SEC_RAS_NFE_ENB_MSK		0x177
#define SEC_MEM_START_INIT_REG	0x0100
#define SEC_MEM_INIT_DONE_REG	0x0104
#define SEC_MEM_TIMING_REG	0x0108
#define SEC_ECC_ENABLE_REG	0x010c
#define SEC_CNT_CLR_CE_REG	0x0120
#define SEC_FSM_MAX_CNT_REG	0x0124
#define SEC_SGL_OFFSET_CONTROL_REG	0x0130
#define SEC_PAGE_SIZE_CONTROL_REG	0x0134
#define SEC_DIF_CRC_INIT_REG	0x0138

#define SEC_CONTROL_REG	0x0200
#define SEC_TRNG_EN_SHIFT	8

#define SEC_AXI_CACHE_CFG_REG	0x0210
#define SEC_AXI_CACHE_CFG_1_REG	0x0214
#define SEC_SNPATTR_CFG_REG	0x0218
#define SEC_INTERFACE_USER_CTRL0_REG	0x0220
#define SEC_INTERFACE_USER_CTRL1_REG	0x0224
#define SEC_BD_CS_PACKET_OST_CFG_REG	0x0240
#define SEC_DATA_OST_CFG_REG	0x0248
#define SEC_SAA_CLK_EN_REG	0x0260
#define SEC_SAA_EN_REG	0x0270
#define SEC_REQ_TRNG_TIME_TH_REG	0x0280
#define SEC_BD_ERR_CHK_EN_REG(n)	(0x0380 + (n) * 0x04)

#define BD_LATENCY_MIN_REG	0x0600
#define BD_LATENCY_MAX_REG	0x0608
#define BD_LATENCY_AVG_REG	0x060C
#define BD_NUM_IN_SAA_0_REG	0x0670
#define BD_NUM_IN_SAA_1_REG	0x0674
#define BD_NUM_IN_SEC_REG		0x0680

#define SEC_PF_FSM_HBEAT_INFO_REG(n)	(0x20 + (n) * 0x4)
#define SEC_FSM_USE_REG_NUM	2
#define SEC_BD_M_FSM_REG		0x700
#define SEC_KEY_FSM_REG			0x704
#define SEC_IV_FSM_REG			0x708
#define SEC_IV_KEY_FSM_REG		0x70c
#define SEC_CLU_ALG_FSM_REG	0x710
#define SEC_RD_SGE_FSM_REG	0x72c
#define SEC_RD_HAC_SGE_FSM_REG(n)	(0x730 + (n) * 0x4)
#define SEC_AW_HAC_FSM_REG(n)	(0x750 + (n) * 0x4)	
#define SEC_SGE_CBB_NUM		3
#define SEC_DIF_SHAPE_REG(n)	(0x760 + (n) * 0x4)
#define SEC_CHANNEL_NUM		9
#define SEC_BD_TOP_FSM_REG	0x7A0

#define SEC_ECC_1BIT_CNT_REG	0xC00
#define SEC_ECC_1BIT_INFO_REG	0xC04
#define SEC_ECC_2BIT_CNT_REG	0xC10
#define SEC_ECC_2BIT_INFO_REG	0xC14

#define SEC_USER0_SMMU_NORMAL	((1<<23) |(1<<15))
#define SEC_USER1_SMMU_NORMAL	((1<<31) |1<<(23) |(1<<15) |(1<<7))
#define MAX_SQ_PRIORITY 16
#define MAX_SQ_TYPE 8
#define QM_CQE_SIZE 16
#define QM_EQE_SIZE 4
#define QM_XQC_SIZE 32

#define ACC_ENGINE_PF_CFG_OFF 0x300000
#define ACC_QM_PF_CFG_OFF 0x100000
#define ACC_QM_PF_OP_OFF 0x000000

#define SEC_QUEUE_DEPTH   31

#define SEC_POLL_TIMEOUT_MS   1 /* 1ms */

#define SEC_CHAIN_ABN_RD_ADDR_LOW 0x300
#define SEC_CHAIN_ABN_RD_ADDR_HIG 0x304
#define SEC_CHAIN_ABN_RD_LEN 0x308
#define SEC_CHAIN_ABN_WR_ADDR_LOW 0x310
#define SEC_CHAIN_ABN_WR_ADDR_HIG 0x314
#define SEC_CHAIN_ABN_WR_LEN 0x318

#define SEC_CHAIN_ABN_LEN 128UL

#define QM_ARUSER_M_CFG_0   0x0084
#define QM_ARUSER_M_CFG_1 0x0088
#define QM_ARUSER_M_CFG_EN 0x0090
#define QM_AWUSER_M_CFG_0   0x0094
#define QM_AWUSER_M_CFG_1 0x0098
#define QM_AWUSER_M_CFG_EN 0x00A0
#define QM_WUSER_M_CFG_EN 0x00A8
#define QM_RWUSER_CFG_VAL (0x40000070UL)
#define QM_RWUSER_CFG_EN_MASK GENMASK(31, 0)
#define QM_WUSER_CFG_EN_MASK (1 << 0)

#define QM_MAILBOX_OP_WR 0
#define QM_MAILBOX_OP_RD 1

#define QM_MEM_START_INIT_REG 0x0040
#define QM_MEM_START_INIT_MASK (1<<0)
#define QM_MEM_INIT_DONE_REG 0x0044
#define QM_MEM_INIT_DONE_MASK (1<<0)

#define ACC_POLL_TIMEOUT_MS             1UL
#define ACC_DELAY_10_US                 10UL
#define QM_CACHE_WB_START_REG    0x204
#define QM_CACHE_WB_DONE_REG     0x208

struct acc_device;
struct qm_function;
struct qm_func_ops;
extern uint32_t session_id;

static inline void do_sq_cq_db(uint64_t val, void *base)
{
	writeq(val, (uint64_t)base + QM_VF_SQ_CQ_DB_0);
}

static inline void do_eq_aeq_db(uint64_t val, void  *base)
{
	writeq(val, (uint64_t)base + QM_VF_EQ_AEQ_DB_0);
}

static inline void write_128bits(volatile void *dst, void *src)
{
	unsigned long tmp0 = 0;
	unsigned long tmp1 = 0;

	asm volatile (
		"	     ldp     %0, %1, %3     \n"
		"	     stp     %0, %1, %2     \n"
		"	     dsb     sy			 \n"
		: "=&r"(tmp0), "=&r"(tmp1), "+Q"(*((char *)dst))
		: "Q"(*((char *)src))
		: "memory");
}

static inline int32_t __do_mb(void *val, void  *base)
{
	uint32_t reg = 0;

	SRE_SwMsleep(ACC_POLL_TIMEOUT_MS);
	reg = readl((uint64_t)base + QM_VF_MB_0);
	if ((reg >> 13) & 0x1) {
		tloge("mb status busy 0x%x\n", reg);
		return -1;
	}

	write_128bits(base + QM_VF_MB_0, val);
	/* Make sure the sequence of writing is okay */

	SRE_SwMsleep(ACC_POLL_TIMEOUT_MS);
	reg = readl((uint64_t)base + QM_VF_MB_0);
	if ((reg >> 13) & 0x1) {
		tloge("mb status busy 0x%x\n", reg);
		return -1;
	}

	return 0;
}

struct device {
    struct device           *parent;
    const char              *init_name; /* initial name of the device */
    void            *platform_data; /* Platform specific data, device
                                       core doesn't touch it */
    void            *driver_data;   /* Driver data, set and get with*/
    uint64_t             *dma_mask;      /* dma mask (if dma'able device) */
    uint64_t             coherent_dma_mask;/* Like dma_mask, but for
                                              alloc_coherent mappings as
                                              not all hardware supports
                                              64 bit addresses for consistent
                                              allocations such descriptors. */
    unsigned long   dma_pfn_offset;

    uint32_t                     id;     /* device instance */
};

enum acc_device_type {
    DEV_UNKNOWN = 0,
    DEV_HPRE,
    DEV_HPREVF,
    DEV_RDE,
    DEV_RDEVF,
    DEV_SEC,
    DEV_SECVF,
    DEV_ZIP,
    DEV_ZIPVF,
    DEV_POE
};

struct acc_hw_device_class {
    const char *name;
    const enum acc_device_type type;
    uint32_t instances;
};

struct acc_hw_device_data {
    uint32_t (*get_num_accels)(struct acc_hw_device_data *self);
    uint32_t (*get_pf2vf_offset)(uint32_t i);
    uint64_t (*get_subctrl_base)(uint32_t chip_id);
    uint32_t (*get_chip_id)(void);
    uint32_t (*get_prp_page_size)(struct acc_device *adev);
    uint32_t (*get_comp_head_size)(struct acc_device *adev);
    void (*get_device_dfx_info)(void);
    void (*bd_visilize)(struct acc_device *adev);
    /* irqreturn_t (*ras_handler)(struct acc_device *adev); */

    int32_t (*set_crc_seed)(struct acc_device *adev, uint16_t seed);
    int32_t (*set_prp_page_size)(struct acc_device *adev, uint32_t size);
    int32_t (*set_sge_offset)(struct acc_device *adev, uint32_t offset);
    int32_t (*set_comp_head_size)(struct acc_device *adev, uint32_t offset);

    int32_t (*reset_device)(struct acc_device *adev);
    int32_t (*init_device)(struct acc_device *adev);
    int32_t (*init_pf)(struct acc_device *adev);
    int32_t (*init_vf)(struct acc_device *adev, struct qm_func_ops *ops);

    uint32_t priv_data_size;
    uint32_t subctrl_size;
    uint64_t base_addr;
    uint64_t subctrl_addr;
    uint64_t peh_addr;
};

struct acc_stats_info {
	long io_latency_sum;
	long max_io_latency;
	long min_io_latency;
	long chip_latency_sum;
	long max_chip_latency;
	long min_chip_latency;
	long stats_io_num;
};

struct acc_stats_ctrl {
	struct acc_stats_info stats_info;
	bool enable_stats;	
	int32_t err_bd1_num;
	int32_t err_bd2_num;
};

enum qm_hw_ver {
    QM_HW_UNKNOWN = -1,
    QM_HW_V1 = 1,
    QM_HW_V2
};

struct qm_xqc {
	uint32_t data[QM_XQC_SIZE / 4];
};

struct qm_sq {
	void *virt_addr;
	uint64_t dma_addr;
	uint64_t cmpl_sqe_num;
	uint64_t submit_db_num;
	uint16_t tail;
	uint16_t last_tail;
	uint16_t depth;
	uint16_t cqn;
	uint16_t rand_data;
	uint8_t burst_cnt_shift;
	uint8_t type;
	uint8_t order;
	bool valid;
};

struct qm_cqe {
	uint32_t data[QM_CQE_SIZE / sizeof(uint32_t)];
};

struct qm_eqe {
	uint32_t data[QM_EQE_SIZE / sizeof(uint32_t)];
};

struct qm_cq {
	struct qm_cqe *virt_addr;
	uint64_t dma_addr;
	void **handled_sqe_addr;
	uint16_t head;
	uint16_t depth;
	uint32_t phase;
	uint16_t rand_data;
};

struct qm_eq {
	struct qm_eqe *virt_addr;
	uint64_t dma_addr;
	uint16_t head;
	uint16_t depth;
	uint32_t phase;
};

struct qm_sq_selector {
	uint32_t start_id;
	uint32_t num;
	uint32_t cur_id;
};

struct session_node {
	void *priv_data;
	uint16_t session_id;
	uint8_t in_use;
	bool in_qm;
};

struct qm_func_ops {
	int (*priv_data_init)(struct device *dev, void *priv_data, uint16_t id);
	void (*priv_data_exit)(struct device *dev, void *priv_data, uint16_t i);
	int (*task_complete_proc)(struct qm_function *qm_func, void *sqe,
		void *priv_data);
	int (*task_fault_proc)(struct qm_function *qm_func, void *priv_data,
		uint16_t session_id);
	uint16_t (*get_tag_field)(void *sqe);
	void (*set_tag_field)(void *sqe, uint16_t tag_value);
	int (*soft_reset)(void);
	int (*engine_init)(void);
};

struct qm_cq_work {
	struct qm_function *qm_func;
	uint16_t cqn;
};

struct qm_function {
	void *base;
	void *qm_pf_cfg_base;
	struct qm_sq *sq;
	struct qm_xqc *sqc;
	uint64_t sqc_dma_addr;
	struct qm_cq *cq;
	struct qm_xqc *cqc;
	uint64_t cqc_dma_addr;
	struct qm_eq eq;
	struct qm_eq aeq;
	struct qm_sq_selector sq_select[MAX_SQ_TYPE][MAX_SQ_PRIORITY];
	uint16_t sq_num;
	uint16_t cq_num;
	uint16_t sqe_size;
	uint16_t session_num;
	uint16_t priv_data_size;
	uint16_t cur_start_sqn;
	bool enable_flow_stats;
	bool in_reset;
	int32_t msi_vector_num;
	uint16_t db_thresh;
	uint8_t one_db_for_one_bd;
	uint8_t ver;
	int32_t pack_sqe_num;
	int32_t total_eq_int_num;
	int32_t empty_eq_int_num;
	int32_t status_field_err_num;
	struct session_node *session_table;
	struct qm_func_ops *ops;
	char *eq_name;
	char *aeq_name;
	char *flr_int_name;
	char *pf_int_name;
	struct qm_cq_work *cq_work;
};

struct acc_device {
    struct acc_hw_device_data *hw_device;
    struct acc_stats_ctrl stats_ctrl;

    struct qm_function qm_func;

    bool smmu_normal;
    bool is_vf;
    unsigned long status;
    uint32_t dev_id;
    enum qm_hw_ver revid;
    uint32_t chip_id;
    uint32_t num_vfs; /* Num VFs requested for this PF */
    uint32_t prp_page_size;
    uint32_t sq_num;
    uint32_t endian;
};

struct qm_sq_config {
	uint32_t sq_num;
	uint32_t depth;
	uint32_t burst_cnt_shift;
	uint32_t type;
	uint32_t order;
};

struct qm_vf_config {
	struct qm_sq_config *sq_config;
	uint32_t sq_config_num;
	uint16_t sqe_size;
	uint16_t cq_depth;
	uint16_t cq_num;
	uint16_t eq_depth;
	uint16_t aeq_depth;
	uint16_t session_num;
	uint16_t priv_data_size;
};

struct qm_cq_config {
	uint16_t cq_num;
	uint16_t depth;
};

struct qm_queue_config {
	struct qm_sq_config *sq_config;
	struct qm_cq_config *cq_config;
	uint32_t sq_config_num;
	uint32_t cq_config_num;
	uint16_t eq_depth;
	uint16_t aeq_depth;
};

struct sqc_vft_config {
	uint16_t sq_num;
	uint8_t valid;
};

struct cqc_vft_config {
	uint8_t valid;
};

typedef void (*QM_HOOK_FUNC)(void *Arg, void *Result);

struct qm_enqueue_req {
	void *bd;
	uint32_t bd_num;
	uint32_t sq_burst;
	uint32_t sq_type;
	QM_HOOK_FUNC hook_func;
	void *hook_para;
};

enum qm_dump_type {
	DUMP_SQ = 0,
	DUMP_SQC,
	DUMP_CQ,
	DUMP_CQC,
	DUMP_EQ,
	DUMP_EQC,
	DUMP_AEQ,
	DUMP_AEQC,
	DUMP_SQ_SELECTOR,
	DUMP_CMD_MAX
};

struct acc_latency_info {
	long io_latency;
	long chip_latency;
};

int qm_pf_init(struct qm_function* qm, void  *cfg_addr);
void qm_set_smmu(struct qm_function *pf_info, uint32_t smmu_normal);
int qm_pf_config_vft(struct qm_function *pf_info, uint32_t vft_id,
	const struct sqc_vft_config *vft_sqc,
	const struct cqc_vft_config *vft_cqc);
void qm_function_set_dev(struct qm_function *qm_func, void  *addr_base);
int qm_function_init(struct qm_function *qm_func,
	struct qm_vf_config *vf_config, struct qm_func_ops *ops);
void qm_function_free(struct qm_function *qm_func);
int acc_common_get_session(struct qm_function *qm_func, void **out_sess_data,
	uint16_t *out_sess_id);
int acc_common_put_session(struct qm_function *qm_func, uint16_t session_id);
int qm_bd_enqueue(struct qm_function *qm_func, struct qm_enqueue_req *req);
int qm_multi_sqe_enqueue(struct qm_function *qm_func,
	struct qm_enqueue_req *req);

int acc_set_config(struct qm_queue_config *q_config, uint32_t *sq_index, uint32_t *cq_index,
	uint16_t sq_config_num, uint16_t cq_config_num, uint16_t eq_depth, uint16_t aeq_depth);

int qm_pf_reconfig_sqc_vft(struct qm_function *pf_info, uint32_t vft_id,
		   const struct sqc_vft_config *vft_sqc);
int qm_pf_reconfig_cqc_vft(struct qm_function *pf_info, uint32_t vft_id,
		   const struct cqc_vft_config *vft_cqc);
int acc_common_reinit_session(struct qm_function *qm_func, uint16_t session_num);
int qm_set_db_thresh(struct qm_function *qm_func, uint16_t db_thresh);

#define readl_relaxed_poll_timeout(addr, val, cond, delay_us, timeout_us) \
({ \
	uint32_t times = timeout_us / delay_us; \
	while (times) { \
		(val) = readl(addr); \
		if (cond) \
			break; \
		SRE_SwMsleep(delay_us); \
		times--; \
	} \
	(cond) ? 0 : -ETIMEDOUT; \
})

extern int sec_soft_reset(struct acc_device *sec_dev);
extern void acc_init_hw_data_sec(struct acc_hw_device_data *hw_data);
extern int acc_dev_init(struct acc_device *adev);
extern int sec_engine_init(struct acc_device *sec_dev);
extern uint32_t *kzalloc_align(size_t size, size_t align);

#endif
