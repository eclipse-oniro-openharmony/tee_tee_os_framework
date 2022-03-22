/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __ACC_COMMON_QM_H__
#define __ACC_COMMON_QM_H__

#include "hi_sec_dlv.h"
#define QM_MAX_FUNCTION_NUM	64
#define QM_MAX_QP_NUM	1024
#define QM_MAX_QUEUE_DEPTH	4096
#define QM_MAX_BURST_CNT_SHIFT	16

#define QM_SQC_VFT (0)
#define QM_CQC_VFT (1)

#define QM_SQC_VFT_SQ_NUM_SHIFT 45
#define QM_SQC_VFT_SQ_NUM_MASK GENMASK(54, 45)
#define QM_SQC_VFT_VALID_SHIFT 44
#define QM_SQC_VFT_START_SQN_SHIFT 28
#define QM_SQC_VFT_START_SQN_MASK GENMASK(43, 28)

#define QM_CQC_VFT_VALID_SHIFT 28

#define QM_SQC_SQE_SIZE_SHIFT 12
#define QM_SQC_SQE_SIZE_MASK GENMASK(15, 12)
#define QM_SQC_QES_MASK	GENMASK(11, 0)
#define QM_SQC_BURST_CNT_SHIFT 16
#define QM_SQC_BURST_CNT_MASK GENMASK(19, 16)
#define QM_SQC_ORDER_SHIFT 20
#define QM_SQC_ORDER_MASK GENMASK(23, 20)
#define QM_SQC_TYPE_SHIFT 24
#define QM_SQC_TYPE_MASK GENMASK(27, 24)

#define QM_CQC_CQE_SIZE_SHIFT 12
#define QM_CQC_QES_MASK GENMASK(11, 0)
#define QM_CQC_CQE_SIZE_MASK GENMASK(15, 12)
#define QM_CQC_C_FLAG_SHIFT 1

#define QM_CQE_COMMAND_IDENTIFIER_MASK GENMASK(15, 0)
#define QM_CQE_SQ_IDENTIFIER_SHIFT 16
#define QM_CQE_SQ_HEAD_POINTER_MASK GENMASK(15, 0)
#define QM_CQE_STATUS_FIELD_SHIFT 17
#define QM_CQE_STATUS_FIELD_MASK GENMASK(24, 17)
#define QM_CQE_P_MASK (1<<16)

#define QM_EQC_PHASE_SHIFT 16
#define QM_EQE_P_MASK (1<<16)
#define QM_EQE_CQN_MASK GENMASK(15, 0)

#define QM_AEQC_PHASE_SHIFT 16
#define QM_AEQE_P_MASK (1<<16)
#define QM_AEQE_QN_MASK GENMASK(15, 0)
#define QM_AEQE_TYPE_MASK GENMASK(20, 17)
#define QM_AEQE_TYPE_SHIFT 17

#define QM_MAILBOX_SIZE 16

#define QM_MB_CMD_MASK GENMASK(7, 0)
#define QM_MB_BUSY_SHIFT 13
#define QM_MB_BUSY_MASK (1<<13)
#define QM_MB_OP_TYPE_SHIFT 14
#define QM_MB_OP_TYPE_MASK (1<<14)
#define QM_MB_QUEUE_SHIFT 16
#define QM_MB_QUEUE_MASK GENMASK(31, 16)

#define QM_DB_CMD_SHIFT 12
#define QM_DB_RAND_DATA_SHIFT 16
#define QM_DB_PRIORITY_SHIFT 16

enum qm_doorbell_cmd {
	DB_SQ = 0,
	DB_CQ,
	DB_EQ,
	DB_AEQ,
	DB_CMD_MAX
};

enum qm_mailbox_cmd {
	MB_SQC = 0,
	MB_CQC,
	MB_EQC,
	MB_AEQC,
	MB_SQC_BT,
	MB_CQC_BT,
	MB_SQC_VFT,
	MB_CMD_MAX
};

struct mailbox {
	uint32_t data[QM_MAILBOX_SIZE / sizeof(uint32_t)];
};

uint64_t db_set(uint16_t qn, uint8_t cmd, uint16_t index, uint8_t priority, uint16_t rand_data);
int32_t qm_send_mb(uint8_t cmd, uint64_t addr, uint16_t queue, uint8_t op_type, void *base);
int32_t qm_write_vft(void *base, uint8_t vft_type, uint32_t vft_addr, uint64_t vft_data);
int32_t qm_init_sq(struct qm_function *qm_func, struct qm_sq_config *sq_config, uint32_t config_num);
int32_t qm_init_cq(struct qm_function *qm_func, uint16_t cq_depth);
int32_t qm_init_eq(struct qm_function *qm_func);
int32_t qm_read_vft(void *base, uint8_t vft_type, uint32_t vft_addr, uint64_t *vft_data);
#ifndef CONFIG_HI1620_ESL
int32_t qm_write_back_cache(struct qm_function *qm_func);
#endif
int32_t qm_modify_vft_start_sqn(struct qm_function *pf_info, uint16_t start_sqn,
	uint16_t change_num, uint8_t inscrease_flag);
int32_t qm_verify_vf_config(const struct qm_queue_config *queue_config);
void qm_function_release(struct qm_function *qm_func);
/*int qm_reinit_cq(struct qm_function *qm_func, struct qm_cq_config *cq_config);*/
/*int qm_function_reset(struct qm_function *qm_func);*/
struct qm_xqc *qm_get_a_xqc(struct qm_function *func, uint64_t *dma_handle, uint64_t *orig_addr);
void qm_free_a_xqc(struct qm_function *func, uint64_t addr, unsigned long long  dma_handle);
int qm_reg_test(void *base);

#endif

