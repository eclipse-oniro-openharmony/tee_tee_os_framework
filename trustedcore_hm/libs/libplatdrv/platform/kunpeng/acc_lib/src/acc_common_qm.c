/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


#include "tee_log.h"
#include "acc_common.h"
#include "acc_common_qm.h"
#include "mem_ops.h"
#include <cache_flush.h>
#include <string.h>

uint64_t db_set(uint16_t qn, uint8_t cmd, uint16_t index, uint8_t priority, uint16_t rand_data)
{
	uint64_t val;

	val = index | ((uint32_t)priority << QM_DB_PRIORITY_SHIFT);
	val <<= 32;
	val |= (((uint64_t)cmd << QM_DB_CMD_SHIFT) | qn |
		((uint64_t)rand_data << QM_DB_RAND_DATA_SHIFT));

	return val;
}

int32_t qm_send_mb(uint8_t cmd, uint64_t addr, uint16_t queue, uint8_t op_type, void *base)
{
	uint8_t addr_mode;
	int32_t ret;
	uint64_t data;
	struct mailbox mb;

	if ((QM_MAILBOX_OP_RD == op_type) && (cmd >= MB_SQC_BT) && (cmd <= MB_SQC_VFT))
		addr_mode = 1;
	else
		addr_mode = 0;

	memset_s((void *)&mb, sizeof(mb), 0x0, sizeof(mb));
	mb.data[0] |= (cmd & QM_MB_CMD_MASK);
	mb.data[0] |= QM_MB_BUSY_MASK;
	mb.data[0] |= (((uint32_t)op_type << QM_MB_OP_TYPE_SHIFT) & QM_MB_OP_TYPE_MASK);
	mb.data[0] |= (((uint32_t)queue << QM_MB_QUEUE_SHIFT) & QM_MB_QUEUE_MASK);
	if (addr_mode == 0) {
		/* The addr should be DMA address for DMA */
		mb.data[1] = (uint32_t) (addr & GENMASK(31, 0));
		mb.data[2] = (uint32_t) (addr >> 32);
	} else {
		mb.data[1] = 0;
		mb.data[2] = 0;
	}
	/* token field */
	mb.data[3] = 0;
	ret = __do_mb(&mb, base);
	if (ret != 0)
		return ret;

	if (addr_mode) {
		/* make sure data has reached to DDR */
		data = readl((uintptr_t)base + QM_VF_MB_2);
		data = (data << 32) | (readl((uintptr_t)base + QM_VF_MB_1) & GENMASK(31, 0));
		/* The addr should be virtual address for CPU */
		*((uint64_t *) addr) = data;
	}

	return 0;
}

int32_t qm_write_vft(void *base, uint8_t vft_type, uint32_t vft_addr, uint64_t vft_data)
{
	uint32_t reg_val = 0;
    uint64_t data;

	if (readl_relaxed_poll_timeout(((uintptr_t)base + QM_VFT_CFG_RDY_REG),
		reg_val, reg_val & QM_VFT_CFG_RDY_MASK,
		ACC_DELAY_10_US, ACC_POLL_TIMEOUT_MS)) {
		tlogi("qm cfg rdy\n");
	} else {
		tloge("qm cfg not rdy\n");
		return -1;
	}
    __asm__ volatile("isb");

	writel(QM_VFT_CFG_OP_WRITE, (uintptr_t)base + QM_VFT_CFG_OP_WR_REG);
	writel(vft_type, (uintptr_t)base + QM_VFT_CFG_TYPE_REG);
	writel(vft_addr, (uintptr_t)base + QM_VFT_CFG_ADDRESS_REG);
	writel(vft_data >> 32, (uintptr_t)base + QM_VFT_CFG_DATA_H_REG);
	writel(vft_data & GENMASK(31, 0), (uintptr_t)base + QM_VFT_CFG_DATA_L_REG);

	data = readl((uintptr_t)base + QM_VFT_CFG_DATA_H_REG);
	data = data << 32;
	data |= readl((uintptr_t)base + QM_VFT_CFG_DATA_L_REG);

	writel(0x0, (uintptr_t)base + QM_VFT_CFG_RDY_REG);
	writel(0x1, (uintptr_t)base + QM_VFT_CFG_OP_EN_REG);
	/* Make sure clearing of QM_VFT_CFG_RDY_REG has completed */
    __asm__ volatile("dsb sy");
	if (readl_relaxed_poll_timeout(((uintptr_t)base + QM_VFT_CFG_RDY_REG),
		reg_val, reg_val & QM_VFT_CFG_RDY_MASK,
		ACC_DELAY_10_US, ACC_POLL_TIMEOUT_MS)) {
		tlogi("qm cfg rdy\n");
		return 0;
	} else {
		tloge("qm cfg not rdy\n");
		return -1;
	}
}

int32_t qm_read_vft(void *base, uint8_t vft_type, uint32_t vft_addr, uint64_t *vft_data)
{
	uint32_t reg_val = 0;
	uint64_t data;

	if (readl_relaxed_poll_timeout(((uintptr_t)base + QM_VFT_CFG_RDY_REG),
		reg_val, reg_val & QM_VFT_CFG_RDY_MASK,
		ACC_DELAY_10_US, ACC_POLL_TIMEOUT_MS)) {
	} else {
		tloge("qm cfg not rdy\n");
		return -1;
	}
    __asm__ volatile("isb");

	writel(QM_VFT_CFG_OP_READ, (uintptr_t)base + QM_VFT_CFG_OP_WR_REG);
	writel(vft_type, (uintptr_t)base + QM_VFT_CFG_TYPE_REG);
	writel(vft_addr, (uintptr_t)base + QM_VFT_CFG_ADDRESS_REG);
	writel(0x0, (uintptr_t)base + QM_VFT_CFG_RDY_REG);
	writel(0x1, (uintptr_t)base + QM_VFT_CFG_OP_EN_REG);
	/* Make sure clearing of QM_VFT_CFG_RDY_REG has completed */
    __asm__ volatile("dsb sy");

	if (readl_relaxed_poll_timeout(((uintptr_t)base + QM_VFT_CFG_RDY_REG),
		reg_val, reg_val & QM_VFT_CFG_RDY_MASK,
		ACC_DELAY_10_US, ACC_POLL_TIMEOUT_MS)) {
	} else {
		tloge("qm cfg not rdy\n");
		return -1;
	}
    __asm__ volatile("dsb sy");

	data = readl((uintptr_t)base + QM_VFT_CFG_DATA_H_REG);
	data = data << 32;
	data |= readl((uintptr_t)base + QM_VFT_CFG_DATA_L_REG);
    __asm__ volatile("dsb sy");
	*vft_data = data;

	return 0;
}

struct qm_xqc *qm_get_a_xqc(struct qm_function *func, uint64_t *dma_handle, uint64_t *orig_addr)
{
	struct qm_xqc *xqc;
	uint64_t size = (uint64_t)sizeof(*xqc);
	void *ret = malloc_coherent(size + 0x20);
	int32_t alig = (uint64_t)ret % 0x20;

	if (func) {
		// TODO
	}
	// TODO, need to check.
	*orig_addr = (uintptr_t)ret;
	ret = ret + 0x20 - alig;
	xqc = (struct qm_xqc *)ret;

	*dma_handle = (uintptr_t)virt_mem_to_phys((uintptr_t)xqc);

	return xqc;
}

void qm_free_a_xqc(struct qm_function *func,
			uint64_t addr, unsigned long long  dma_handle)
{
	if (func || dma_handle) {
		// TODO
	}
    free((void *)addr);
}

static int qm_sqc_set(struct qm_function *qm_func, uint16_t sq_id)
{
	int ret;
	struct qm_xqc *sqc;
	uint64_t orig_sqc;
	struct qm_xqc *sqc_rd;
	uint64_t orig_sqc_rd;
	uint64_t sqc_dma_addr = 0;
	uint64_t sqc_rd_dma_addr = 0;

	sqc = qm_get_a_xqc(qm_func, &sqc_dma_addr, &orig_sqc);
	if (!sqc)
		return -1;

	/*sec bd size= 128, hpre bd size = 64. hpre addr is 0xa08000000*/
	uint32_t bd_size_shift = ((uint64_t)qm_func->base == 0x208000000) ? 6 : 7;
	sqc->data[1] = qm_func->sq[sq_id].dma_addr & GENMASK(31, 0);
	sqc->data[2] = qm_func->sq[sq_id].dma_addr >> 32;
	sqc->data[3] = ((bd_size_shift << QM_SQC_SQE_SIZE_SHIFT) & QM_SQC_SQE_SIZE_MASK);
	sqc->data[3] |= qm_func->sq[sq_id].depth & QM_SQC_QES_MASK;
	sqc->data[4] = qm_func->sq[sq_id].rand_data;
	sqc->data[5] = (((uint32_t)qm_func->sq[sq_id].burst_cnt_shift <<
		QM_SQC_BURST_CNT_SHIFT) & QM_SQC_BURST_CNT_MASK);
	sqc->data[6] = qm_func->sq[sq_id].cqn;
	sqc->data[6] |= (((uint32_t)qm_func->sq[sq_id].order << QM_SQC_ORDER_SHIFT) &
	    QM_SQC_ORDER_MASK);
	sqc->data[6] |= (((uint32_t)qm_func->sq[sq_id].type << QM_SQC_TYPE_SHIFT) &
	    QM_SQC_TYPE_MASK);

	ret = qm_send_mb(MB_SQC, (uint64_t)sqc_dma_addr, sq_id,
		QM_MAILBOX_OP_WR, qm_func->base);
	if (ret != 0) {
		tloge("fail to send mailbox to set SQC\n");
		goto exit;
	}
    __dma_flush_range((uintptr_t)sqc, (uintptr_t)sqc + sizeof(struct qm_xqc));

	sqc_rd = qm_get_a_xqc(qm_func, &sqc_rd_dma_addr, &orig_sqc_rd);	
	if (!sqc_rd) {
		ret = -1;
		goto exit;
	}

	ret = qm_send_mb(MB_SQC, (uint64_t)sqc_rd_dma_addr, sq_id,
		QM_MAILBOX_OP_RD, qm_func->base);
	if (ret != 0) {
		tloge("fail to send mailbox to read SQC\n");
		goto exit1;
	}
    __dma_flush_range((uintptr_t)sqc_rd, (uintptr_t)sqc_rd + sizeof(struct qm_xqc));
	/* make sure data has reached to DDR */

	ret = memcmp(sqc_rd, sqc, QM_XQC_SIZE);
	if (ret != 0) {
		int i;
		tloge("write sqc\n", ret);
		for (i = 0; i < 8; i++) {
			tloge(" 0x%x ", sqc->data[i]);
		}
		tloge("\nread sqc\n", ret);
		for (i = 0; i < 8; i++) {
			tloge(" 0x%x ", sqc_rd->data[i]);
		}
		tloge("error! invalid SQC setting 0x%x\n", ret);
		ret = -1;
	}

exit1:
	qm_free_a_xqc(qm_func, orig_sqc_rd, sqc_rd_dma_addr);
exit:
	qm_free_a_xqc(qm_func, orig_sqc, sqc_dma_addr);
	return ret;
}

static int qm_sq_info_set(struct qm_function *qm_func,
			  struct qm_sq_config *sq_config, uint16_t sq_id)
{
	uint16_t real_depth;
	uint16_t ratio;
	int i;
	int ret;

	real_depth = (0 == sq_config->depth) ? 2 : (sq_config->depth + 1);
	uint64_t size = (uint64_t)real_depth * qm_func->sqe_size;
	qm_func->sq[sq_id].virt_addr = (void *)kzalloc_align(size, 0x80);
	qm_func->sq[sq_id].dma_addr = virt_mem_to_phys((uintptr_t)(qm_func->sq[sq_id].virt_addr));

	qm_func->sq[sq_id].depth = sq_config->depth;
	qm_func->sq[sq_id].type = sq_config->type;
	qm_func->sq[sq_id].burst_cnt_shift = sq_config->burst_cnt_shift;
	qm_func->sq[sq_id].order = sq_config->order;
	ratio = (!(qm_func->sq_num % qm_func->cq_num)) ?
		(qm_func->sq_num / qm_func->cq_num) :
		(qm_func->sq_num / qm_func->cq_num + 1);
	qm_func->sq[sq_id].cqn = sq_id / ratio;
	qm_func->sq[sq_id].rand_data = 0x5a;
	tlogi("[set sq]ratio 0x%x, cqn 0x%x, real_depth 0x%x\n", ratio,qm_func->sq[sq_id].cqn, real_depth);

	if (!qm_func->sq_select[sq_config->type][sq_config->burst_cnt_shift].num)
		qm_func->sq_select[sq_config->type][sq_config->burst_cnt_shift].start_id = sq_id;

	if (sq_id - qm_func->sq_select[sq_config->type][sq_config->burst_cnt_shift].start_id !=
	    qm_func->sq_select[sq_config->type][sq_config->burst_cnt_shift].num) {
		tloge("error! sq_id of the same type and burst is not continuous\n");
		return -1;
	}
	qm_func->sq_select[sq_config->type][sq_config->burst_cnt_shift].num++;
	qm_func->sq_select[sq_config->type][sq_config->burst_cnt_shift].cur_id = -1;
	ret = qm_sqc_set(qm_func, sq_id);
	if (ret != 0) {
		tloge("fail to set sqc\n");
		return ret;
	}
	qm_func->sq[sq_id].depth = real_depth;
	if (qm_func->ops->set_tag_field) {
		for (i = 0; i < real_depth; i++)
			qm_func->ops->set_tag_field(qm_func->sq[sq_id].virt_addr + i * qm_func->sqe_size, BD_TAG_FREE_FLAG);
	}
	qm_func->sq[sq_id].valid = true;

	return 0;
}

int qm_sqc_bt_set(struct qm_function *qm_func)
{
	int ret;
	uint64_t sqc_bt_rd;

	ret = qm_send_mb(MB_SQC_BT, qm_func->sqc_dma_addr, 0, QM_MAILBOX_OP_WR, qm_func->base);
	if (ret != 0) {
		tloge("fail to set sqc_bt\n");
		return ret;
	}

	sqc_bt_rd = 0;
	ret = qm_send_mb(MB_SQC_BT, (uint64_t)&sqc_bt_rd, 0, QM_MAILBOX_OP_RD, qm_func->base);
	if (ret != 0) {
		tloge("fail to read sqc_bt\n");
		return ret;
	}
	/* make sure data has reached to DDR */
	if (sqc_bt_rd != qm_func->sqc_dma_addr) {
		tloge("error! invalid sqc_bt setting, sqc_bt_rd = 0x%llx\n", sqc_bt_rd);
		// TODO.
		return -1;
	}

	return 0;
}

int32_t qm_init_sq(struct qm_function *qm_func,
		      struct qm_sq_config *sq_config, uint32_t config_num)
{
	int ret;
	uint32_t i, j;
	uint16_t config_sq_id;
    uint64_t tmp_dma_addr = 0;
	struct qm_sq_config *config_ptr;

	/* Initialize SQC and SQC_BT */
	uint64_t size = (uint64_t)qm_func->sq_num * sizeof(*qm_func->sqc);
    tmp_dma_addr = (uintptr_t)kzalloc_align(size, 0x20);
    tmp_dma_addr = (uint64_t)virt_mem_to_phys((uintptr_t)tmp_dma_addr);
	qm_func->sqc_dma_addr = tmp_dma_addr;

	ret = qm_sqc_bt_set(qm_func);
	if (ret != 0)
		return ret;

	/* Initialize SQ */
	qm_func->sq =(struct qm_sq *)malloc(qm_func->sq_num * sizeof(*qm_func->sq));
	if (!qm_func->sq)
		return -1;

	config_sq_id = 0;

	// tmp
	tloge("config_num 0x%x\n", config_num);
	for (i = 0; i < config_num; i++) {
		config_ptr = sq_config + i;
		if (config_sq_id + config_ptr->sq_num > qm_func->sq_num) {
			tloge("error! config sq num is out of range\n");
			return -1;
		}
		for (j = 0; j < config_ptr->sq_num; j++) {
			ret = qm_sq_info_set(qm_func, config_ptr, config_sq_id);
			if (ret != 0)
				return ret;
			config_sq_id++;
		}
	}

	return 0;
}

static int qm_cqc_set(struct qm_function *qm_func, uint16_t cq_id)
{
	int ret;
	struct qm_xqc *cqc;
	uint64_t orig_cqc;
	struct qm_xqc *cqc_rd;
	uint64_t orig_cqc_rd;
	unsigned long long  cqc_dma_addr = 0;
	unsigned long long  cqc_rd_dma_addr = 0;

	cqc = qm_get_a_xqc(qm_func, (uint64_t *)&cqc_dma_addr, &orig_cqc);
	if (!cqc) {
        tloge("malloc failed\n");
		return -1;
    }

	cqc->data[1] = qm_func->cq[cq_id].dma_addr & GENMASK(31, 0);
	cqc->data[2] = qm_func->cq[cq_id].dma_addr >> 32;
	cqc->data[3] = ((4 << QM_CQC_CQE_SIZE_SHIFT) &
		QM_CQC_CQE_SIZE_MASK);
	cqc->data[3] |= qm_func->cq[cq_id].depth & QM_CQC_QES_MASK;
	cqc->data[4] = qm_func->cq[cq_id].rand_data;
	cqc->data[6] = 0x1;
	cqc->data[6] |= (0x1 << QM_CQC_C_FLAG_SHIFT);

	ret = qm_send_mb(MB_CQC, cqc_dma_addr, cq_id,
		QM_MAILBOX_OP_WR, qm_func->base);
	if (ret != 0) {
		tloge("fail to send mailbox to set CQC\n");
		goto exit;
	}

	cqc_rd = qm_get_a_xqc(qm_func, (uint64_t *)&cqc_rd_dma_addr, (uint64_t *)&orig_cqc_rd);
	if (cqc_rd == NULL) {
        tloge("malloc failed\n");
		ret = -1;
		goto exit;
	}

	ret = qm_send_mb(MB_CQC, cqc_rd_dma_addr, cq_id,
		QM_MAILBOX_OP_RD, qm_func->base);
	if (ret != 0) {
		tloge("fail to send mailbox to read CQC\n");
		goto exit1;
	}
	/* make sure data has reached to DDR */
	ret = memcmp(cqc_rd, cqc, QM_XQC_SIZE);
	if (ret != 0) {
		int i;
		tloge("write cqc\n", ret);
		for (i = 0; i < 8; i++) {
			tloge(" 0x%x ", cqc->data[i]);
		}
		tloge("\nread cqc\n", ret);
		for (i = 0; i < 8; i++) {
			tloge(" 0x%x ", cqc_rd->data[i]);
		}
		tloge("error! invalid CQC setting 0x%x\n", ret);
		ret = -1;
	}
exit1:
	qm_free_a_xqc(qm_func, orig_cqc_rd, cqc_rd_dma_addr);
exit:
	qm_free_a_xqc(qm_func, orig_cqc, cqc_dma_addr);
	return ret;
}

static int qm_cq_info_set(struct qm_function *qm_func, uint16_t cq_depth, uint16_t cq_id)
{
	uint16_t real_depth;
	int32_t i;
	int32_t ret;
	uint32_t sqe_sum;

	qm_func->cq[cq_id].depth = cq_depth;
	real_depth = (0 == cq_depth) ? 2 : (cq_depth + 1);
	sqe_sum = 0;

	for (i = 0; i < qm_func->sq_num; i++) {
		if (cq_id == qm_func->sq[i].cqn)
			sqe_sum += qm_func->sq[i].depth;
	}

	if (sqe_sum > real_depth)
		tloge("warning! sqe_sum = %u is bigger than cq_depth = %d, "
			"it may generate risk of cq overflow\n",
			sqe_sum, real_depth);

	uint64_t size = (uint64_t)real_depth * sizeof(*qm_func->cq[cq_id].virt_addr);
	qm_func->cq[cq_id].virt_addr = (struct qm_cqe *)kzalloc_align(size, 0x20);
	qm_func->cq[cq_id].dma_addr = (uint64_t)virt_mem_to_phys((uintptr_t)qm_func->cq[cq_id].virt_addr);
	qm_func->cq[cq_id].handled_sqe_addr = (void *)malloc(
		sizeof(*qm_func->cq[cq_id].handled_sqe_addr) * real_depth);

	if (!qm_func->cq[cq_id].handled_sqe_addr)
		return -1;

	qm_func->cq[cq_id].phase = QM_CQE_P_MASK;
	qm_func->cq[cq_id].rand_data = 0x5a;

	ret = qm_cqc_set(qm_func, cq_id);
	if (ret != 0) {
		tloge("fail to set cqc\n");
		return ret;
	}
	qm_func->cq[cq_id].depth = real_depth;

	return 0;
}

int qm_cqc_bt_set(struct qm_function *qm_func)
{
	int ret;
	uint64_t cqc_bt_rd;

	ret = qm_send_mb(MB_CQC_BT, qm_func->cqc_dma_addr, 0,
		QM_MAILBOX_OP_WR, qm_func->base);
	if (ret != 0) {
		tloge("fail to set cqc_bt\n");
		return ret;
	}

	cqc_bt_rd = 0;
	ret = qm_send_mb(MB_CQC_BT, (uint64_t)&cqc_bt_rd, 0,
		QM_MAILBOX_OP_RD, qm_func->base);
	if (ret != 0) {
		tloge("fail to read cqc_bt\n");
		return ret;
	}
	/* make sure data has reached to DDR */
	if (cqc_bt_rd != qm_func->cqc_dma_addr) {
		tloge("error! invalid cqc_bt setting, cqc_bt_rd = 0x%llx\n", cqc_bt_rd);
		return -1;
	}

	return 0;
}

int qm_pre_init_cq(struct qm_function *qm_func)
{
	int32_t ret;
    uint64_t tmp_dma_addr;

	/* Initialize CQC and CQC_BT */
	uint64_t size = (uint64_t)qm_func->cq_num * sizeof(*qm_func->cqc);
    tmp_dma_addr = (uintptr_t)kzalloc_align(size, 0x20);
	qm_func->cqc_dma_addr = virt_mem_to_phys((uintptr_t)tmp_dma_addr);
    tlogi("cqc virt_addr is 0x%llx, dma_addr is 0x%llx\n", tmp_dma_addr, qm_func->cqc_dma_addr);

	ret = qm_cqc_bt_set(qm_func);
	if (ret != 0)
		return ret;


	/* Initialize CQ */
	qm_func->cq = (struct qm_cq *)malloc(qm_func->cq_num * sizeof(*qm_func->cq));
	if (!qm_func->cq)
		return -1;

	return 0;
}

int32_t qm_init_cq(struct qm_function *qm_func, uint16_t cq_depth)
{
	int32_t i;
	int32_t ret;

	ret = qm_pre_init_cq(qm_func);
	if (ret != 0)
		return ret;
	for (i = 0; i < qm_func->cq_num; i++) {
		ret = qm_cq_info_set(qm_func, cq_depth, i);
		if (ret)
			return ret;
	}

	return 0;
}

int qm_eqc_set(struct qm_function *qm_func)
{
	int32_t ret;
	struct qm_xqc *eqc;
	uint64_t orig_eqc;
	struct qm_xqc *eqc_rd;
	uint64_t orig_eqc_rd;
	uint64_t eqc_dma_addr = 0;
	uint64_t eqc_rd_dma_addr = 0;

	eqc = qm_get_a_xqc(qm_func, &eqc_dma_addr, &orig_eqc);
	if (!eqc)
		return -1;

	eqc->data[1] = qm_func->eq.dma_addr & GENMASK(31, 0);
	eqc->data[2] = qm_func->eq.dma_addr >> 32;
	eqc->data[6] = (0x1 << QM_EQC_PHASE_SHIFT);
	eqc->data[6] |= qm_func->eq.depth;
	ret = qm_send_mb(MB_EQC, eqc_dma_addr, 0, QM_MAILBOX_OP_WR, qm_func->base);
	if (ret) {
		tloge("fail to send mailbox to set EQC\n");
		goto exit;
	}

	eqc_rd = qm_get_a_xqc(qm_func, &eqc_rd_dma_addr, &orig_eqc_rd);
	if (eqc_rd == NULL) {
		ret = -1;
		goto exit;
	}

	ret = qm_send_mb(MB_EQC, eqc_rd_dma_addr, 0, QM_MAILBOX_OP_RD, qm_func->base);
	if (ret) {
		tloge("fail to send mailbox to read EQC\n");
		goto exit1;
	}
	/* make sure data has reached to DDR */
	ret = memcmp(eqc_rd, eqc, QM_XQC_SIZE);
	if (ret != 0) {
		int i;
		tloge("write eqc 0x%x\n", ret);
		for (i = 0; i < 8; i++) {
			tloge(" 0x%x ", eqc->data[i]);
		}
		tloge("\nread eqc 0x%x\n", ret);
		for (i = 0; i < 8; i++) {
			tloge(" 0x%x ", eqc_rd->data[i]);
		}
		tloge("error! invalid EQC setting 0x%x\n", ret);
		ret = -1;
	}
exit1:
	qm_free_a_xqc(qm_func, orig_eqc_rd, eqc_rd_dma_addr);
exit:
	qm_free_a_xqc(qm_func, orig_eqc, eqc_dma_addr);
	return ret;
}

int32_t qm_init_eq(struct qm_function *qm_func)
{
	int32_t ret;
	uint16_t real_depth;

	real_depth = (0 == qm_func->eq.depth) ? 2 : (qm_func->eq.depth + 1);
	if (qm_func->cq_num > (real_depth / 2))
		tloge("warning! cq_num is bigger than half of eq_depth, "
			"it may generate risk of eq overflow\n");
	uint64_t size = (uint64_t)real_depth * sizeof(*qm_func->eq.virt_addr);
	qm_func->eq.virt_addr = (struct qm_eqe *)kzalloc_align(size, 0x20);
	qm_func->eq.dma_addr = (uint64_t)virt_mem_to_phys((uintptr_t)qm_func->eq.virt_addr);

	qm_func->eq.phase = QM_EQE_P_MASK;
	ret = qm_eqc_set(qm_func);
	if (ret != 0)
		return ret;
	qm_func->eq.depth = real_depth;

	return 0;
}

int32_t qm_modify_vft_start_sqn(struct qm_function *pf_info, uint16_t start_sqn,
	uint16_t change_num, uint8_t inscrease_flag)
{
	uint16_t sqn;
	int i;
	int ret;
	uint64_t sqc_vft_entry;

	for (i = 0; i < QM_MAX_FUNCTION_NUM; i++) {
		ret = qm_read_vft(pf_info->qm_pf_cfg_base, QM_SQC_VFT, i,
			&sqc_vft_entry);
		if (ret) {
			tloge("qm sqc vft busy!\n");
			return ret;
		}
		sqn = (sqc_vft_entry & QM_SQC_VFT_START_SQN_MASK)
			>> QM_SQC_VFT_START_SQN_SHIFT;
		if (sqn > start_sqn) {
			sqc_vft_entry &= ~QM_SQC_VFT_START_SQN_MASK;
			if (inscrease_flag)
				sqc_vft_entry |= (((uint64_t)(sqn + change_num)
					<< QM_SQC_VFT_START_SQN_SHIFT) &
					QM_SQC_VFT_START_SQN_MASK);
			else
				sqc_vft_entry |= (((uint64_t)(sqn - change_num)
					<< QM_SQC_VFT_START_SQN_SHIFT) &
					QM_SQC_VFT_START_SQN_MASK);
			ret = qm_write_vft(pf_info->qm_pf_cfg_base, QM_SQC_VFT, i,
				sqc_vft_entry);
			if (ret) {
				tloge("qm sqc vft busy!\n");
				return ret;
			}
		}
	}

	return 0;
}

int qm_verify_vf_config(const struct qm_queue_config *queue_config)
{
	uint32_t i;
	uint16_t total_num;

	if (!queue_config->sq_config_num || !queue_config->cq_config_num)
		return -1;

	total_num = 0;
	for (i = 0; i < queue_config->sq_config_num; i++) {
		if (!queue_config->sq_config[i].sq_num ||
			queue_config->sq_config[i].depth >= QM_MAX_QUEUE_DEPTH ||
			queue_config->sq_config[i].burst_cnt_shift >= QM_MAX_BURST_CNT_SHIFT ||
			queue_config->sq_config[i].order > 1)
			return -1;
		total_num += queue_config->sq_config[i].sq_num;
	}
	if (total_num > QM_MAX_QP_NUM)
		return -1;
	total_num = 0;
	for (i = 0; i < queue_config->cq_config_num; i++) {
		if (!queue_config->cq_config[i].cq_num ||
			queue_config->cq_config[i].depth >= QM_MAX_QUEUE_DEPTH)
			return -1;
		total_num += queue_config->cq_config[i].cq_num;
	}
	if (total_num > QM_MAX_QP_NUM)
		return -1;

	return 0;
}

int qm_write_back_cache(struct qm_function *qm_func)
{
	int ret;
	uint32_t reg = 0;

	writeq(0x1, (uintptr_t)qm_func->base + QM_CACHE_WB_START_REG);

	/* barrier for execution sequence */

	ret = (readl_relaxed_poll_timeout((uintptr_t)qm_func->base +
		QM_CACHE_WB_DONE_REG, reg,
		reg & 0x1, ACC_DELAY_10_US,
		ACC_POLL_TIMEOUT_MS));
	if (ret) {
		tloge("error! write back qm cache time out\n");
		return ret;
	}

	return 0;
}
