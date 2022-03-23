/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdlib.h>
#include <securec.h>
#include "acc_common.h"
#include "acc_common_qm.h"
#include "tee_log.h"
#include "register_ops.h"
#include "acc_common_sess.h"

uint32_t malloc_cnt = 0;
void * old_addr;
void * new_addr;
uint32_t *kzalloc(size_t size)
{
	void *ret = malloc(size);
	memset_s(ret, size, 0 ,size);
	return ret;
}

uint32_t *kzalloc_align(size_t size, size_t align)
{
    void *ret = malloc_coherent((size + align));
	memset_s(ret, (size + align), 0 ,(size + align));

	uint64_t off = ((uint64_t)ret) % ((uint64_t)align);
	ret = ret + align - off;

	return ret;
}

/**
 * qm_pf_config_vft - use PF to configure the VFT of a VF
 * @pf_info: information of physical function
 * @vft_id: function ID
 * @vft_sqc: configuration parameters of SQC_VFT
 * @vft_cqc: configuration parameters of CQC_VFT
 * Returns 0 for success and negative value for failure
 */
int qm_pf_config_vft(struct qm_function *pf_info, uint32_t vft_id,
		   const struct sqc_vft_config *vft_sqc,
		   const struct cqc_vft_config *vft_cqc)
{
	int ret;
	uint64_t sqc_vft_entry;
	uint64_t cqc_vft_entry;
	uint64_t vft_entry_rd;

	/* sqc_vft initial */
	sqc_vft_entry = vft_sqc->sq_num - 1;
	// tmp
	sqc_vft_entry = ((sqc_vft_entry << QM_SQC_VFT_SQ_NUM_SHIFT) &
		QM_SQC_VFT_SQ_NUM_MASK);
	sqc_vft_entry |=
	    (((uint64_t) vft_sqc->valid & 0x1) << QM_SQC_VFT_VALID_SHIFT);
	sqc_vft_entry |=
	    ((uint64_t) pf_info->cur_start_sqn << QM_SQC_VFT_START_SQN_SHIFT);
	ret = qm_write_vft(pf_info->qm_pf_cfg_base, QM_SQC_VFT, vft_id,
		sqc_vft_entry);
	if (ret) {
		tloge("qm sqc vft busy!\n");
		return ret;
	}
	tlogi("sqc vft init\n");

	/* verify the validity of sqc_vft */
	vft_entry_rd = 0;
	ret = qm_read_vft(pf_info->qm_pf_cfg_base, QM_SQC_VFT, vft_id,
		&vft_entry_rd);
	if (ret) {
		tloge("qm sqc vft busy!\n");
		return ret;
	}
	if (vft_entry_rd != sqc_vft_entry) {
		tloge("error! invalid sqc_vft setting!\n");
		return -1;
	}
	tloge("verify sqc vft init\n");

	/* cqc_vft initial */
	cqc_vft_entry = 0;
	cqc_vft_entry |=
	    (((uint64_t) vft_cqc->valid & 0x1) << QM_CQC_VFT_VALID_SHIFT);

	ret = qm_write_vft(pf_info->qm_pf_cfg_base, QM_CQC_VFT, vft_id,
		cqc_vft_entry);
	if (ret) {
		tloge("qm cqc vft busy!\n");
		return ret;
	}
	tloge("cqc vft init\n");

	/* verify the validity of cqc_vft */
	vft_entry_rd = 0;
	ret = qm_read_vft(pf_info->qm_pf_cfg_base, QM_CQC_VFT, vft_id,
		&vft_entry_rd);
	if (ret) {
		tloge("qm cqc vft busy!\n");
		return ret;
	}
	if (vft_entry_rd != cqc_vft_entry) {
		tloge("error! invalid cqc_vft setting!\n");
		return -1;
	}
	tlogi("verify cqc vft init\n");

	pf_info->cur_start_sqn += vft_sqc->sq_num;

	return 0;
}

/**
 * qm_pf_init - initialize the physical function
 * @pf_info: information of physical function
 * @cfg_addr: the input configuration address
 * Returns 0 for success and negative value for failure
 */
int32_t qm_pf_init(struct qm_function *qm, void  *cfg_addr)
{
	int32_t ret;

	qm->qm_pf_cfg_base = cfg_addr;
	qm->cur_start_sqn = 0;
	/* user domain */
	writeq(QM_RWUSER_CFG_EN_MASK, (uintptr_t)qm->qm_pf_cfg_base + QM_ARUSER_M_CFG_EN);
	writeq(QM_RWUSER_CFG_EN_MASK, (uintptr_t)qm->qm_pf_cfg_base + QM_AWUSER_M_CFG_EN);
	writeq(QM_WUSER_CFG_EN_MASK, (uintptr_t)qm->qm_pf_cfg_base + QM_WUSER_M_CFG_EN);

	/* memory init */
	writel(QM_MEM_START_INIT_MASK, (uintptr_t)qm->qm_pf_cfg_base + QM_MEM_START_INIT_REG);
	SRE_SwMsleep(ACC_POLL_TIMEOUT_MS);
	ret = readl((uintptr_t)qm->qm_pf_cfg_base + QM_MEM_INIT_DONE_REG);
	if (ret != 1) {
		tloge("pf fail to init QM memory\n");
		return -1;
	}

	return 0;
}

/**
 * qm_axuser_m_cfg - set config of aruser and awuser
 * @pf_info: pointer to a physical function
 * @smmu_normal: 1 for smmu normal and 0 for smmu bypass
 */
static void qm_axuser_m_cfg(struct qm_function *pf_info)
{
	writel(0x40000070, (uintptr_t)pf_info->qm_pf_cfg_base + QM_ARUSER_M_CFG_1);
	writel(0x40000070, (uintptr_t)pf_info->qm_pf_cfg_base + QM_AWUSER_M_CFG_1);
}

/**
 * qm_peh_axuser_cfg - set config of peh axuser
 * @pf_info: pointer to a physical function
 * @smmu_normal: 1 for smmu normal and 0 for smmu bypass
 */

/**
 * qm_set_smmu - set smmu to be normal or bypassed
 * @pf_info: pointer to a physical function
 * @smmu_normal: 1 for smmu normal and 0 for smmu bypass
 */
void qm_set_smmu(struct qm_function *pf_info, uint32_t smmu_normal)
{
	if (smmu_normal) {
		tloge("Currently, the SMMU is not supported.\n");
		return;
	}

	if (pf_info->qm_pf_cfg_base == NULL) {
		tloge("error! pf cfg base addr is null\n");
		return;
	}
	qm_axuser_m_cfg(pf_info);
}

/**
 * qm_function_set_dev - set the device for a function
 * @pdev: pointer to a pci device
 * @base_addr: the input base address
 */
void qm_function_set_dev(struct qm_function *qm_func, void *base_addr)
{
	qm_func->base = base_addr;
}

/**
 * qm_get_sqc_vft - get sqc_vft configured by PF
 * @qm_func: pointer to a function
 * Returns 0 for success and negative value for failure
 */
static int32_t qm_get_sqc_vft(struct qm_function *qm_func)
{
	int32_t ret;
	uint64_t sqc_vft = 0;

	ret = qm_send_mb(MB_SQC_VFT, (uint64_t)&sqc_vft, 0, QM_MAILBOX_OP_RD, qm_func->base);
	if (ret) {
		tloge("fail to read sqc vft\n");
		return ret;
	}

	if (!((sqc_vft >> QM_SQC_VFT_VALID_SHIFT) & 0x1)) {
		tloge("error! vf is not valid\n");
		return -1;
	}
	qm_func->sq_num = ((sqc_vft & QM_SQC_VFT_SQ_NUM_MASK) >> QM_SQC_VFT_SQ_NUM_SHIFT) + 1;

	return 0;
}

/**
 * qm_function_init - initialize the configuration for a function
 * @qm_func: pointer to a function
 * @vf_config: the intput configuration parameters
 * @ops: the input operation functions
 * Returns 0 for success and negative value for failure
 */
int32_t qm_function_init(struct qm_function *qm_func,
		     struct qm_vf_config *vf_config, struct qm_func_ops *ops)
{
	int32_t ret;

	if (qm_func->base == NULL) {
		tloge("error! fuction base addr is null\n");
		return -1;
	}
	tlogi("start qm func init\n");

	ret = qm_get_sqc_vft(qm_func);
	if (ret) {
		tloge("get sqc failed\n");
		return ret;
	}
	tlogi("qm func get sqc\n");

	// tmp
	qm_func->cq_num = (vf_config->cq_num > qm_func->sq_num) ?
	    qm_func->sq_num : vf_config->cq_num;
	qm_func->sqe_size = vf_config->sqe_size;
	qm_func->ops = ops;

	ret = qm_init_sq(qm_func, vf_config->sq_config,
			 vf_config->sq_config_num);
	if (ret) {
		tloge("fail to init sq\n");
		return ret;
	}
	tlogi("qm func init sq\n");

	ret = qm_init_cq(qm_func, vf_config->cq_depth);
	if (ret) {
		tloge("fail to init cq\n");
		return ret;
	}
	tlogi("qm func init cq\n");

	qm_func->eq.depth = vf_config->eq_depth;
	ret = qm_init_eq(qm_func);
	if (ret) {
		tloge("fail to init eq\n");
		return ret;
	}
	tlogi("qm func init eq\n");

	qm_func->priv_data_size = vf_config->priv_data_size;
	ret = acc_common_init_session(qm_func, vf_config->session_num);
	if (ret) {
		tloge("fail to init session\n");
		return ret;
	}
	qm_func->enable_flow_stats = false;

	return 0;
}

/**
 * qm_bd_enqueue - make one bd enqueue
 * @qm_func: pointer to a function
 * @req: pointer to an enqueue request
 * Returns 0 for success and negative value for failure
 */
void sec_print_bd1(struct sec_bd *bd)
{
    uint32_t i;

    tloge("sec bd:\n");
    for (i = 0; i < (SEC_BD_SIZE / sizeof(uint32_t)); i++)
        tloge("Word[%d]: 0x%x\n", i, bd->data[i]);
}

int32_t qm_bd_enqueue(struct qm_function *qm_func, struct qm_enqueue_req *req)
{
	uint32_t sq_id;

	qm_func->sq_select[req->sq_type][req->sq_burst].cur_id++;
	sq_id = ((qm_func->sq_select[req->sq_type][req->sq_burst].cur_id) %
		qm_func->sq_select[req->sq_type][req->sq_burst].num) +
	    qm_func->sq_select[req->sq_type][req->sq_burst].start_id;

	memcpy_s((void *)(qm_func->sq[sq_id].virt_addr + qm_func->sq[sq_id].tail * qm_func->sqe_size), qm_func->sqe_size, req->bd, qm_func->sqe_size);
	qm_func->sq[sq_id].last_tail = qm_func->sq[sq_id].tail;
	qm_func->sq[sq_id].tail = (qm_func->sq[sq_id].tail + 1) % qm_func->sq[sq_id].depth;

	/* make sure writing operation has completed */
	do_sq_cq_db(db_set(sq_id, DB_SQ, qm_func->sq[sq_id].tail,
		req->sq_burst, qm_func->sq[sq_id].rand_data),
		qm_func->base);

	return 0;
}
