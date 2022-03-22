/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "acc_common.h"
#include "acc_common_qm.h"
#include <tee_log.h>

#define QM_EQ_MSI_INT_INDEX	0
#define QM_AEQ_MSI_INT_INDEX	1
#define QM_FLR_MSI_INT_INDEX	2
#define QM_PF_MSI_INT_INDEX	3


#ifdef CONFIG_EQ_POLL_MODE
int qm_task_proc_thread_start(struct qm_function *qm_func);
#else
#endif

static int32_t qm_cqe_handle(struct qm_function *qm_func, struct qm_cqe *cqe,
	void **out_sqe)
{
	uint16_t tag;
	uint16_t sq_identifier;
	uint16_t sq_head_pointer;
	uint16_t cmd_id;
	void *sqe;

	sq_identifier = (cqe->data[2] >> QM_CQE_SQ_IDENTIFIER_SHIFT);
	if (sq_identifier >= qm_func->sq_num) {
		tloge("error! sq_identifier is out of range\n");
		goto fault_handle;
	}
	sq_head_pointer = cqe->data[2] & QM_CQE_SQ_HEAD_POINTER_MASK;
	if (sq_head_pointer >= qm_func->sq[sq_identifier].depth) {
		tloge("error! sq_head_pointer is out of range\n");
		goto fault_handle;
	}
	cmd_id = cqe->data[1] & QM_CQE_COMMAND_IDENTIFIER_MASK;
	sqe = (void *)(qm_func->sq[sq_identifier].virt_addr + sq_head_pointer * qm_func->sqe_size);
    if (qm_func->ops->get_tag_field) {
		tag = qm_func->ops->get_tag_field(sqe);
		if (tag != cmd_id) {
			tloge("error! cmd_id = %u is not equal to tag field = %u\n",
				cmd_id, tag);
			goto fault_handle;
		}
	}
	if (cmd_id >= qm_func->session_num) {
		tloge("error! cmd_id = %u is out of range\n", cmd_id);
		goto fault_handle;
	}

	*out_sqe = sqe;

	return 0;

fault_handle:
	tloge("qm need reset!!!\n");
	return -1;
}

static int32_t qm_cq_process(struct qm_function *qm_func, uint16_t cqn)
{
	int32_t i;
	int32_t ret;
	int32_t handle_cqe_num;
	struct qm_cqe *cqe;

	handle_cqe_num = 0;

	for (cqe = (struct qm_cqe *)qm_func->cq[cqn].virt_addr + qm_func->cq[cqn].head;
		 (cqe->data[3] & QM_CQE_P_MASK) == qm_func->cq[cqn].phase;
		 cqe = (struct qm_cqe *)qm_func->cq[cqn].virt_addr + qm_func->cq[cqn].head) {
		/* make sure read the updated phase domain */
		ret = qm_cqe_handle(qm_func, cqe, &qm_func->cq[cqn].handled_sqe_addr[handle_cqe_num]);
		if (ret != 0) {
			return ret;
        }

		qm_func->cq[cqn].head++;
		if (qm_func->cq[cqn].head == qm_func->cq[cqn].depth) {
			qm_func->cq[cqn].head = 0;
			qm_func->cq[cqn].phase = (~(qm_func->cq[cqn].phase)) & QM_CQE_P_MASK;
		}
		handle_cqe_num++;
		/* To avoid dispatching a CQ doorbell with an unchanged cq_head */
		if (handle_cqe_num >= qm_func->cq[cqn].depth - 1)
			break;
	}

	if (handle_cqe_num == 0)
		tloge("qm no cqe generate\n");

	do_sq_cq_db(db_set(cqn, DB_CQ, qm_func->cq[cqn].head, 1,
		qm_func->cq[cqn].rand_data),
		qm_func->base);
	/*
	  * Set all SQEs free after CQ doorbell dispatched in order to
	  * avoid CQ overflow
	  */
	if (qm_func->ops->set_tag_field)
		for (i = 0; i < handle_cqe_num; i++)
			qm_func->ops->set_tag_field(qm_func->cq[cqn].handled_sqe_addr[i],BD_TAG_FREE_FLAG);

	return 0;
}


int32_t qm_eq_process(struct qm_function *qm_func)
{
	uint16_t cqn;
	int32_t ret;
	int32_t half_eq_depth;
	int32_t handle_eqe_num;
	struct qm_eqe *eqe;

	handle_eqe_num = 0;
	half_eq_depth = qm_func->eq.depth / 2 - 1;

	for (eqe = (struct qm_eqe *)qm_func->eq.virt_addr + qm_func->eq.head;
		 (eqe->data[0] & QM_EQE_P_MASK) == qm_func->eq.phase;
		 eqe = (void *)qm_func->eq.virt_addr + qm_func->eq.head) {
		/* each eqe indicates bunch of CQEs for one single CQ */
		cqn = eqe->data[0] & QM_EQE_CQN_MASK;

		if (cqn >= qm_func->cq_num) {
			tloge("error! cqn is out of range, eqe = %u\n",
				eqe->data[0]);
			tloge("qm need reset!!!\n");
			return -1;
		}

		ret = qm_cq_process(qm_func, cqn);
		if (ret) {
			tloge("qm cq process fail 0x%x\n", ret); 
			return -1;
		}

		qm_func->eq.head++;
		if (qm_func->eq.head == qm_func->eq.depth) {
			qm_func->eq.head = 0;
			qm_func->eq.phase = (~(qm_func->eq.phase)) &
				QM_EQE_P_MASK;
		}
		handle_eqe_num++;
		if (handle_eqe_num >= half_eq_depth)
			break;
	}

	if (handle_eqe_num) {
		do_eq_aeq_db(db_set(0, DB_EQ, qm_func->eq.head, 0, 0), qm_func->base);
    }

	return 0;
}
