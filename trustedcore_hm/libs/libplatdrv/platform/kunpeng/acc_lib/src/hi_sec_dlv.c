/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "hi_sec_dlv.h"
#include <stdio.h>
#include <tee_log.h>

extern struct acc_device *g_sec_dev;

uint16_t sec_get_tag_field(void *sqe)
{
	uint8_t endian;
	uint16_t tag;
	struct hisi_sec_sqe *bd = sqe;
	struct acc_device *sec_dev;

    sec_dev = g_sec_dev;
	if (!sec_dev)
		return (uint16_t)(-1);

	endian = (uint8_t)sec_dev->endian;
	tag = (uint16_t)(bd->type2.tag);

	return tag;
}

void sec_set_tag_field(void *sqe, uint16_t tag_value)
{
	struct hisi_sec_sqe *bd = sqe;
	struct acc_device *sec_dev;

	sec_dev = g_sec_dev;
	if (!sec_dev)
		return;
	bd->type2.tag = (uint32_t)tag_value;
}

static void sec_check_error(struct qm_function *func, struct hisi_sec_sqe *bd, uint8_t *out_err_print)
{
	uint8_t error_type;
	uint8_t warning_type;

	if (func) {
		// TODO
	}
	error_type = bd->type2.error_type;
	if (error_type) {
		tloge("bd error: error_type = 0x%x\n", error_type);
		*out_err_print = 1;
	}

	warning_type = bd->type2.warning_type;
	if (warning_type) {
		tloge("bd warning: warning_type = 0x%x\n", warning_type);
		*out_err_print = 1;
	}
}

static void sec_inc_err_bd_stats(struct acc_device *sec_dev, uint8_t type)
{
	if (SEC_BD_TYPE1 == type)
		/*atomic_inc(&sec_dev->stats_ctrl.err_bd1_num);*/
		sec_dev->stats_ctrl.err_bd1_num++;
	else if (SEC_BD_TYPE2 == type)
		/*atomic_inc(&sec_dev->stats_ctrl.err_bd2_num);*/
		sec_dev->stats_ctrl.err_bd2_num++;
}

static void sec_check_write_back(struct qm_function *func, struct hisi_sec_sqe *bd)
{
	uint8_t done;
	uint8_t icv;
	uint8_t type;
	uint8_t error_print = 0;
	struct acc_device *sec_dev;

	done = bd->type2.done & 0x1;
	if (!done) {
		tloge("error! no done flag write back\n");
		error_print = 1;
	}

	icv = bd->type2.icv;
	if (BD_ICV_CHECK_FAIL == icv) {
		tloge("icv: check fail\n");
		error_print = 1;
	} else if (BD_ICV_ERROR == icv) {
		tloge("icv: bd or bus error\n");
		error_print = 1;
	}

	type = bd->type & BD_TYPE_MASK;
	if (SEC_BD_TYPE2 != type) {
		tloge("bd type should be type2.\n");
		error_print = 1;
	}

	sec_check_error(func, bd, &error_print);
	if (error_print) {
		sec_dev = g_sec_dev;
		sec_inc_err_bd_stats(sec_dev, type);
	}
}

int32_t sec_task_complete_proc(struct qm_function *func, void *sqe, void *priv_data)
{
	uint16_t sess_id;
	uint32_t err_code;
	void *cb_arg;
	SEC_CALLBACK cb_func;
	struct acc_device *sec_dev;
	struct sec_task_property *task_prop = priv_data;
	struct hisi_sec_sqe *le_bd_ptr;


	sec_dev = g_sec_dev;
	le_bd_ptr = sqe;

	sec_check_write_back(func, le_bd_ptr);
	sess_id = sec_get_tag_field(sqe);
	cb_func = task_prop->callback_func;
	cb_arg = task_prop->callback_para;

	if (cb_func) {
		if (SEC_CB_INPUT_RES == task_prop->cb_input_type) {
			err_code = 0;
			cb_func(cb_arg, &err_code);
		} else if (SEC_CB_INPUT_BD == task_prop->cb_input_type) {
			cb_func(cb_arg, le_bd_ptr);
		}
	}

	sec_set_tag_field(sqe, BD_TAG_FREE_FLAG);
	return acc_common_put_session(func, sess_id);
}

int32_t sec_task_fault_proc(struct qm_function *func, void *priv_data, uint16_t sess_id)
{
	uint32_t err_code;
	SEC_CALLBACK cb_func;
	struct sec_task_property *task_prop = priv_data;

	cb_func = task_prop->callback_func;
	if (task_prop->callback_func) {
		if (SEC_CB_INPUT_RES == task_prop->cb_input_type) {
			/* return time-out here */
			err_code = 1;
			cb_func(task_prop->callback_para, &err_code);
		} else if (SEC_CB_INPUT_BD == task_prop->cb_input_type) {
			cb_func(task_prop->callback_para, NULL);
		}
	}
	return acc_common_put_session(func, sess_id);
}