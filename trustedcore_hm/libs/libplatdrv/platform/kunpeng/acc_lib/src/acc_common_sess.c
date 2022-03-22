/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "acc_common.h"
#include <stddef.h>
#include "tee_log.h"

uint32_t session_id = 0;

int acc_common_init_session(struct qm_function *qm_func, uint16_t session_num)
{
	int32_t i;

	qm_func->session_table = malloc(sizeof(*qm_func->session_table) * session_num);
	if (qm_func->session_table == NULL) {
		tloge("fail to alloc memory for session table\n");
		return -1;
	}

	for (i = 0; i < session_num; i++) {
		qm_func->session_table[i].session_id = i;
		qm_func->session_table[i].in_qm = false;
	}
	qm_func->session_num = session_num;

	return 0;
}

/**
 * acc_common_get_session - get a session
 * @qm_func: pointer to a function
 * @out_sess_data: point to the output session data
 * Returns 0 for success and negative value for failure
 */
int acc_common_get_session(struct qm_function *qm_func, void **out_sess_data,
			   uint16_t *out_sess_id)
{
	qm_func->session_table[session_id].in_use = 1;
	*out_sess_data = qm_func->session_table[session_id].priv_data;
	*out_sess_id = session_id;
	session_id++;

	return 0;
}

/**
 * acc_common_get_session - release a session
 * @qm_func: pointer to a function
 * @session_id: session ID
 * Returns 0 for success and negative value for failure
 */
int acc_common_put_session(struct qm_function *qm_func, uint16_t in_session_id)
{
	qm_func->session_table[in_session_id].in_use = 0;
	session_id--;

	return 0;
}

void acc_common_destroy_session(struct qm_function *qm_func)
{
	qm_func->session_num = 0;
}
