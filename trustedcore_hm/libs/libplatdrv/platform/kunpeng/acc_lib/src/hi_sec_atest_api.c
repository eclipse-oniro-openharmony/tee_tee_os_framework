/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include "hi_sec_atest_api.h"
#include <stdio.h>
#include <tee_log.h>

extern struct acc_device *g_sec_dev;
int32_t sec_send_bd(void *bd, uint8_t priority, uint8_t type)
{
	uint16_t sess_id;
	int32_t ret;
	struct acc_device *sec_dev;
	struct qm_enqueue_req req;
	struct sec_task_property *task_prop;

	sec_dev = g_sec_dev;
	if (sec_dev == NULL) {
		tloge("error! sec device is NULL\n");
		return -1;
	}

	ret = acc_common_get_session(&sec_dev->qm_func,
		(void *)&task_prop, &sess_id);
	if (ret)
		return ret;

	req.bd = bd;
	sec_set_tag_field(req.bd, sess_id);

	req.bd_num = 1;
	req.sq_burst = priority;
	req.sq_type = type;
	req.hook_func = NULL;
	req.hook_para = NULL;

	ret = qm_bd_enqueue(&sec_dev->qm_func, &req);
	if (ret != 0) {
        tloge("qm_bd_enqueue ret is 0x%x\n", ret);
		(void)acc_common_put_session(&sec_dev->qm_func, sess_id);
		return ret;
	}

	return 0;
}

int32_t sec_get_available_type_sq(uint8_t type, uint8_t *burst)
{
	uint32_t i;
	struct acc_device *sec_dev;

	sec_dev = g_sec_dev;
	for (i = 0; i < MAX_SQ_PRIORITY; i++) {
		if (sec_dev->qm_func.sq_select[(uint32_t)type][i].num) {
			*burst = i;
			return 0;
		}
	}
	return -1;
}
