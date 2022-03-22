/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __ACC_COMMON_SESS_H__
#define __ACC_COMMON_SESS_H__

int acc_common_init_session(struct qm_function *qm_func, uint16_t session_num);
void acc_common_destroy_session(struct qm_function *qm_func);

#endif
