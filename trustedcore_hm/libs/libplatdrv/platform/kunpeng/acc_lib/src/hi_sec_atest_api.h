/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __HI_SEC_ATEST_API_H__
#define __HI_SEC_ATEST_API_H__

#include "hi_sec_dlv.h"

int32_t sec_send_bd(void *bd, uint8_t priority, uint8_t type);
int32_t sec_send_multi_sqe(struct hisi_sec_sqe *bd, uint16_t sqe_num, uint8_t priority,
	uint8_t type, SEC_CALLBACK *cb_func_array, void **arg_array);
int32_t sec_get_available_type_sq(uint8_t type, uint8_t *burst);

#endif
