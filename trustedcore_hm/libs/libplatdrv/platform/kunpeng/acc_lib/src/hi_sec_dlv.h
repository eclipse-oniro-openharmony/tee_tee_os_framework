/*
 * Copyright (c) 2018-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __HI_SEC_DLV_H__
#define __HI_SEC_DLV_H__


#include <stdint.h>
#include <stdbool.h>
#include "acc_common.h"
#include "hisi_sec_udrv.h"
#define SEC_BD_SIZE	128

#define SEC_BD_TYPE1	0x1
#define SEC_BD_TYPE2	0x2
#define BITS_PER_LONG 64
#define GENMASK(h, l) \
     (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define BD_TAG_MASK GENMASK(15, 0)
#define BD_TYPE_MASK    GENMASK(3, 0)
#define BD_ERROR_TYPE_MASK  GENMASK(23, 16)
#define BD_ERROR_TYPE_SHIFT 16
#define BD_ICV_MASK GENMASK(3, 1)
#define BD_ICV_SHIFT    1
#define BD_ICV_CHECK_FAIL   0x2
#define BD_ICV_ERROR    0x3
#define BD_WARNING_TYPE_MASK    GENMASK(31, 24)
#define BD_WARNING_TYPE_SHIFT   24

#define BD_DC_MASK  GENMASK(13, 11)
#define BD_DC_SHIFT 11
#define BD_DC_FAIL  0x2

#define BD_CSC_MASK GENMASK(6, 4)
#define BD_CSC_SHIFT    4
#define BD_CSC_CHECK_FAIL   0x2
#define BD_CSC_CHECK_FAIL 0x2

#define BD_FLAG_MASK      GENMASK(10, 7)
#define BD_FLAG_SHIFT     7
#define BD_TAG_FREE_FLAG 0xA5A5

typedef void (*SEC_CALLBACK)(void *Arg, void *Result);

enum sec_cb_input_type {
	SEC_CB_INPUT_BD = 0,
	SEC_CB_INPUT_RES = 1
};

enum sec_endian {
	SEC_LE = 0,
	SEC_32BE,
	SEC_64BE
};

struct sec_task_property {
	void *callback_func;
	void *callback_para;
	enum sec_cb_input_type cb_input_type;
	bool enable_stats;
	long io_start_time;
	long chip_start_time;
};

struct sec_bd {
	uint32_t data[SEC_BD_SIZE / sizeof(uint32_t)];
};

uint16_t sec_get_tag_field(void *sqe);
void sec_set_tag_field(void *sqe, uint16_t tag_value);
int32_t sec_task_complete_proc(struct qm_function *func,
	void *sqe, void *priv_data);
int32_t sec_task_fault_proc(struct qm_function *func,
	void *priv_data, uint16_t sess_id);

#endif
