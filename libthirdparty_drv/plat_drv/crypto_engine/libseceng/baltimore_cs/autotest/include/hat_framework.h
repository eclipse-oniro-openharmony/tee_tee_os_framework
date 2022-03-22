/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: hava autotest framework
 * Author     : m00475438
 * Create     : 2019/08/09
 */
#ifndef __HAT_FRAMEWORK_H__
#define __HAT_FRAMEWORK_H__
#include <common_define.h>

typedef void *(*hat_func_t)();

enum hat_type_enum {
	HAT_TYPE_NONE     = 0,
	HAT_TYPE_PC2HISEE = 1,
	HAT_TYPE_HISEE2PC = 2,

	HAT_TYPE_FUNC_ADDR = 3,

	HAT_TYPE_RET_U32 = 4,
	HAT_TYPE_RET_BUF = 5,
	HAT_TYPE_RET_VOID = 6,

	HAT_TYPE_IN_U32 = 7,
	HAT_TYPE_IO_U32 = 8,
	HAT_TYPE_OUT_U32 = 9,

	HAT_TYPE_IN_BUF = 10,
	HAT_TYPE_IO_BUF = 11,
	HAT_TYPE_OUT_BUF = 12,
	HAT_TYPE_NULL_BUF = 13,

	HAT_TYPE_IN_STRU_PTR = 14,
	HAT_TYPE_IO_STRU_PTR = 15,
	HAT_TYPE_IN_POINTER = 16,
	HAT_TYPE_IO_POINTER = 17,
	HAT_TYPE_OUT_POINTER = 18,

	HAT_TYPE_TMP_BUFFER = 19,   /* template buffer for function */

	HAT_TYPE_VALUE_MAX  = 0xFF
};

struct hat_type {
	u8  type;
	u8  offset;  /* address offset */
	u16 opts;
};

hat_func_t hat_get_func_addr(const char *name, u32 len);
err_bsp_t hat_autotest(u8 *pdata, u32 *psize, u32 *pcost_time);
#endif /* __HAT_FRAMEWORK_H__ */
