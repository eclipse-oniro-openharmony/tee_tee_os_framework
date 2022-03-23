/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: common data provided for drv.c, hal.c, reg.c and external
 * Author     : secengmeng
 * Create     : 2020/04/21
 */
#ifndef __COMMON_KM_H__
#define __COMMON_KM_H__
#include <common_define.h>

enum symm_ktype {
	SYMM_KEYTYPE_CEK = 0,
	SYMM_KEYTYPE_KDR,
	SYMM_KEYTYPE_GID,
	SYMM_KEYTYPE_RTL,
	SYMM_KEYTYPE_USER,
	SYMM_KEYTYPE_POS,
	SYMM_KEYTYPE_DERIVE,
	SYMM_KEYTYPE_RTL1,
	SYMM_KEYTYPE_CEK1,
	SYMM_KEYTYPE_TAKEY,

	SYMM_KEYTYPE_MAX,

	SYMM_KEYTYPE_BYPASS = 0x7FFFFFFF,
};

#endif /* end of __COMMON_KM_H__ */
