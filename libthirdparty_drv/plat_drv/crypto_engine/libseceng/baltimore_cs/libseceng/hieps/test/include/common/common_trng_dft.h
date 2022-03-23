/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: trng test-related common data definitions
 * Author     : m00475438
 * Create     : 2018/03/08
 */
#ifndef __COMMON_TRNG_DFT_H__
#define __COMMON_TRNG_DFT_H__
#include <common_define.h>

enum rng_alarm {
	TRNG_ALARM_PRE = 0,
	TRNG_ALARM_POS,
	TRNG_ALM_CHI = 0x10,
	TRNG_ALM_LONGRUN,
	TRNG_ALM_PRE_POKER,
	TRNG_ALM_POS_POKER,
	TRNG_ALM_TIME_OUT,
	TRNG_ALM_SIGNAL,
};

enum rng_mode {
	TRNG_MODE_SRC = 0, /* source */
	TRNG_MODE_POS,     /* mask disabled */
};

#endif /* end of __COMMON_TRNG_DFT_H__ */
