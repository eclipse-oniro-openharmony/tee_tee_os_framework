/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: compiler assert
 * Author: l00370476, liuchong13@huawei.com
 * Create: 2019/12/24
 */

#ifndef __PAL_COMPILER_H__
#define __PAL_COMPILER_H__
#include <common_utils.h>

#define ASSERT_CONCATENATE(a, b) CONCATENATE(a, b)
#define PAL_COMPILER_ASSERT(cond, message) \
	static inline void ASSERT_CONCATENATE(__assert_func, __LINE__)(void) \
	{ \
		enum { \
			ASSERT_CONCATENATE(__assert_line, __LINE__) = \
						(1 / ((cond) ? 0 : 1)), \
		}; \
	}

#endif
