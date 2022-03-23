/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: autotest configure
 * Author     : m00475438
 * Create     : 2019/08/09
 */
#ifndef __HAT_CONFIGURE_H__
#define __HAT_CONFIGURE_H__
#include <pal_log.h>

/* #define FEATURE_HAT_PACKET_TRACE */

#define HAT_NAME_LEN           8
#define HAT_VALUE_LEN          (10 * 1024)  /* max parameter buffer size */
#define HAT_PACKET_MAX_LENGYH  (62 * 1024)  /* max packet size */

#define HAT_PRINTF(fmt, ...)  PAL_PRINTF(fmt, ##__VA_ARGS__)
#define HAT_INFO(fmt, ...)    HAT_PRINTF("<test>: "fmt, ##__VA_ARGS__)
#define HAT_ERROR(fmt, ...)   PAL_ERROR(fmt, ##__VA_ARGS__)

/**
 * do attention please:
 */
#define HAT_MEM_PARAMS_ALLOC_MAX    8  /* max members for dynamic mem alloc */
#define HAT_ST_POINTERS_NUMBER_MAX  20 /* max support for struct pointers */
#define HAT_IN_PARAMS_NUMBER_MAX    10 /* max support for func parameters */
#define HAT_RUN_FUNC(pfunc, pargv) \
	(pfunc)((pargv)[0], (pargv)[1], (pargv)[2], (pargv)[3], \
		(pargv)[4], (pargv)[5], (pargv)[6], (pargv)[7], \
		(pargv)[8], (pargv)[9])

#endif /* __HAT_CONFIGURE_H__ */
