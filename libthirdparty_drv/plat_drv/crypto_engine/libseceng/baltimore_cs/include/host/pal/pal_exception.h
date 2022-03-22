/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: define exception
 * Author     : m00475438
 * Create     : 2019/08/25
 */
#ifndef __PAL_EXCEPTION_H__
#define __PAL_EXCEPTION_H__
#include <pal_exception_plat.h>
#include <pal_log.h>

/**
 * @brief throw exception when errno isn not BSP_RET_OK
 */
#define PAL_ERR_THROW(result) do { \
	if ((result) != BSP_RET_OK) { \
		PAL_ERROR("Exception for errno = " PAL_FMT_HEX "\n", result); \
		pal_exception_process(BSP_THIS_MODULE, result); \
	} \
} while (0)

#endif /* __PAL_EXCEPTION_H__ */
