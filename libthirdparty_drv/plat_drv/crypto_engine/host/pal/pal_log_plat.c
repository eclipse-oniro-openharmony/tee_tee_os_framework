/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * Description: platform adapter for log
 * Author     : m00475438
 * Create     : 2018/08/15
 */
#include <pal_log.h>
#include <stdio.h>
#include <stdarg.h>
#include <pal_libc.h>
#include <common_utils.h>

#define BSP_THIS_MODULE               BSP_MODULE_SYS

void hieps_log(const char *fmt, ...)
{
	int str_len;
	va_list args;
	char log_buf[128] = {0}; /* 128 is log buffer size */

	va_start(args, fmt);
	str_len = vsnprintf_s(log_buf, sizeof(log_buf),
			      sizeof(log_buf) - 1, fmt, args);
	va_end(args);
	if (str_len <= 0)
		printf("hieps_log,ret=%d\n", str_len);
	log_buf[sizeof(log_buf) - 1] = '\0';
	printf("%s", log_buf);
}

