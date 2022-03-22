/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Thu Aug 15 10:22:06 2019
 */

#ifdef MEMTRACE
#include <stdio.h>

static void __mtrace_record_malloc(void *p, size_t size)
{
}

static void __mtrace_record_free(const void *p)
{
}

static size_t __mtrace_get_obj_size(const void *p)
{
	return 0;
}

weak_alias(__mtrace_record_malloc, mtrace_record_malloc);
weak_alias(__mtrace_record_free, mtrace_record_free);
weak_alias(__mtrace_get_obj_size, mtrace_get_obj_size);

#endif
