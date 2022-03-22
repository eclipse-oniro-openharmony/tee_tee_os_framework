/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Fri Sep 6 14:22:24 2019
 */
#define _GNU_SOURCE
#include <malloc.h>
#include <string.h>

#include "libc.h"
#include "malloc_impl.h"

/* Default value by musl */
#define DEFAULT_MMAP_THRESHOLD (0x1c00*SIZE_ALIGN)
#define DEFAULT_TRIM_THRESHOLD 163840

#define MMAP_THRESHOLD_MAX (SIZE_ALIGN * 128 * 64)

struct malloc_par mal_par = {
	.mmap_threshold = DEFAULT_MMAP_THRESHOLD,
	.trim_threshold = DEFAULT_TRIM_THRESHOLD,
};

int __malloc_initialized = -1;

extern char **__environ;

static inline char **next_malloc_env(char **pos)
{
	while (*pos != NULL) {
		if (__builtin_expect((*pos)[0] == 'M', 0)
		    && (*pos)[1] == 'A'
		    && (*pos)[2] == 'L'
		    && (*pos)[3] == 'L'
		    && (*pos)[4] == 'O'
		    && (*pos)[5] == 'C'
		    && (*pos)[6] == '_')
			return pos;
		++pos;
	}

	return NULL;
}

void malloc_init(void)
{
	char **env = NULL;

	if (__malloc_initialized >= 0)
		return;

	__malloc_initialized = 0;

	if (libc.secure) {
		__malloc_initialized = 1;
		return;
	}

	env = __environ;
	while ((env = next_malloc_env(env)) != NULL) {
		char *s = *env + 7;
		size_t len = strchrnul(s, '=') - s;

		++env;
		if (len == 0 || s[len] == '\0')
			continue;
		switch (len) {
		case 15:
			if (strncmp(s, "TRIM_THRESHOLD_", 15) == 0)
				mallopt(M_TRIM_THRESHOLD, atoi(&s[16]));
			else if (strncmp(s, "MMAP_THRESHOLD_", 15) == 0)
				mallopt(M_MMAP_THRESHOLD, atoi(&s[16]));
			break;
		default:
			break;
		}
	}

	__malloc_initialized = 1;
}

int mallopt(int param, int value)
{
	int ret = 0;

	if (__builtin_expect(__malloc_initialized < 0, 0))
		malloc_init();

	switch (param) {
	case M_TRIM_THRESHOLD:
		set_trim_threshold((size_t)value);
		ret = 1;
		break;
	case M_MMAP_THRESHOLD:
		if ((size_t)value <= MMAP_THRESHOLD_MAX) {
			set_mmap_threshold((size_t)value);
			ret = 1;
		}
		break;
	default:
		break;
	}

	return ret;
}
