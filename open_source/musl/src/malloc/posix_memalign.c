#define __NEED_size_t
#include <stdio.h>
#include "bits/alltypes.h"

#include <errno.h>
#include <asan.h>
#include "malloc_impl.h"

// A wrapper of __memalign which uses stack for return value and returns the errno.
NO_KASAN int posix_memalign(void **res, size_t align, size_t len)
{
	if (align < sizeof(void *)) return EINVAL;
	void *mem = __memalign(align, len);
	if (!mem) return errno;
	*res = mem;
	return 0;
}
