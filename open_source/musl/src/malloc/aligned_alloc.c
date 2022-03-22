#define __NEED_size_t
#include "bits/alltypes.h"
#include "malloc_impl.h"
#include <stddef.h>

// simply call memalign
void *aligned_alloc(size_t align, size_t len)
{
	return __memalign(align, len);
}
