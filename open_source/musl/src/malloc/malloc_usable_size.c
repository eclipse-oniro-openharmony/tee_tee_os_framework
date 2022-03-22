#include <malloc.h>
#include <asan.h>
#include "malloc_impl.h"
 
hidden void *(*const __realloc_dep)(void *, size_t) = realloc;

/*
 * The malloc_usable_size() function returns the number of usable bytes
 * in the block pointed to by ptr, a pointer to a block of memory allocated
 * by malloc(3) or a related function.
 */
NO_KASAN size_t malloc_usable_size(void *p)
{
	return p ? CHUNK_SIZE(MEM_TO_CHUNK(p)) - OVERHEAD : 0;
}
