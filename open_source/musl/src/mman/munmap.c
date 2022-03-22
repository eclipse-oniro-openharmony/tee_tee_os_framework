#include <hm_mman.h>
#include <procmgr.h>


static void dummy(void) { }
weak_alias(dummy, __vm_wait);

/*
 * ARG: start, len: passed to hm_munmap
 * RET: __vm_wait: void
 *      hm_munmap: return its ret
 */
// simply call hm_munmap which sends a mmap request to mmgr
int __munmap(const void *start, size_t len)
{
	__vm_wait();
	return hm_munmap(start, len);
}

weak_alias(__munmap, munmap);
