#include <unistd.h>
#include <hm_mman.h>
#include <stdint.h>

/*
 * ARG: start, len, prot, flags, fd, off: passed to hm_mmap
 * RET: hm_mmap: return its ret
 */
// simply call hm_mmap which sends a mmap request to mmgr
void *__mmap(void *start, size_t len, int prot, int flags, int fd, off_t off)
{
	return hm_mmap(start, len, prot, flags, fd, off);
}

weak_alias(__mmap, mmap);

weak_alias(mmap, mmap64);
