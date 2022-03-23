#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>    //__mmap is declared here.
#include "libc.h"
// here include syscall.h and please donot include unistd.h
// the syscall declaration in unistd.h will be expanded as error by macros in syscall.h
#include "syscall.h"
#include <pthread.h>
#include "autoconf.h"
#include "hm_thread.h"
#include "atomic.h"
#include "pthread_impl.h"
#include <asan.h>
#include "hm_malloc.h"
#include "malloc_impl.h"

#ifdef CONFIG_MEM_DEBUG
extern volatile int memcnt_lock[2];
extern uint32_t heap_alloc;
extern uint32_t expand_heap_times;
#endif

// copy from malloc.c
NO_KASAN static inline void lock(volatile int *lk)
{
	if (libc.threads_minus_1)
		while (a_swap(lk, 1)) __wait(lk, lk + 1, 1, 1);
}

// copy from malloc.c
NO_KASAN static inline void unlock(volatile int *lk)
{
	if (lk[0]) {
		a_store(lk, 0);
		if (lk[1]) __wake(lk, 1, 1);
	}
}

free_hook_fun svm_notify_drv = NULL;

NO_KASAN void set_free_heap_hook(free_hook_fun fn)
{
	svm_notify_drv = fn;
}

NO_KASAN void *__expand_heap(size_t *pn)
{
	static unsigned mmap_step;
	size_t n = *pn;

	/* check heap max size roughly, detail at memmgr */
	if (n > SIZE_MAX/2 - PAGE_SIZE) {
		errno = ENOMEM;
		return 0;
	}
	n += ((size_t)(-n) & (PAGE_SIZE - 1));

	/* using an exponential growth with limit */
	size_t min = (size_t)PAGE_SIZE << mmap_step / 2;
	if (n < min)
		n = min;
	// start address -1 means allocate virtual memory from
	// heap_start
	void *area = __mmap((void *)(uint64_t)-1, n, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED)
		return 0;

	*pn = n;
	mmap_step++;

	/* limit expand heap step: max 4 Pages (16k) */
	if (mmap_step > 5)
		mmap_step = 0;

#ifdef CONFIG_MEM_DEBUG
	lock(memcnt_lock);
	heap_alloc += n;
	expand_heap_times += 1;
	unlock(memcnt_lock);
#endif
	return area;
}

#define BIGHEAP_SIZE_SHIFT 5
NO_KASAN void *__expand_heap_big(size_t *pn)
{
	size_t n = *pn;

	/* check heap max size roughly, detail at memmgr */
	if (n > SIZE_MAX / 2 - PAGE_SIZE) {
		errno = ENOMEM;
		return 0;
	}
	n += ((size_t)(-n) & (PAGE_SIZE - 1));

	/* expand 256KB heap space every times to reduce change of page table */
	size_t min = (size_t)PAGE_SIZE << BIGHEAP_SIZE_SHIFT;
	if (n < min) n = min;
	// start address -1 means allocate virtual memory from
	// heap_start
	void *area = __mmap((void *)(uint64_t) -1, n, PROT_READ | PROT_WRITE,
		MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (area == MAP_FAILED) return 0;
	*pn = n;

#ifdef CONFIG_MEM_DEBUG
	lock(memcnt_lock);
	heap_alloc += n;
	expand_heap_times += 1;
	unlock(memcnt_lock);
#endif
	return area;
}