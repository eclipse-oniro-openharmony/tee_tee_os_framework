#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>
#include <hm_mman.h>
#include <pthread.h>
#include <securec.h>
#include <sys/usrsyscall.h>
#include "libc.h"
#include "malloc.h"
#include "autoconf.h"
#include "posix_types.h"
#include "hm_thread.h"
#include "atomic.h"
#include "pthread_impl.h"
#include "malloc_impl.h"
#include <inttypes.h>
#include <procmgr.h>
#include <asan.h>
#include "hm_malloc.h"
#include "enable_free_uncommit.h"

#if defined(__GNUC__) && defined(__PIC__)
#define inline inline __attribute__((always_inline))
#endif

#define WEAK weak

#ifdef CONFIG_MEM_DEBUG
volatile int memcnt_lock[2];
uint32_t heap_used;
uint32_t heap_alloc;
uint32_t heap_free;
uint32_t mmap_used;
uint32_t mmap_alloc;
uint32_t mmap_free;
uint32_t mmap_times;
uint32_t munmap_times;
uint32_t expand_heap_times;
#endif

extern free_hook_fun svm_notify_drv;

#define MAX_BIN_NUM 64
static struct {
	volatile uint64_t binmap;
	//struct bin bins[64];
	struct bin bins[MAX_BIN_NUM];
	//volatile int free_lock[2];
	volatile int binmap_lock_m[2];
	volatile int binmap_lock_f[2];
} mal;

struct heap_reg {
	uintptr_t start;
	uintptr_t end;
} heap_reg;

static int num_heap_regs;
#define MAX_HEAP_REGS 64
static struct heap_reg heap_regs[MAX_HEAP_REGS];

int __malloc_replaced;

NO_KASAN static inline void lock(volatile int *lk)
{
	if (libc.threads_minus_1)
		while(a_swap(lk, 1)) __wait(lk, lk+1, 1, 1);
}

NO_KASAN static inline void unlock(volatile int *lk)
{
	if (lk[0]) {
		a_store(lk, 0);
		if (lk[1]) __wake(lk, 1, 1);
	}
}

NO_KASAN static inline void lock_bin(int i)
{
	lock(mal.bins[i].lock);
	if (!mal.bins[i].head)
		mal.bins[i].head = mal.bins[i].tail = BIN_TO_CHUNK(i);
}

NO_KASAN static inline void unlock_bin(int i)
{
	unlock(mal.bins[i].lock);
}

NO_KASAN static int first_set(uint64_t x)
{
	return a_ctz_64(x);
}

static const unsigned char bin_tab[60] = {
	            32,33,34,35,36,36,37,37,38,38,39,39,
	40,40,40,40,41,41,41,41,42,42,42,42,43,43,43,43,
	44,44,44,44,44,44,44,44,45,45,45,45,45,45,45,45,
	46,46,46,46,46,46,46,46,47,47,47,47,47,47,47,47,
};

/*
 * BUFOVF: index of bin_tab will not overflow
 *         if 32 < x < 512 ----> 0 < x/8-4 < 60
 *         if 512 <= x <= 7168(0x1c00) ----> 0 <= x/128-4 <= 52
 */
NO_KASAN static int bin_index(size_t x)
{
	x = x / SIZE_ALIGN - 1;
	if (x <= 32) return x;
	if (x < 512) return bin_tab[x/8-4];
	if (x > 0x1c00) return 63;
	return bin_tab[x/128-4] + 16;
}

/*
 * BUFOVF: bin_tab will not overflow
 */
NO_KASAN static int bin_index_up(size_t x)
{
	x = x / SIZE_ALIGN - 1;
	if (x <= 32) return x;
	x--;
	if (x < 512) return bin_tab[x/8-4] + 1;
	return bin_tab[x/128-4] + 17;
}

/*
 * BUFOVF: i is smaller than MAX_BIN_NUM
 */
NO_KASAN void dump_bins(void)
{
	int i;

	for (i = 0; i < MAX_BIN_NUM; i++) {
		if (mal.bins[i].head != BIN_TO_CHUNK(i) && mal.bins[i].head) {
			struct chunk *c = mal.bins[i].head;
			while (c->next != mal.bins[i].head) {
				/* mal.bins[i].head is circular linked list
				 * so c->next will no null */
				printf("bin %d: size %zu\n", i, c->csize);
				c = c->next;
			}
		}
	}
}

static void add_expand_record(void *addr, size_t size);

NO_KASAN static bool find_prev_and_merge(const void *p, size_t n)
{
	int i;

	add_expand_record((void *)p, n);

	for (i = 0; i < num_heap_regs; i++) {
		if (heap_regs[i].end == (uintptr_t)p) {
			heap_regs[i].end += n;
			return true;
		}
	}

	if (num_heap_regs >= MAX_HEAP_REGS) {
		printf("!!!WARNING: reach MAX_HEAP_REGS\n");
		return false;
	}

	heap_regs[num_heap_regs].start = (uintptr_t)p;
	heap_regs[num_heap_regs].end = (uintptr_t)p + n;
	num_heap_regs += 1;
	return false;
}

static bool using_big_heap = false;
volatile int heap_lock[2];

NO_KASAN void use_bigheap_policy(void)
{
	lock(heap_lock);
	using_big_heap = true;
	unlock(heap_lock);
}

NO_KASAN void dump_heap_regs(void)
{
	int i;

	lock(heap_lock);
	for (i = 0; i < num_heap_regs; i++) {
		printf("heap_regs[%d]: start %"PRIuPTR", end %"PRIuPTR"\n", i,
		       heap_regs[i].start, heap_regs[i].end);
	}
	unlock(heap_lock);
}

/*
 * RET: failure of __expand_heap is handled
 */
NO_KASAN static struct chunk *expand_heap(size_t n)
{
	static void *end;
	void *p;
	struct chunk *w;

	/* The argument n already accounts for the caller's chunk
	 * overhead needs, but if the heap can't be extended in-place,
	 * we need room for an extra zero-sized sentinel chunk. */
	n += SIZE_ALIGN;

	lock(heap_lock);

	if (using_big_heap)
		p = __expand_heap_big(&n);
	else
		p = __expand_heap(&n);
	if (!p) {
		unlock(heap_lock);
		return 0;
	}

	/* If not just expanding existing space, we need to make a
	 * new sentinel chunk below the allocated space. */
	if (!find_prev_and_merge(p, n)) {
		/* Valid/safe because of the prologue increment. */
		n -= SIZE_ALIGN;
		p = (char *)p + SIZE_ALIGN;
		w = MEM_TO_CHUNK(p);
		w->psize = 0 | C_INUSE;
	}

	/* Record new heap end and fill in footer. */
	end = (char *)p + n;
	w = MEM_TO_CHUNK(end);
	w->psize = n | C_INUSE;
	w->csize = 0 | C_INUSE;

	/* Fill in header, which may be new or may be replacing a
	 * zero-size sentinel header at the old end-of-heap. */
	w = MEM_TO_CHUNK(p);
	w->csize = n | C_INUSE;

	unlock(heap_lock);

	return w;
}

NO_KASAN static int adjust_size(size_t *n)
{
	/* Result of pointer difference must fit in ptrdiff_t. */
	if (*n-1 > PTRDIFF_MAX - SIZE_ALIGN - PAGE_SIZE) {
		if (*n) {
			errno = ENOMEM;
			return -1;
		} else {
			*n = SIZE_ALIGN;
			return 0;
		}
	}
#ifdef CONFIG_KASAN
	*n = (*n + ASAN_GUARD_CHUNK_SIZE + OVERHEAD + SIZE_ALIGN - 1) & SIZE_MASK;
#else
	*n = (*n + OVERHEAD + SIZE_ALIGN - 1) & SIZE_MASK;
#endif
	return 0;
}

NO_KASAN static void unbin(struct chunk *c, int i)
{
	if (c->prev == c->next)
		a_and_64(&mal.binmap, ~(1ULL<<i));
	c->prev->next = c->next;
	c->next->prev = c->prev;
	c->csize |= C_INUSE;
	NEXT_CHUNK(c)->psize |= C_INUSE;
}

NO_KASAN static int alloc_fwd(struct chunk *c)
{
	size_t k = c->csize;
	while (!(k & C_INUSE)) {
		int i = bin_index(k);
		lock_bin(i);
		if (c->csize == k) {
			unbin(c, i);
			unlock_bin(i);
			return 1;
		}
		unlock_bin(i);
		k = c->csize;
	}
	return 0;
}

NO_KASAN static int alloc_rev(struct chunk *c)
{
	size_t k = c->psize;
	while (!(k & C_INUSE)) {
		int i = bin_index(k);
		lock_bin(i);
		if (c->psize == k) {
			unbin(PREV_CHUNK(c), i);
			unlock_bin(i);
			return 1;
		}
		unlock_bin(i);
		k = c->psize;
	}
	return 0;
}

/* pretrim - trims a chunk _prior_ to removing it from its bin.
 * Must be called with i as the ideal bin for size n, j the bin
 * for the _free_ chunk self, and bin j locked. */
NO_KASAN static int pretrim(struct chunk *self, size_t n, int i, int j)
{
	size_t n1;
	struct chunk *next, *split;

	/* We cannot pretrim if it would require re-binning. */
	if (j < 40) return 0;
	if (j < i+3) {
		if (j != 63) return 0;
		n1 = CHUNK_SIZE(self);
		if (n1-n <= MMAP_THRESHOLD) return 0;
	} else {
		n1 = CHUNK_SIZE(self);
	}
	if (bin_index(n1-n) != j) return 0;

	next = NEXT_CHUNK(self);
	split = (void *)((char *)self + n);

	split->prev = self->prev;
	split->next = self->next;
	split->prev->next = split;
	split->next->prev = split;
	split->psize = n | C_INUSE;
	split->csize = n1-n;
	next->psize = n1-n;
	self->csize = n | C_INUSE;
	return 1;
}

NO_KASAN static void trim(struct chunk *self, size_t n)
{
	size_t n1 = CHUNK_SIZE(self);
	struct chunk *next, *split;

	if (n >= n1 - DONTCARE) return;

	next = NEXT_CHUNK(self);
	split = (void *)((char *)self + n);

	split->psize = n | C_INUSE;
	split->csize = n1-n | C_INUSE;
	next->psize = n1-n | C_INUSE;
	self->csize = n | C_INUSE;

	__bin_chunk(split);
}

NO_KASAN void get_memusage()
{
#ifdef CONFIG_MEM_DEBUG
	pid_t pid = hm_getpid();
	if (pid < 0)
		printf("ERROR: hm_getpid pid = %d\n", pid);
	lock(memcnt_lock);
	printf("=========================pid %d mem usage: total %x\n"
	       "=========================heap_alloc %x, heap_used %x, mmap_alloc %x, mmap_used %x, mmap_free %x\n"
	       "=========================expand_heap_times %u, mmap times %u, munmap times %u\n",
	       pid, heap_alloc + mmap_alloc - mmap_free, heap_alloc,
	       heap_used - heap_free, mmap_alloc, mmap_used, mmap_free,
	       expand_heap_times, mmap_times, munmap_times);
	unlock(memcnt_lock);
#endif
}

#ifndef USE_IN_SYSMGR
/*
 * BUFOVF: mal.bins[64] for j is return value of bin_index, from 0 to 63
 *         so there will not be buf overflow
 * RET: failure of __mmap is handled
 *      failure of expand_heap is handled
 */
/*
 * every malloced frame has a chunk in the prev frame.
 * when mmaped or extend heap , layout is as below.
 * --------------------------------------------------------------------------------
 * | padding or asan_guard | chunk | malloc buffer | asan_guard | padding | chunk |
 * --------------------------------------------------------------------------------
 *			   ^	                                          ^
 *			   pre chunk				          cur chunk
 *			   SIZE_ALIGN					  SIZE_ALIGN
 */
NO_KASAN void *malloc(size_t n)
{
	struct chunk *c;
	__attribute__((unused)) size_t ori_len = n;
	int i;

	if (n == 0)
		return NULL;
	if (adjust_size(&n) < 0) return 0;

	if (n > MMAP_THRESHOLD) {
		size_t len = n + OVERHEAD + PAGE_SIZE - 1 & -PAGE_SIZE;
		char *base = __mmap(0, len, PROT_READ|PROT_WRITE,
			MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
		if (base == (void *)-1) return 0;
		c = (void *)(base + SIZE_ALIGN - OVERHEAD);
		c->csize = len - (SIZE_ALIGN - OVERHEAD);
		c->psize = SIZE_ALIGN - OVERHEAD;
#ifdef CONFIG_MEM_DEBUG
		lock(memcnt_lock);
		mmap_alloc += len;
		mmap_used += n;
		mmap_times += 1;
		unlock(memcnt_lock);
#endif
#ifdef CONFIG_KASAN
		asan_unpoison_shadow(base + SIZE_ALIGN, ori_len);
		asan_poison_shadow(ALIGN_UP((size_t)(base + SIZE_ALIGN + ori_len),
					    ASAN_SHADOW_SCALE_SIZE),
				   base + len - ALIGN_UP((size_t)(base + SIZE_ALIGN + ori_len),
							 ASAN_SHADOW_SCALE_SIZE),
				   0xff);
		asan_poison_shadow(base, SIZE_ALIGN, 0xff);
#endif
		return CHUNK_TO_MEM(c);
	}

	i = bin_index_up(n);

	lock(mal.binmap_lock_m);
	for (;;) {
		int j;
		lock(mal.binmap_lock_f);
		uint64_t mask = mal.binmap & (uint64_t) -(1ULL << (unsigned int)i);
		unlock(mal.binmap_lock_f);
		if (!mask) {
			c = expand_heap(n);
			if (!c) {
				unlock(mal.binmap_lock_m);
				return 0;
			}
			if (alloc_rev(c)) {
				struct chunk *x = c;
				c = PREV_CHUNK(c);
				NEXT_CHUNK(x)->psize = c->csize =
					x->csize + CHUNK_SIZE(c);
			}
			break;
		}
		j = first_set(mask);
		lock_bin(j);
		c = mal.bins[j].head;
		if (c != BIN_TO_CHUNK(j)) {
			if (!pretrim(c, n, i, j)) unbin(c, j);
			unlock_bin(j);
			break;
		}
		unlock_bin(j);
	}

#ifdef CONFIG_MEM_DEBUG
	lock(memcnt_lock);
	heap_used += CHUNK_SIZE(c);
	unlock(memcnt_lock);
#endif
	/* Now patch up in case we over-allocated */
	trim(c, n);
	unlock(mal.binmap_lock_m);

#ifdef CONFIG_KASAN
	asan_unpoison_shadow(CHUNK_TO_MEM(c), ori_len);
	asan_poison_shadow(ALIGN_UP((size_t)(CHUNK_TO_MEM(c) + ori_len),
				    ASAN_SHADOW_SCALE_SIZE),
			   CHUNK_TO_MEM(c) + CHUNK_SIZE(c) - ALIGN_UP((size_t)(CHUNK_TO_MEM(c) + ori_len),
								      ASAN_SHADOW_SCALE_SIZE),
			   0xff);
#endif
	return CHUNK_TO_MEM(c);
}
#else
/* A dummy weak malloc/calloc/realloc/free to avoid introduce other dependencies */
WEAK void *malloc(size_t n)
{
    return NULL;
}
#endif

/*
 * RET: failure of __mmap is handled
 */
NO_KASAN void *malloc_coherent(size_t n)
{
	if (n == 0)
		return NULL;

	if (adjust_size(&n) < 0)
		return 0;

	struct chunk *c = NULL;
	size_t len = (n + OVERHEAD + PAGE_SIZE - 1) & -PAGE_SIZE;
	char *base = __mmap(0, len, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_COHERENT, -1, 0);
	if (base == (void *) -1) return 0;
	c = (void *)(base + SIZE_ALIGN - OVERHEAD);
	c->csize = len - (SIZE_ALIGN - OVERHEAD);
	c->psize = SIZE_ALIGN - OVERHEAD;
#ifdef CONFIG_MEM_DEBUG
	lock(memcnt_lock);
	mmap_alloc += len;
	mmap_used += n;
	mmap_times += 1;
	unlock(memcnt_lock);
#endif
	return CHUNK_TO_MEM(c);
}

/*
 *new patch in 22 version, waiting for checking!
 */
NO_KASAN static size_t mal0_clear(char *p, size_t pagesz, size_t n)
{
#ifdef __GNUC__
	typedef uint64_t __attribute__((__may_alias__)) T;
#else
	typedef unsigned char T;
#endif
	char *pp = p + n;
	size_t i = (uintptr_t)pp & (pagesz - 1);
	for (;;) {
		pp = memset(pp - i, 0, i);
		if (pp - p < pagesz) return pp - p;
		for (i = pagesz; i; i -= 2*sizeof(T), pp -= 2*sizeof(T))
		        if (((T *)pp)[-1] | ((T *)pp)[-2])
				break;
	}
}

#ifndef USE_IN_SYSMGR
/*
 *new patch in 22 version, waiting for checking!
 */
NO_KASAN void *calloc(size_t m, size_t n)
{
	if (n && m > (size_t)-1/n) {
		errno = ENOMEM;
		return 0;
	}
	n *= m;
	void *p = malloc(n);
	if (!p) return p;
	if (!__malloc_replaced) {
		if (IS_MMAPPED(MEM_TO_CHUNK(p)))
			return p;
		if (n >= PAGE_SIZE)
			n = mal0_clear(p, PAGE_SIZE, n);
	}
	return memset(p, 0, n);
}
#else
WEAK void *calloc(size_t m, size_t n)
{
    return NULL;
}
#endif

#ifndef USE_IN_SYSMGR
/*
 * RET: failure of memcpy_s is handled
 *      failure of malloc is handled
 * LEAK: when memcpy_s failed, allocated memory is freed
 */
NO_KASAN void *realloc(void *p, size_t n)
{
	struct chunk *self, *next;
	size_t n0, n1;
	size_t __attribute__((unused)) ori_len = n;
	void *new;
    int rc;

	if (!p) return malloc(n);

	if (!n) {
		free(p);
		return NULL;
	}

	if (adjust_size(&n) < 0) return 0;

	self = MEM_TO_CHUNK(p);
	n1 = n0 = CHUNK_SIZE(self);

	if (IS_MMAPPED(self)) {
		size_t extra = self->psize;
		char *base = (char *)self - extra;
		size_t oldlen = n0 + extra;
		size_t newlen = n + extra;
		/* Crash on realloc of freed chunk */
		if (extra & 1) a_crash();
		if (newlen < PAGE_SIZE) {
			new = malloc(n);
			if (new == NULL) {
				return NULL;
			}
			n0 = n;
			goto copy_free_ret;
		}
		newlen = (newlen + PAGE_SIZE-1) & -PAGE_SIZE;

		if (oldlen == newlen) {
#ifdef CONFIG_KASAN
			asan_unpoison_shadow(p, ori_len);
			asan_poison_shadow(ALIGN_UP((size_t)(p + ori_len), ASAN_SHADOW_SCALE_SIZE),
					   (void *)self + CHUNK_SIZE(self) - ALIGN_UP((size_t)(p + ori_len),
										      ASAN_SHADOW_SCALE_SIZE),
					   0xff);
#endif
			return p;
		}
		/*
		 * We don't support mremap yet, so alway goto
		 * copy_realloc, when mremap is supported, we can
		 * add it back.
		 */
		base = (void *) -1;
		if (base == (void *)-1)
			goto copy_realloc;
		self = (void *)(base + extra);
		self->csize = newlen - extra;
		return CHUNK_TO_MEM(self);
	}

	next = NEXT_CHUNK(self);

	/* Crash on corrupted footer (likely from buffer overflow) */
	if (next->psize != self->csize) a_crash();

	/* Merge adjacent chunks if we need more space. This is not
	 * a waste of time even if we fail to get enough space, because our
	 * subsequent call to free would otherwise have to do the merge. */
	if (n > n1 && alloc_fwd(next)) {
#ifdef CONFIG_MEM_DEBUG
		lock(memcnt_lock);
		heap_used += CHUNK_SIZE(next);
#endif
		n1 += CHUNK_SIZE(next);
		next = NEXT_CHUNK(next);
#ifdef CONFIG_MEM_DEBUG
		heap_alloc += CHUNK_SIZE(next);
		unlock(memcnt_lock);
#endif
	}
	self->csize = n1 | C_INUSE;
	next->psize = n1 | C_INUSE;

	/* If we got enough space, split off the excess and return */
	if (n <= n1) {
		trim(self, n);
		return CHUNK_TO_MEM(self);
	}

copy_realloc:
	/* As a last resort, allocate a new chunk and copy to it. */
	new = malloc(ori_len);
	if (!new) return 0;

copy_free_ret:
	rc = memcpy_s(new, n, p, n0 - OVERHEAD);
	if (rc) {
		printf("!!!WARNINGS, realloc memcpy_s error for SECC_RET_MEMCPY_ECODE = %d\n",
		       rc);
		free(new); /* because new is local variable, do not need to set NULL */
		return NULL;
	}
	free(CHUNK_TO_MEM(self));
	return new;
}
#else
WEAK void *realloc(void *p, size_t n)
{
    return NULL;
}
#endif

static int need_uncommit = 0;

void enable_free_uncommit(void)
{
	need_uncommit = 0x1234;
}

static void do_unmap_and_notify(void *base, size_t len)
{
	int rc = __munmap(base, len);
	if (rc)
		printf("ERROR: free: __munmap return code= %d\n", rc);
	else if (svm_notify_drv != NULL)
		svm_notify_drv(base, (void *)(uintptr_t)len);
}

NO_KASAN void __bin_chunk(struct chunk *self)
{
	struct chunk *next = NEXT_CHUNK(self);
	size_t final_size, new_size, size;
	int reclaim=0;
	int i;
	int rc;

#ifdef CONFIG_MEM_DEBUG
	lock(memcnt_lock);
	heap_free += CHUNK_SIZE(self);
	unlock(memcnt_lock);
#endif

	final_size = new_size = CHUNK_SIZE(self);

	/* Crash on corrupted footer (likely from buffer overflow) */
	if (next->psize != self->csize) {
		// For RTOSck, bad free() will not crash process.
		// We just print a error message here.
		printf("ERROR: free: corrupted footer\n");
#ifdef CONFIG_DEBUG_BUILD
		rc = hm_dump_current_stack();
		if (rc)
			printf("ERROR: free: hm_dump_current_stack return code = %d\n", rc);
#endif
		return;
	}

	lock(mal.binmap_lock_f);
	for (;;) {
		if (self->psize & next->csize & C_INUSE) {
			self->csize = final_size | C_INUSE;
			next->psize = final_size | C_INUSE;
			i = bin_index(final_size);
			lock_bin(i);
			if (self->psize & next->csize & C_INUSE)
				break;
			unlock_bin(i);
		}

		if (alloc_rev(self)) {
			self = PREV_CHUNK(self);
			size = CHUNK_SIZE(self);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
		}

		if (alloc_fwd(next)) {
			size = CHUNK_SIZE(next);
			final_size += size;
			if (new_size+size > RECLAIM && (new_size+size^size) > size)
				reclaim = 1;
			next = NEXT_CHUNK(next);
		}
	}

	if (!(mal.binmap & 1ULL << (unsigned int)i))
		a_or_64(&mal.binmap, 1ULL << (unsigned int)i);

	self->csize = final_size;
	next->psize = final_size;
	unlock(mal.binmap_lock_f);

	self->next = BIN_TO_CHUNK(i);
	self->prev = mal.bins[i].tail;
	self->next->prev = self;
	self->prev->next = self;

#ifdef CONFIG_KASAN
	asan_poison_shadow(CHUNK_TO_MEM(self), CHUNK_SIZE(self), 0xff);
#endif
	/* Replace middle of large chunks with fresh zero pages */
	if (need_uncommit && reclaim) {
		uintptr_t a = ((uintptr_t)self + SIZE_ALIGN + PAGE_SIZE - 1) & -PAGE_SIZE;
		uintptr_t b = ((uintptr_t)next - SIZE_ALIGN) & -PAGE_SIZE;
		rc = hm_muncommit((void *)a, b - a);
		if (rc) {
			printf("ERROR: free: hm_muncommit return code = %d\n", rc);
		}
	}

	unlock_bin(i);
}

NO_KASAN static void unmap_chunk(struct chunk *self)
{
    size_t extra = self->psize;
	char *base = (char *)self - extra;
	size_t len = CHUNK_SIZE(self) + extra;
	/* Crash on double free */
	if (extra & 1) {
		// For RTOSck, bad free() will not crash process.
		// We just print a error message here.
		printf("ERROR: free: double free\n");
#ifdef CONFIG_DEBUG_BUILD
		int rc = hm_dump_current_stack();
		if (rc)
			printf("ERROR: free: hm_dump_current_stack return code = %d\n", rc);
#endif
		return;
	}
	do_unmap_and_notify((void *)base, len);
#ifdef CONFIG_MEM_DEBUG
	lock(memcnt_lock);
	mmap_free += len;
	munmap_times += 1;
	unlock(memcnt_lock);
#endif
}

#ifndef USE_IN_SYSMGR
/*
 * BUFOVF: mal.bins[64] for i is return value of bin_index, from 0 to 63
 *         so there will not be buf overflow
 * RET: failure of __munmap/hm_dump_current_stack/hm_muncommit
 *      are handled
 */
NO_KASAN void free(void *p)
{
	if (!p) return;

	struct chunk *self = MEM_TO_CHUNK(p);

	if (IS_MMAPPED(self))
		unmap_chunk(self);
	else
		__bin_chunk(self);
}
#else
WEAK void free(void *p)
{}
#endif

NO_KASAN static void delbin(struct chunk *local_c, struct chunk *c, int i)
{
	if (local_c->prev == local_c->next)
		a_and_64(&mal.binmap, ~(1ULL << (unsigned int)i));
	local_c->prev->next = local_c->next;
	local_c->next->prev = local_c->prev;

	c->csize = 0 | C_INUSE;
}

NO_KASAN static struct chunk* free_last_chunk(struct chunk *self)
{
	struct chunk *next = NULL;
	size_t final_size, size;
	int i;
	final_size = CHUNK_SIZE(self);
	next = NEXT_CHUNK(self);

	for (;;) {
		if (self->psize & next->csize & C_INUSE) {
			self->csize = final_size | C_INUSE;
			next->psize = final_size | C_INUSE;
			i = bin_index(final_size);
			lock_bin(i);
			if (self->psize & next->csize & C_INUSE)
				break;
			unlock_bin(i);
		}

		if (alloc_rev(self)) {
			self = PREV_CHUNK(self);
			size = CHUNK_SIZE(self);
			final_size += size;
		}
	}

	if (!(mal.binmap & 1ULL << (unsigned int)i))
		a_or_64(&mal.binmap, 1ULL << (unsigned int)i);

	self->csize = final_size;
	next->psize = final_size;

	self->next = BIN_TO_CHUNK(i);
	self->prev = mal.bins[i].tail;
	self->next->prev = self;
	self->prev->next = self;
	unlock_bin(i);
	return self;
}

#define EXPAND_RECORD_NUM	64
struct expand_entry{
	void *addr;
	size_t size;
};
struct expand_array {
	uint32_t head;
	uint32_t tail;
	uint32_t entry_cnt;
	struct expand_entry entrys[EXPAND_RECORD_NUM];
};
static struct expand_array records = {0, 0, 0, {{0, 0}}};

NO_KASAN static void add_expand_record(void *addr, size_t size)
{
	if (records.head >= EXPAND_RECORD_NUM || records.tail >= EXPAND_RECORD_NUM) {
		printf("records index overflow\n");
		records.head = records.tail = 0;
		records.entry_cnt = 0;
	}
	records.entrys[records.head].addr = addr;
	records.entrys[records.head].size = size;
	records.head = (records.head + 1) % EXPAND_RECORD_NUM;
	records.entry_cnt += 1;
	if (records.head == records.tail)
		records.tail = (records.tail + 1) % EXPAND_RECORD_NUM;
}

NO_KASAN static int do_shrink(void *addr, size_t n, bool *do_unmap)
{
	int i = 0;
	for (; i < num_heap_regs; ++i) {
		if (heap_regs[i].start == (uintptr_t)addr)
			return -ENOMEM;

		if (heap_regs[i].end == (uintptr_t)(addr + n)) {
			break;
		}
	}
	if (i >= num_heap_regs) {
		for (i = 0; i < num_heap_regs; i++) {
			printf("heap_regs[%d]: start %"PRIuPTR", end %"PRIuPTR"\n", i,
				heap_regs[i].start, heap_regs[i].end);
		}
		return -EINVAL;
	}

	int rc = __munmap(addr, n);
	if (rc) {
		printf("do shrink heap failed %d!\n", rc);
		return rc;
	}

	heap_regs[i].end -= n;
	records.head = (records.head + EXPAND_RECORD_NUM - 1) % EXPAND_RECORD_NUM;
	records.entry_cnt -= 1;
	*do_unmap = true;
	return 0;
}

NO_KASAN static int check_merge_top_heap(struct chunk *c_chunk, size_t n)
{
	size_t c_sz = CHUNK_SIZE(c_chunk);
	int i = bin_index(c_sz);
	lock_bin(i);

	if (c_chunk->csize & C_INUSE) {
		goto out_merge;
	}

	if (CHUNK_SIZE(c_chunk) >= n) {
		unlock_bin(i);
		return 0;
	}

	if (c_chunk->psize & C_INUSE) {
		goto out_merge;
	}

	/* do merge */
	unbin(c_chunk, i); /* malloc chunk */
	unlock_bin(i);
	c_chunk = free_last_chunk(c_chunk); /* free chunk */

	if (CHUNK_SIZE(c_chunk) >= n)
		return 0;
	else
		return -ENOMEM;
out_merge:
	unlock_bin(i);
	return -ENOMEM;
}

NO_KASAN static int shrink_top_heap_map(uint32_t head, bool *do_unmap)
{
	int i, rc;
	size_t n = records.entrys[head].size;
	void *map_ptr = records.entrys[head].addr;
	struct chunk *heap_end = NULL, *c_chunk = NULL;
	size_t c_sz;

	heap_end = MEM_TO_CHUNK(map_ptr + n);
	c_chunk = PREV_CHUNK(heap_end);
	rc = check_merge_top_heap(c_chunk, n);
	if (rc) {
		return rc;
	}

	c_chunk = PREV_CHUNK(heap_end);
	c_sz = CHUNK_SIZE(c_chunk);
	i = bin_index(c_sz);
	lock_bin(i);

	if (c_sz == n) {
		/* can't access link list after unmap, store them first*/
		struct chunk local_c = *c_chunk;
		if (do_shrink(map_ptr, n, do_unmap)) {
			unlock_bin(i);
			return -EINVAL;
		}
		delbin(&local_c, c_chunk, i);
		unlock_bin(i);
	} else {
		if (c_sz - n <= DONTCARE) {
			unlock_bin(i);
			return -EINVAL;
		}
		if (do_shrink(map_ptr, n, do_unmap)) {
			unlock_bin(i);
			return -EINVAL;
		}

		c_chunk->csize -= n; /* delete unmap chunk region */
		heap_end = NEXT_CHUNK(c_chunk);
		heap_end->csize = 0 | C_INUSE;
		heap_end->psize = c_sz - n;
		unbin(c_chunk, i); /* malloc left chunk */
		unlock_bin(i);

		free_last_chunk(c_chunk); /* free the left chunk */
	}
	return 0;
}

#define REMAIN_EXPAND	2
NO_KASAN int shrink()
{
	if (need_uncommit)
		return 0;
	lock(mal.binmap_lock_m);
	lock(mal.binmap_lock_f);
	lock(heap_lock);

	uint32_t head = (records.head + EXPAND_RECORD_NUM - 1) % EXPAND_RECORD_NUM;
	uint32_t tail = (records.tail + EXPAND_RECORD_NUM - 1) % EXPAND_RECORD_NUM;
	int unmap_times = (records.entry_cnt > REMAIN_EXPAND) ? records.entry_cnt - REMAIN_EXPAND: 0;
	bool do_unmap = false;

	while (head != tail && unmap_times--) {
		if (shrink_top_heap_map(head, &do_unmap))
			goto unlock_exit;

		head = (head + EXPAND_RECORD_NUM - 1) % EXPAND_RECORD_NUM;
	}
unlock_exit:
	unlock(heap_lock);
	unlock(mal.binmap_lock_f);
	unlock(mal.binmap_lock_m);
	return do_unmap;
}

NO_KASAN void __malloc_donate(char *start, char *end)
{
	size_t align_start_up = (SIZE_ALIGN-1) & (-(uintptr_t)start - OVERHEAD);
	size_t align_end_down = (SIZE_ALIGN-1) & (uintptr_t)end;

	/* Getting past this condition ensures that the padding for alignment
	 * and header overhead will not overflow and will leave a nonzero
	 * multiple of SIZE_ALIGN bytes between start and end. */
	if (end - start <= OVERHEAD + align_start_up + align_end_down)
		return;
	start += align_start_up + OVERHEAD;
	end   -= align_end_down;

	struct chunk *c = MEM_TO_CHUNK(start), *n = MEM_TO_CHUNK(end);
	c->psize = n->csize = C_INUSE;
	c->csize = n->psize = C_INUSE | (end-start);
	__bin_chunk(c);
}
