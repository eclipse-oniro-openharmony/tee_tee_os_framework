/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * Author: Huawei OS Kernel Lab
 * Create: Tue Feb 11 11:50:30 2020
 */

#include "internal.h"
#include "enable_free_uncommit.h"
#include <sys/hmapi.h>
#include <hm_mman.h>

#define X2(a, b) a(b), a(b + 1)
#define X4(a, b) X2(a, b), X2(a, b + 2)
#define X8(a, b) X4(a, b), X4(a, b + 4)
#define X16(a, b) X8(a, b), X8(a, b + 8)
#define X32(a, b) X16(a, b), X16(a, b + 16)
#define X64(a, b) X32(a, b), X32(a, b + 32)

/* statically initialize main heap to avoid bothering with init sequence */
heap_t g_heapmgr_mainheap = {
#define INIT_BIN(x) .bin[x] = {&g_heapmgr_mainheap.bin[x], &g_heapmgr_mainheap.bin[x]}
	X8(INIT_BIN, 0), X2(INIT_BIN, 8), INIT_BIN(10),
#if SIZE_MAX == UINT_MAX
	X4(INIT_BIN, 11), INIT_BIN(15),
#endif
#undef INIT_BIN
	.full = {&g_heapmgr_mainheap.full, &g_heapmgr_mainheap.full},
#define INIT_FREE(x) .free[x] = {&g_heapmgr_mainheap.free[x], &g_heapmgr_mainheap.free[x]}
#ifndef SMALL_CHUNK
	X64(INIT_FREE, 0), X32(INIT_FREE, 64), X16(INIT_FREE, 96),
	X8(INIT_FREE, 112), X4(INIT_FREE, 120), X2(INIT_FREE, 124),
#else
	X4(INIT_FREE, 0), X2(INIT_FREE, 4), INIT_FREE(6),
#endif
#undef INIT_FREE
	.chunks = {&g_heapmgr_mainheap.chunks, &g_heapmgr_mainheap.chunks},
};

#ifndef SMALL_CHUNK
static_assert(DATA_PAGE_NUM == 126, "unmatched g_heapmgr_mainheap initializer");
#else
static_assert(DATA_PAGE_NUM == 7, "unmatched g_heapmgr_mainheap initializer");
#endif
#if SIZE_MAX == UINT_MAX
static_assert(NUM_SMALL_CLASSES == 16, "unmatched g_heapmgr_mainheap initializer");
#else
static_assert(NUM_SMALL_CLASSES == 11, "unmatched g_heapmgr_mainheap initializer");
#endif

#undef X2
#undef X4
#undef X8
#undef X16
#undef X32
#undef X64

heap_t *g_heapmgr_heaps[HEAP_NUM_MAX] = {
	[0] = &g_heapmgr_mainheap,
};
size_t g_heapmgr_num_heaps = 1UL;
size_t g_heapmgr_trim_threshold = DEFAULT_TRIM_THRESHOLD;
size_t g_heapmgr_hugealloc_cnt = 0UL;
size_t g_heapmgr_hugealloc_size = 0UL;

static unsigned long g_heap_counter;

#define check_free_abort(x, func, line) do { \
	if (!(x)) { \
		heapmgr_log("[func %s line %d] abnormal free on 0x%zx: %s\n", \
			    func, line, (uintptr_t)p, #x); \
		abort(); \
	} \
} while(1 != 1)
#define do_check_free(x) check_free_abort(x, __func__, __LINE__)
static void check_free_huge(void *p)
{
	chunk_t *c = align_ptr(p, CHUNK_SIZE);
	unsigned long tmp_addr;
	if (c == p) {
		tmp_addr = ptr_to_ulong(p);
		tmp_addr -= SYSTEM_PAGE_SIZE;
		c = ulong_to_ptr(tmp_addr, chunk_t);
		do_check_free(c->state == CHUNK_STATE_HUGE_ALIGNED);
		do_check_free(c->huge_aligned.base == p);
	} else {
		do_check_free(c->state == CHUNK_STATE_HUGE);
		do_check_free(c->huge.base == p);
	}
}

static void check_free_normal(void *p)
{
	do_check_free(ptr_aligned(p, SMALL_ALIGN));
	chunk_t *c = align_ptr(p, CHUNK_SIZE);
	size_t idx = ((uintptr_t)p % CHUNK_SIZE) / HEAPMGR_PAGE_SIZE;
	do_check_free(idx >= META_PAGE_NUM);
	unsigned long tmp_addr = ptr_to_ulong(c);
	tmp_addr += (idx * PAGE_DESC_SIZE);
	page_t *page = ulong_to_ptr(tmp_addr, page_t);
	switch (page->state) {
	case PAGE_STATE_SMALL:
		do_check_free(page->small.used > 0U);
		do_check_free(page_block_valid(page, (block_t *)p));
		do_check_free(!page_block_free(page, (block_t *)p));
		break;
	case PAGE_STATE_LARGE_HEAD:
		do_check_free(p == page_base_addr_of(page));
		break;
	case PAGE_STATE_LARGE_TAIL_MIXED:
		do_check_free((char *)p ==
			      (char *)page_base_addr_of(page) + page->large_tail_mixed.size0);
		do_check_free(page->large_tail_mixed.used0 != 0U);
		do_check_free(page->large_tail_mixed.used1 != 0U);
		break;
	case PAGE_STATE_LARGE_HEAD_MIXED:
		/* HEAD_MIXED page is always single page */
		do_check_free(page->large_head_mixed.npages == 1UL);
		char *base = page_base_addr_of(page);
		if ((char *)p == base) {
			/* first block */
			do_check_free(page->large_head_mixed.used0 != 0U);
		} else {
			/* second block */
			do_check_free((char *)p == base + page->large_head_mixed.size0);
			do_check_free(page->large_head_mixed.used1 != 0U);
		}
		break;
	default:
		heapmgr_log("abnormal free on 0x%zx: undefined page state!\n", (uintptr_t)p);
		abort();
	}
}
#define MCHECK_FREE_HUGE(p) do { \
	if (UNLIKELY(g_heapmgr_enable_mcheck)) { \
		check_free_huge(p); \
	} \
} while(1 != 1)
#define MCHECK_FREE_NORMAL(p) do { \
	if (UNLIKELY(g_heapmgr_enable_mcheck)) { \
		check_free_normal(p); \
	} \
} while(1 != 1)

static lock_t g_heapmgr_sel_heaps_lock;
static int32_t g_heapmgr_heap_sel_cache[HEAP_NUM_MAX];

void heap_cleanup(int32_t tid)
{
	uint32_t i;

	heapmgr_mutex_lock(g_heapmgr_sel_heaps_lock);
	for (i = 0; i < HEAP_NUM_MAX; i++) {
		if (tid == g_heapmgr_heap_sel_cache[i]) {
			g_heapmgr_heap_sel_cache[i] = 0;
			break;
		}
	}
	heapmgr_mutex_unlock(g_heapmgr_sel_heaps_lock);
}

ALWAYS_INLINE size_t sel_heap_with_cache(int32_t tid)
{
	uint32_t i;

	heapmgr_mutex_lock(g_heapmgr_sel_heaps_lock);
	for (i = 0; i < HEAP_NUM_MAX; i++) {
		if (g_heapmgr_heap_sel_cache[i] == 0) {
			g_heapmgr_heap_sel_cache[i] = tid;
			break;
		}
	}
	heapmgr_mutex_unlock(g_heapmgr_sel_heaps_lock);

	return i < HEAP_NUM_MAX ? i : -1;
}

ALWAYS_INLINE heap_t *select_heap(void)
{
	heap_t *ret = NULL;

	DCHECK(g_heapmgr_num_heaps >= 1UL);
	DCHECK(g_heapmgr_num_heaps <= HEAP_NUM_MAX);
	if (g_heapmgr_num_heaps == 1UL) {
		ret = &g_heapmgr_mainheap;
	} else {
		heap_t *local_heap = (heap_t *)(hmapi_tls_get()->thread_local_heap);
		if (UNLIKELY(local_heap == NULL)) {
			size_t n = sel_heap_with_cache((heap_t *)(hmapi_tls_get()->thread_id));
			if (n == -1)
				n = __atomic_fetch_add(&g_heap_counter, 1, __ATOMIC_RELAXED);
			DCHECK(g_heapmgr_num_heaps <= HEAP_NUM_MAX);
			local_heap = g_heapmgr_heaps[n % g_heapmgr_num_heaps];
			hmapi_tls_get()->thread_local_heap = local_heap;
		}
		ret = local_heap;
	}

	return ret;
}

ALWAYS_INLINE void *heap_alloc(heap_t *heap, size_t size)
{
	void *p = NULL;

	if (UNLIKELY(size > SMALL_SIZE_MAX)) {
		p = heap_alloc_large(heap, size);
	} else {
		/* size2direct is faster than size2bin, use it in fastpath */
		size_t d = size2direct(size);
		DCHECK(d < NUM_DIRECT);

		heapmgr_mutex_lock(heap->lock);

		page_t *page = heap->direct[d];
		if (UNLIKELY(page == NULL)) {
			/* no cached page, go to the slow path */
			p = heap_alloc_small_locked(heap, size);
		} else {
			DCHECK(page->state == PAGE_STATE_SMALL);
			if (UNLIKELY(page->small.free == NULL)) {
				/* cached page is full, go to the slow path */
				heap_move_page_to_full(heap, page);
				p = heap_alloc_small_locked(heap, size);
			} else {
				/* this is the fast path for alloc */
				DCHECK(page->small.size >= size);
				DCHECK(page->small.used < HEAPMGR_PAGE_SIZE / page->small.size);
				p = page_pop_block(page);
			}
		}

		heapmgr_mutex_unlock(heap->lock);
	}

	return p;
}

/*
 * heapmgr_alloc: The main entry of malloc
 *
 * We have three kinds of return address for return value p:
 * 1. p is aligned with 256K(CHUNK_SIZE)
 *    aligned alloc for size >= 252K, meta data will be stored in
 *    address (p - SYSTEM_PAGE_SIZE).
 * 2. (p - 32) is aligned with 256K
 *    non-aligned alloc for size >= 252K, meta data will be
 *    stored in address (p - 32). (32 is CHUNK_DESC_SIZE)
 * 3. p % 256K >= 4K(META_PAGE_SIZE)
 *    other malloc requests for size < 252K(CHUNK_SIZE - META_PAGE_SIZE).
 */
#ifndef USE_IN_SYSMGR
void *heapmgr_malloc(size_t size)
{
	if (size == 0UL)
		return NULL;
	void *p = heap_alloc(select_heap(), size);
#ifdef MEMTRACE
	if (LIKELY(p != NULL)) {
		mtrace_record_malloc(p, size);
	}
#endif
	return p;
}
#else
void *heapmgr_malloc(size_t size)
{
	return NULL;
}
#endif

WEAK_ALIAS(heapmgr_malloc, malloc);

#ifndef USE_IN_SYSMGR
void *heapmgr_calloc(size_t count, size_t size)
{
	void *p = NULL;
	size_t total;

	if (count == 0UL || size == 0UL)
		return NULL;
	if (UNLIKELY(mul_overflow(count, size, &total))) {
		heapmgr_set_errno(ENOMEM, __func__, __LINE__);
	} else {
		p = heap_alloc(select_heap(), total);
		if (LIKELY(p != NULL)) {
			chunk_t *c = align_ptr(p, CHUNK_SIZE);
			if (c->state == CHUNK_STATE_NORMAL) {
				(void)memset(p, 0, total);
			} else {
				/* mmap'ed, zero-init by OS */
				DCHECK(c->state == CHUNK_STATE_HUGE);
			}
#ifdef MEMTRACE
			mtrace_record_malloc(p, size);
#endif
		}
	}

	return p;
}
#else
void *heapmgr_calloc(size_t count, size_t size)
{
    return NULL;
}
#endif

WEAK_ALIAS(heapmgr_calloc, calloc);

#ifndef USE_IN_SYSMGR
void *heapmgr_realloc(void *p, size_t newsize)
{
	void *ret = NULL;

	if (p == NULL) {
		if (newsize == 0UL)
			return NULL;
		ret = heap_alloc(select_heap(), newsize);
#ifdef MEMTRACE
		if (LIKELY(ret != NULL)) {
			mtrace_record_malloc(ret, newsize);
		}
#endif
	} else if (newsize == 0UL) {
		heapmgr_free(p);
	} else {
		size_t size = heapmgr_usable_size(p);
		if ((newsize <= size) && (newsize >= size / 2UL)) {
			/* at most 50% waste of space in this case */
			ret = p;
		} else {
			/* perf: can use mremap for some cases */
			ret = heap_alloc(select_heap(), newsize);
			if (LIKELY(ret != NULL)) {
				(void)memcpy(ret, p, size > newsize ? newsize : size);
				heapmgr_free(p);
#ifdef MEMTRACE
				mtrace_record_malloc(ret, newsize);
#endif
			}
		}
	}

	return ret;
}
#else
void *heapmgr_realloc(void *p, size_t newsize)
{
    return NULL;
}
#endif

WEAK_ALIAS(heapmgr_realloc, realloc);

#ifndef USE_IN_SYSMGR
void *heapmgr_reallocarray(void *p, size_t nmemb, size_t elem_size)
{
	size_t bytes = 0UL;
	void *ret = NULL;
	if (UNLIKELY(mul_overflow(nmemb, elem_size, &bytes))) {
		heapmgr_set_errno(ENOMEM, __func__, __LINE__);
	} else {
		ret = heapmgr_realloc(p, bytes);
	}
	return ret;
}
#else
void *heapmgr_reallocarray(void *p, size_t nmemb, size_t elem_size)
{
    return NULL;
}
#endif

WEAK_ALIAS(heapmgr_reallocarray, reallocarray);

static void do_free_with_chunk(void *p, chunk_t *chunk)
{
#ifdef MEMTRACE
	mtrace_record_free(p);
#endif
	if (UNLIKELY(chunk == p || chunk->state != CHUNK_STATE_NORMAL)) {
		MCHECK_FREE_HUGE(p);
		/* CHUNK_STATE_HUGE or CHUNK_STATE_HUGE_ALIGNED */
		free_huge_pages(p);
	} else {
		heap_t *heap = chunk->normal.heap;
		DCHECK((char *)p < (char *)chunk + CHUNK_SIZE);
		size_t idx = ((uintptr_t)p % CHUNK_SIZE) / HEAPMGR_PAGE_SIZE;
		DCHECK(idx >= META_PAGE_NUM);
		unsigned long tmp_addr = ptr_to_ulong(chunk);
		tmp_addr += (idx * PAGE_DESC_SIZE);
		page_t *page = ulong_to_ptr(tmp_addr, page_t);

		heapmgr_mutex_lock(heap->lock);
		MCHECK_FREE_NORMAL(p);

		if (UNLIKELY(page->state != PAGE_STATE_SMALL)) {
			/* PAGE_STATE_LARGE_* */
			heap_free_large_locked(heap, p);
		} else {
			block_t *b = p;
			DCHECK(page->small.used > 0U);
			DCHECK(!page_block_free(page, b));
			if (UNLIKELY((page->small.used == 1U) ||
				     (page->small.free == NULL))) {
				/* need to change page state in this case, go to the slow path */
				heap_free_small_locked(heap, page, b);
			} else {
				/* this is the fast path for free */
				page_push_block(page, b);
			}
		}
		heapmgr_mutex_unlock(heap->lock);
	}
}

#ifndef USE_IN_SYSMGR
void heapmgr_free(void *p)
{
	DCHECK(ptr_aligned(p, SMALL_ALIGN));
	chunk_t *chunk = align_ptr(p, CHUNK_SIZE);
	if (LIKELY(chunk != NULL)) {
		do_free_with_chunk(p, chunk);
	}
}
#else
void heapmgr_free(void *p)
{}
#endif

WEAK_ALIAS(heapmgr_free, free);

size_t heapmgr_usable_size(void *p)
{
	size_t ret = 0UL;

	DCHECK(ptr_aligned(p, SMALL_ALIGN));
	chunk_t *chunk = align_ptr(p, CHUNK_SIZE);
	unsigned long tmp_addr;
	if (LIKELY(chunk != NULL)) {
		if (UNLIKELY(chunk == p)) {
			tmp_addr = ptr_to_ulong(p);
			tmp_addr -= SYSTEM_PAGE_SIZE;
			chunk = ulong_to_ptr(tmp_addr, chunk_t);
			DCHECK(chunk->state == CHUNK_STATE_HUGE_ALIGNED);
			DCHECK(chunk->huge_aligned.base == p);
			ret = chunk->huge_aligned.size - (size_t)((char *)p - (char *)chunk);
		} else if (UNLIKELY(chunk->state == CHUNK_STATE_HUGE)) {
			DCHECK(chunk->huge.base == p);
			ret = chunk->huge.size - (size_t)((char *)p - (char *)chunk);
		} else {
			DCHECK(chunk->state == CHUNK_STATE_NORMAL);
			size_t idx = ((uintptr_t)p % CHUNK_SIZE) / HEAPMGR_PAGE_SIZE;
			DCHECK(idx >= META_PAGE_NUM);
			tmp_addr = ptr_to_ulong(chunk);
			tmp_addr += (idx * PAGE_DESC_SIZE);
			page_t *page = ulong_to_ptr(tmp_addr, page_t);

			if (LIKELY(page->state == PAGE_STATE_SMALL)) {
				ret = page->small.size;
			} else {
				ret = large_page_usable_size(page, p);
			}
		}
	}
	
	return ret;
}

WEAK_ALIAS(heapmgr_usable_size, malloc_usable_size);

#if MALLOCOPT_EN
int heapmgr_config(int param, int value)
{
	int ret = 0;

	if (param == M_MMAP_THRESHOLD) {
		/* ignored for compatibility */
		ret = 1;
	} else if (param == M_HEAPMGR_SET_NUM_HEAPS) {
		if ((value > 0) && (value <= HEAP_NUM_MAX)) {
			size_t n = value;
			if (set_num_heaps(n) == 0) {
				ret = 1;
			}
		}
	} else if (param == M_HEAPMGR_SET_NUM_CACHED) {
		if ((value >= 0) && (value <= CACHED_NUM_MAX)) {
			size_t n = value;
			set_num_cached(n);
			ret = 1;
		}
	} else if (param == M_TRIM_THRESHOLD) {
		if (value >= 0) {
			size_t n = value;
			set_trim_threshold(n);
			ret = 1;
		}
	}

	return ret;
}

WEAK_ALIAS(heapmgr_config, mallopt);
#endif

void *heapmgr_memalign(size_t alignment, size_t size)
{
	return heap_aligned_alloc(select_heap(), size, alignment);
}

WEAK_ALIAS(heapmgr_memalign, memalign);
WEAK_ALIAS(heapmgr_memalign, aligned_alloc);
WEAK_ALIAS(heapmgr_memalign, __memalign);

int heapmgr_posix_memalign(void **pp, size_t alignment, size_t size)
{
	int ret = 0;

	if (pp == NULL) {
		ret = EINVAL;
	}
	if ((ret == 0) && (alignment < sizeof(void *))) {
		ret = EINVAL;
	}
	if ((ret == 0) && ((alignment & (alignment - 1UL)) != 0UL)) {
		ret = EINVAL;
	}
	if (ret == 0) {
		void *p = heap_aligned_alloc(select_heap(), size, alignment);
		if ((p == NULL) && (size != 0UL)) {
			ret = ENOMEM;
		} else {
			DCHECK(ptr_aligned(p, alignment));
			*pp = p;
		}
	}

	return ret;
}

WEAK_ALIAS(heapmgr_posix_memalign, posix_memalign);

void *heapmgr_valloc(size_t size)
{
	return heap_aligned_alloc(select_heap(), size, SYSTEM_PAGE_SIZE);
}

WEAK_ALIAS(heapmgr_valloc, valloc);

void *heapmgr_pvalloc(size_t size)
{
	void *ret = NULL;

	if (UNLIKELY(size > (size_t)PTRDIFF_MAX)) {
		/*
		 * Refer to
		 * sourceware.org/ml/libc-announce/2019/msg00001.html
		 */
		heapmgr_set_errno(ENOMEM, __func__, __LINE__);
	} else {
		size = (size + SYSTEM_PAGE_SIZE - 1UL) & ~(SYSTEM_PAGE_SIZE - 1UL);
		ret = heap_aligned_alloc(select_heap(), size, SYSTEM_PAGE_SIZE);
	}

	return ret;
}

WEAK_ALIAS(heapmgr_pvalloc, pvalloc);

static int need_uncommit = 0;

void enable_free_uncommit(void)
{
	need_uncommit = 0x1234;
}

int get_uncommit_flag(void)
{
	return need_uncommit;
}

void heapmgr_shrink(unsigned int flags)
{
	if (need_uncommit)
		return;
	/* reserved for future extension */
	UNUSED(flags);
	heapmgr_mutex_lock(g_heapmgr_set_heaps_lock);
	for (size_t i = 0UL; i < g_heapmgr_num_heaps; ++i) {
		heapmgr_mutex_lock(g_heapmgr_heaps[i]->lock);
		heap_shrink_locked(g_heapmgr_heaps[i]);
		heapmgr_mutex_unlock(g_heapmgr_heaps[i]->lock);
	}
	heapmgr_mutex_unlock(g_heapmgr_set_heaps_lock);
}

void heapmgr_print_state(unsigned int flags, FILE *f)
{
	/* reserved for future extension */
	UNUSED(flags);
	heapmgr_mutex_lock(g_heapmgr_set_heaps_lock);
	for (size_t i = 0UL; i < g_heapmgr_num_heaps; ++i) {
		heapmgr_fprintf(f, "===== Heap #%zu =====\n", i);
		heapmgr_mutex_lock(g_heapmgr_heaps[i]->lock);
		heap_print_state_locked(g_heapmgr_heaps[i], f);
		heapmgr_mutex_unlock(g_heapmgr_heaps[i]->lock);
	}
	heapmgr_mutex_unlock(g_heapmgr_set_heaps_lock);
}

void heapmgr_dump_state(unsigned int flags, heapmgr_state_t *s)
{
	/* reserved for future extension */
	UNUSED(flags);
	s->total = 0UL;
	s->allocated = 0UL;
	s->used = 0UL;
	s->cached = 0UL;
	heapmgr_mutex_lock(g_heapmgr_set_heaps_lock);
	for (size_t i = 0UL; i < g_heapmgr_num_heaps; ++i) {
		heapmgr_mutex_lock(g_heapmgr_heaps[i]->lock);
		heap_dump_state_locked(g_heapmgr_heaps[i], s);
		heapmgr_mutex_unlock(g_heapmgr_heaps[i]->lock);
	}
	heapmgr_mutex_unlock(g_heapmgr_set_heaps_lock);
}

/* called by parent process before fork */
void heapmgr_lock_parent(void)
{
	heapmgr_mutex_lock(g_heapmgr_set_heaps_lock);
	for (size_t i = 0UL; i < g_heapmgr_num_heaps; ++i) {
		heapmgr_mutex_lock(g_heapmgr_heaps[i]->lock);
	}
}

/* called by parent process after fork */
void heapmgr_unlock_parent(void)
{
	for (size_t i = 0UL; i < g_heapmgr_num_heaps; ++i) {
		heapmgr_mutex_unlock(g_heapmgr_heaps[i]->lock);
	}
	heapmgr_mutex_unlock(g_heapmgr_set_heaps_lock);
}

/* called by child process after fork */
void heapmgr_unlock_child(void)
{
	for (size_t i = 0UL; i < g_heapmgr_num_heaps; ++i) {
		heapmgr_mutex_init(g_heapmgr_heaps[i]->lock);
	}
	heapmgr_mutex_init(g_heapmgr_set_heaps_lock);
}

void *heapmgr_malloc_coherent(size_t size)
{
	void *r = NULL;

	if (size == 0)
		return r;

	/* extra CHUNK_DESC_SIZE used to store chunk_t meta data */
	size_t sz = (size + CHUNK_DESC_SIZE + SYSTEM_PAGE_SIZE - 1UL) & ~(SYSTEM_PAGE_SIZE - 1UL);
	chunk_t *c = mmap(NULL, sz + CHUNK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_COHERENT, -1, 0);
	uintptr_t ptr = (uintptr_t)c;
	uintptr_t aligned_ptr = align_up(ptr, CHUNK_SIZE);
	uintptr_t end = aligned_ptr + sz;

	if (c != MAP_FAILED) {
		if (aligned_ptr > ptr) {
			heapmgr_memory_unmap((void *)ptr, aligned_ptr - ptr);
		}
		if (ptr + sz + CHUNK_SIZE > end) {
			heapmgr_memory_unmap((void *)end, ptr + CHUNK_SIZE - aligned_ptr);
		}
	} else {
		heapmgr_fprintf(stderr, "malloc_coherent error\n");
		return NULL;
	}

	DCHECK(ptr_aligned(aligned_ptr, CHUNK_SIZE));
	c = (chunk_t *)aligned_ptr;
	if (c != NULL) {
		c->state = CHUNK_STATE_HUGE;
		c->huge.size = sz;
		c->huge.base = (char *)c + CHUNK_DESC_SIZE;
		r = (void *)c->huge.base;
		__atomic_fetch_add(&g_heapmgr_hugealloc_cnt, 1, __ATOMIC_RELAXED);
		__atomic_fetch_add(&g_heapmgr_hugealloc_size, sz, __ATOMIC_RELAXED);
	} else {
		heapmgr_set_errno(ENOMEM, __func__, __LINE__);
	}

	return r;
}
WEAK_ALIAS(heapmgr_malloc_coherent, malloc_coherent);
