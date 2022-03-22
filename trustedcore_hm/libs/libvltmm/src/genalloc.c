#include "sre_typedef.h"
#include "list.h"
#include "genalloc.h"
#include "securec.h"
#include "tee_log.h"
#include "tee_common.h"
#include "tee_internal_api.h"

/**
 * 's' means simple, also means that it's in SecOS
 */
struct gen_pool *gen_pool_create(u64 base, u32 size, u32 min_alloc_order)
{
	struct gen_pool *pool = NULL;

	pool = TEE_Malloc(sizeof(*pool), 0);
	if (pool) {
		pool->min_alloc_order = min_alloc_order;
		pool->base = base;
		pool->avail = size;
		pool->size = size;
		tlogd("%s %x\n", __func__, min_alloc_order);
		if (bitmap_create(&pool->sbitmap, size, min_alloc_order)) {
			tloge("bitmap_create failed\n");
			TEE_Free(pool);
			return NULL;
		}
		tlogd("%s %d\n", __func__, min_alloc_order);
	}
	return pool;
}

void gen_pool_destory(struct gen_pool *pool)
{
	bitmap_destroy(&pool->sbitmap);
	TEE_Free(pool);
}

u64 gen_pool_alloc(struct gen_pool *pool, u32 size)
{
	s32 nr = 0;

	tlogd(" %s size = 0x%x\n", __func__, size);
	if (!size)
		return 0;

	nr = bitmap_find_next_zero_area(&pool->sbitmap, size);
	if (nr == -1) {
		tloge(" %s nr = -1\n", __func__);
		return 0;
	}

	bitmap_set_ll(&pool->sbitmap, nr, size);

	if (pool->avail >= size)
		pool->avail -= size;

	tlogd("nr %s  = 0x%x\n", __func__, nr);

	return (u64)(((u64)nr << pool->min_alloc_order) + pool->base);
}

void gen_pool_free(struct gen_pool *pool, u64 addr, u32 size)
{
	u32 nr = 0;

	nr = (u32)((addr - pool->base) >> pool->min_alloc_order);

	bitmap_clear_ll(&pool->sbitmap, nr, size);

	if (pool->avail <= pool->size - size)
		pool->avail += size;
}

u32 gen_pool_size(struct gen_pool *pool)
{
	u32 count = 0;

	count = bitmap_count_ll(&pool->sbitmap);
	return count << pool->min_alloc_order;
}

u32 gen_pool_avail(struct gen_pool *pool)
{
	return pool->avail;
}
