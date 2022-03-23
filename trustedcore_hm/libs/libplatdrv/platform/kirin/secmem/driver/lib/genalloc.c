#include "list.h"
#include "legacy_mem_ext.h"
#include "drv_module.h"
#include "secmem.h"
#include "secmem_priv.h"
#include "sre_log.h"
#include "mem_ops.h"
#include "mem_page_ops.h"
#include "sre_typedef.h"

/**
 * 's' means simple, also means that it's in SecOS
 */
struct gen_pool *gen_pool_create(u32 base, u32 size, u32 min_alloc_order)
{
	struct gen_pool *pool = NULL;

	pool = SRE_MemAlloc(OS_MID_SYS, OS_MEM_DEFAULT_FSC_PT, sizeof(*pool));
	if (pool) {
		pool->min_alloc_order = min_alloc_order;
		pool->base = base;
		tlogd("%s %x\n", __func__, min_alloc_order);
		if (bitmap_create(&pool->sbitmap, size, min_alloc_order)) {
			tloge("bitmap_create failed\n");
			SRE_MemFree(OS_MID_SYS, pool);
			return NULL;
		}
		tlogd("%s %d\n", __func__, min_alloc_order);
	}
	return pool;
}

void gen_pool_destory(struct gen_pool *pool)
{
	bitmap_destroy(&pool->sbitmap);
	SRE_MemFree(OS_MID_SYS, pool);
}

u32 gen_pool_alloc(struct gen_pool *pool, u32 size)
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

	tlogd("nr %s  = 0x%x\n", __func__, nr);

	return (u32)(((u32)nr << pool->min_alloc_order) + pool->base);
}

void gen_pool_free(struct gen_pool *pool, u32 addr, u32 size)
{
	u32 nr = 0;

	nr = (addr - pool->base) >> pool->min_alloc_order;

	bitmap_clear_ll(&pool->sbitmap, nr, size);
}

u32 gen_pool_size(struct gen_pool *pool)
{
	u32 count = 0;

	count = bitmap_count_ll(&pool->sbitmap);
	return count << pool->min_alloc_order;
}
