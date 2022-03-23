/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * Description: secure memory service.
 * Create: 2020-03-06
 * Notes:
 * History: 2020-03-06 create
 */

#ifndef __GENALLOC_H_
#define __GENALLOC_H_


struct bitmap {
	u32 bits;
	u32 order;
	u32 *map;
};

struct gen_pool {
	u64 base;
	u32 size;
	u32 min_alloc_order;
	struct bitmap sbitmap;
	u32 avail;
};

#ifndef ALIGN_UP
#define ALIGN_UP(x, align) (((x) + ((align)-1)) & ~((align)-1))
#endif

#ifndef ALIGN
#define ALIGN(x, align) ALIGN_UP(x, align)
#endif

#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, align)  ((x) & ~((align)-1))
#endif


#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x)        ALIGN_UP(x, PAGE_SIZE)
#endif

#ifndef	PAGE_ALIGN_DOWN
#define PAGE_ALIGN_DOWN(x)      ALIGN_DOWN(x, PAGE_SIZE)
#endif

extern s32 bitmap_create(struct bitmap *sbitmap, u32 size, u32 order);
extern void bitmap_destroy(struct bitmap *scharmap);
extern s32 bitmap_find_next_zero_area(struct bitmap *sbitmap, u32 size);
extern void bitmap_set_ll(struct bitmap *sbitmap, u32 start_ibits, u32 size);
extern void bitmap_clear_ll(struct bitmap *sbitmap, u32 start_ibits, u32 size);
extern u32 bitmap_count_ll(struct bitmap *sbitmap);
extern bool bitmap_empty(struct bitmap *sbitmap);

extern struct gen_pool *gen_pool_create(u64 base, u32 size, u32 min_alloc_order);
extern void gen_pool_destory(struct gen_pool *pool);
extern u64 gen_pool_alloc(struct gen_pool *pool, u32 size);
extern void gen_pool_free(struct gen_pool *pool, u64 addr, u32 size);
extern u32 gen_pool_size(struct gen_pool *pool);
extern u32 gen_pool_avail(struct gen_pool *pool);

#endif
