/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: memory manager for test
 * Author     : m00475438
 * Create     : 2019/08/09
 */
#ifndef __HAT_MEMORY_H__
#define __HAT_MEMORY_H__
#include <hat_mem_plat.h>
#include <pal_heap.h>
#include <hat_framework.h>
#include <common_utils.h>

/**
 * @brief      : test memory alloc
 * @param[in]  : type test memory type for enum ::hat_mem_type
 * @param[in]  : size test memory bytes size
 */
void *hat_alloc(u32 type, u32 size);

/**
 * @brief      : test memory free
 * @param[in]  : type test memory type for enum ::hat_mem_type
 * @param[in]  : p    test memory pointer
 */
void hat_free(u32 type, const void *p);

/* ----------- test memory manager ----------- */
struct hat_mem_item {
	const char *name;
	u8         flag;
	u8         type;
	u16        opts;
	u32        size;
	u8         *pool;
};

#define HAT_MEM_ITEM(m_name, m_type, m_opts, m_pool, m_size) {\
	.name = m_name, \
	.type = m_type, \
	.opts = m_opts, \
	.size = m_size, \
	.pool = (u8 *)PTR(m_pool), \
}

const struct hat_mem_item *hat_mem_get_item(u32 is_opt, u32 t);
struct hat_mem_item *hat_mem_lookup(u32 is_opt, u32 t,
				    u32 size, struct hat_mem_item *items);

/* for hava autotest */
#ifdef FEATURE_HAT_HAVA_SUPPORTED
u8 *hat_buf_addr_parse(struct hat_type type, u8 *p, u32 len);
void hat_buf_addr_post(void);
#endif /* FEATURE_HAT_HAVA_SUPPORTED */

/* -----------  test memory maintenance ----------- */
#ifdef FEATURE_HAT_ALLOC_TRACE_ENABLE
static inline void __hat_free(u32 type, const void *p,
			      const char *func, u32 line)
{
	pal_heap_trace(-1, p, func, line);
	hat_free(type, p);
}

#define hat_free(t, p) __hat_free(t, p, __func__, __LINE__)

static inline void *__hat_alloc(u32 type, u32 size,
				const char *func, u32 line)
{
	void *p = hat_alloc(type, size);

	pal_heap_trace(1, p, func, line);
	return p;
}

#define hat_alloc(t, s) __hat_alloc(t, s, __func__, __LINE__)

#endif /* FEATURE_HAT_ALLOC_TRACE_ENABLE */

#endif /* __HAT_MEMORY_H__ */
