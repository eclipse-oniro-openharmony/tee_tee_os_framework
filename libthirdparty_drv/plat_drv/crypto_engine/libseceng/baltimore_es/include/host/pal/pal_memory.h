/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: heap platform adapter
 * Author     : m00475438
 * Create     : 2019/08/22
 */
#ifndef __PAL_MEMORY_H__
#define __PAL_MEMORY_H__
#include <pal_heap.h>
#include <pal_mem_plat.h>

err_bsp_t pal_mem_equ(const void *_s1, const void *_s2, u32 len);

/**
 * @brief      : free memory
 * @param[in]  : p memory pointer
 * @return     : void
 */
void pal_free(const void *p);

/**
 * @brief      : memory alloc
 * @param[in]  : size    memory size
 * @return     : void *  memory address pointer
 */
void *pal_malloc(u32 size);

/**
 * @brief      : memory alloc and clear to zero
 * @param[in]  : size   memory size
 * @return     : void * memory address pointer
 */
void *pal_calloc(u32 size);

#ifdef FEATURE_ALLOC_TRACE_ENABLE
void pal_mem_trace(int flag, const void *p, const char *func, u32 line);

static inline void __pal_free(const void *p, const char *func, u32 line)
{
	pal_mem_trace(-1, p, func, line);
	pal_free(p);
}

#define pal_free(p) __pal_free(p, __func__, __LINE__)

static inline void *__pal_malloc(u32 size, const char *func, u32 line)
{
	void *p = pal_malloc(size);

	pal_mem_trace(1, p, func, line);
	return p;
}

#define pal_malloc(size) __pal_malloc(size, __func__, __LINE__)

static inline void *__pal_calloc(u32 size, const char *func, u32 line)
{
	void *p = pal_calloc(size);

	pal_mem_trace(1, p, func, line);
	return p;
}

#define pal_calloc(size) __pal_calloc(size, __func__, __LINE__)
#endif /* FEATURE_ALLOC_TRACE_ENABLE */

#ifndef pal_write_u32
#define pal_write_u32(data, addr)  \
	(*((volatile u32 *)PTR(addr)) = (u32)(data))
#endif /* pal_write_u32 */
#ifndef pal_read_u32
#define pal_read_u32(addr)         \
	(*((volatile u32 *)PTR(addr)))
#endif /* pal_read_u32 */

#ifdef FEATURE_PAL_TRACE_ENABLE
#define PAL_TRACE_ADDR_VALID(addr) (PAL_TRUE)
#define PAL_TRACE_ADDR(addr)  (pal_get_trace() && PAL_TRACE_ADDR_VALID(addr))

/* write long */
static inline void __pal_write_u32(u32 data, uintptr_t addr,
				   const char *func, u32 line)
{
	if (PAL_TRACE_ADDR(addr))
		PAL_PRINTF("   --TRACE_REG wl " PAL_FMT_HEX " = " PAL_FMT_HEX
			   " [%s:%d]\n", (u32)addr, data, func, line);
	pal_write_u32(data, addr);
}

#undef pal_write_u32
#define pal_write_u32(data, addr) \
	__pal_write_u32((u32)(data), INTEGER(addr), __func__, __LINE__)

static inline u32 __pal_read_u32(uintptr_t addr, const char *func, u32 line)
{
	u32 data = pal_read_u32(addr);

	if (PAL_TRACE_ADDR(addr)) {
		PAL_PRINTF("   --TRACE_REG rl " PAL_FMT_HEX " = " PAL_FMT_HEX
			   " [%s:%d]\n", (u32)(addr), data, func, line);
	}
	return data;
}

#undef pal_read_u32
#define pal_read_u32(addr) \
	__pal_read_u32(INTEGER(addr), __func__, __LINE__)

#endif  /* end of FEATURE_PAL_TRACE_ENABLE */

#endif /* __PAL_MEMORY_H__ */
