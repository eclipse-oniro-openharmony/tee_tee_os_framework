/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: define types
 *              platform-dependent types is defined in pal_memreg_plat.h
 *              platform-independent types is defined in pal_memory.h
 * Author     : l00370476
 * Cretae     : 2018/08/10
 */

#ifndef __PAL_MEMORY_H__
#define __PAL_MEMORY_H__
#include <pal_log.h>

/*
 * @brief heap memory link note
 */
typedef struct _PAL_HEAP_CB_ {
	struct _PAL_HEAP_CB_  *next;        /* next link note */
	unsigned int           len;         /* data length of current note */
} PAL_HEAP_CB_ST;

u32 pal_get_video_buf(u32 *psize);

/*
 * @brief      : initialize heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 */
err_bsp_t pal_heap_init(void *pool, unsigned int size);

/*
 * @brief      : allocate heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 * @param[in]  : len allocated buffer length
 * @return     : allocated buffer pointer
 */
void *pal_heap_alloc(void *pool, unsigned int size, unsigned int len);

/*
 * @brief      : free allocated heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 * @param[in]  : buf allocated buffer
 */
err_bsp_t pal_heap_free(void *pool, unsigned int size, void *buf);

#ifdef FEATURE_ALLOC_TRACE_ENABLE
/*
 * @brief      : pal_mem_trace
 * @param[in]  : flag -1: free; 1: malloc/calloc
 * @param[in]  : p    buffer pointer
 * @param[in]  : func function name
 * @param[in]  : line code file line
 */
void pal_heap_trace(int flag, const void *p, const char *func, u32 line);
#endif /* FEATURE_ALLOC_TRACE_ENABLE */

#ifndef pal_write_u32
#define pal_write_u32(data, addr)      (*((volatile u32 *)(uintptr_t)(addr)) = (u32)(data))
#endif /* pal_write_u32 */
#ifndef pal_read_u32
#define pal_read_u32(addr)             (*((volatile u32 *)(uintptr_t)(addr)))
#endif /* pal_read_u32 */

#endif /*__PAL_MEMORY_H__*/
