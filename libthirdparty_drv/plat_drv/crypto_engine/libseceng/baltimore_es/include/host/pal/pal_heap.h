/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: heap platform adapter
 * Author     : m00475438
 * Create     : 2019/08/22
 */
#ifndef __PAL_HEAP_H__
#define __PAL_HEAP_H__
#include <common_define.h>
#include <pal_log.h>

/**
 * @brief heap memory link note
 */
struct pal_heap_cb {
	struct pal_heap_cb *next;  /* next link note */
	u32                len;    /* data length of current note */
};

#ifdef FEATURE_PAL_HEAP_SUPPORTED
/**
 * @brief      : initialize heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 */
err_bsp_t pal_heap_init(void *pool, u32 size);

/**
 * @brief      : allocate heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 * @param[in]  : len allocated buffer length
 * @return     : allocated buffer pointer
 */
void *pal_heap_alloc(void *pool, u32 size, u32 len);

/**
 * @brief      : free allocated heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 * @param[in]  : buf allocated buffer
 */
err_bsp_t pal_heap_free(void *pool, u32 size, const void *buf);

#endif /* FEATURE_PAL_HEAP_SUPPORTED */

#ifdef FEATURE_ALLOC_TRACE_ENABLE
/**
 * @brief      : pal_mem_trace
 * @param[in]  : flag -1: free; 1: malloc/calloc
 * @param[in]  : p    buffer pointer
 * @param[in]  : func function name
 * @param[in]  : line code file line
 */
void pal_heap_trace(int flag, const void *p, const char *func, u32 line);
#endif /* FEATURE_ALLOC_TRACE_ENABLE */

#endif /* __PAL_HEAP_H__ */
