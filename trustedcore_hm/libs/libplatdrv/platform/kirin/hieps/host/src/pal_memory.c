/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: memory manager
 * Author: m00475438
 * Create: 2018-12-19
 */

#include <pal_memory.h>
#include <pal_libc.h>
#include <common_utils.h>
#include <eps_ddr_layout_define.h>

#define BSP_THIS_MODULE BSP_MODULE_SYS

/* check whether heap memory is valid */
#define PAL_HEAP_CHECK_VALID(psearch, pool, size) (                                         \
		((psearch)->next) && ((psearch) < ((psearch)->next)) &&                     \
		(((u8 *)(psearch)->next) < (((u8 *)(pool)) + (size))) &&                    \
		((u32)((u8 *)(psearch)->next - (u8 *)(psearch)) >= (psearch)->len)          \
	)

u32 pal_get_video_buf(u32 *psize)
{
	if (psize)
		*psize = HIEPS_DDR_VIDEO_SIZE;

	return HIEPS_DDR_VIDEO_BASE_ADDR;
}

/*
 * @brief      : initialize heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 */
err_bsp_t pal_heap_init(void *pool, u32 size)
{
	PAL_HEAP_CB_ST *ptr = NULL;

	PAL_CHECK_RETURN((!pool) || (sizeof(PAL_HEAP_CB_ST) >= size), ERR_DRV(ERRCODE_PARAMS));
	(void)memset_s(pool, size, 0, size);
	ptr = (PAL_HEAP_CB_ST *)pool;
	ptr->next = (PAL_HEAP_CB_ST *)((u8 *)pool + size - sizeof(PAL_HEAP_CB_ST *));
	ptr->next->next = NULL;
	ptr->len = 0;
	return BSP_RET_OK;
}

/*
 * @brief      : allocate heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 * @param[in]  : len allocated buffer length
 * @return     : allocated buffer pointer
 */
void *pal_heap_alloc(void *pool, u32 size, u32 len)
{
	PAL_HEAP_CB_ST *p = NULL;
	PAL_HEAP_CB_ST *p_search = (PAL_HEAP_CB_ST *)pool;
	u8 *pbuf = NULL;

	PAL_CHECK_RETURN((!pool) || (len == 0), NULL);

	len = BIT_ALIGN(len + sizeof(PAL_HEAP_CB_ST), 2); /* word align (2 ^ 2 bytes align) */
	/* seek valid heap memory */
	while (PAL_HEAP_CHECK_VALID(p_search, pool, size)) {
		if ((u32)((u8 *)p_search->next - (u8 *)p_search - p_search->len) >= len)
			break;
		p_search = p_search->next;
	}

	/* allocate heap memory */
	if (PAL_HEAP_CHECK_VALID(p_search, pool, size)) {
		if (p_search->len != 0) {
			/* add new node */
			p = (PAL_HEAP_CB_ST *)((u8 *)p_search + p_search->len);
			p->next = p_search->next;
			p_search->next = p;
			p_search = p;
		}
		p_search->len = len;
		pbuf = ((u8 *)p_search) + sizeof(PAL_HEAP_CB_ST);
	}

	if ((!pbuf) && (p_search->next)) {
		PAL_ERROR("mem over pool:" PAL_FMT_PTR ",size:%u,p:" PAL_FMT_PTR ",p->next:" PAL_FMT_PTR ", len:%u\n",
			  INTEGER(pool), size, INTEGER(p_search), INTEGER(p_search->next), p_search->len);
	}
	return (pbuf);
}

/*
 * @brief      : free allocated heap memory
 * @param[in]  : pool buffer pool pointer
 * @param[in]  : size buffer pool size
 * @param[in]  : buf allocated buffer
 * @return     : ::NULL  successful
 *               NO_NULL failed
 */
err_bsp_t pal_heap_free(void *pool, u32 size, void *buf)
{
	PAL_HEAP_CB_ST *p_search = NULL;
	PAL_HEAP_CB_ST *p = NULL;

	PAL_CHECK_RETURN(((!pool) || (!buf) || (size <= sizeof(PAL_HEAP_CB_ST))), ERR_DRV(ERRCODE_PARAMS));
	PAL_CHECK_RETURN((((u8 *)buf < ((u8 *)pool + sizeof(PAL_HEAP_CB_ST))) ||
			  ((u8 *)buf >= ((u8 *)pool + size - sizeof(PAL_HEAP_CB_ST)))), ERR_DRV(ERRCODE_MEMORY));
	p_search = (PAL_HEAP_CB_ST *)pool;
	p = (PAL_HEAP_CB_ST *)((u8 *)buf - sizeof(PAL_HEAP_CB_ST));

	if (p_search == p) {
		buf = NULL;
		p_search->len = 0;
	} else {
		/* middle heap note */
		while (PAL_HEAP_CHECK_VALID(p_search, pool, size)) {
			if (p_search->next == p) {
				buf = NULL;
				p_search->next = p->next;
				break;
			}
			p_search = p_search->next;
		}
	}
	if (buf) {
		PAL_WARN("mem = " PAL_FMT_PTR " FREE Failed!\n", INTEGER(buf));
		if ((p_search->next) && !PAL_HEAP_CHECK_VALID(p_search, pool, size)) {
			PAL_ERROR("pool:" PAL_FMT_PTR ",size:%u,p:" PAL_FMT_PTR ",p->next:" PAL_FMT_PTR ",len:%u\n",
				  INTEGER(pool), size, INTEGER(p_search), INTEGER(p_search->next), p_search->len);
			return ERR_DRV(ERRCODE_VERIFY);
		} else {
			return ERR_DRV(ERRCODE_INVALID);
		}
	}
	return BSP_RET_OK;
}

#ifdef FEATURE_ALLOC_TRACE_ENABLE
/*
 * @brief      : pal_mem_trace
 * @param[in]  : flag -1: free; 1: malloc/calloc
 * @param[in]  : p buffer pointer
 * @param[in]  : func function name
 * @param[in]  : line code file line
 */
void pal_heap_trace(int flag, const void *p, const char *func, u32 line)
{
	static s32 s_heap_max_size;
	static s32 s_heap_left_size;
	static s32 s_heap_left_count;
	const PAL_HEAP_CB_ST *pblock = {0};

	if (!p || !func) {
		PAL_PRINTF(PAL_LOG_INFO, "param p or func is NULL\n");
		return;
	}
	pblock = (const PAL_HEAP_CB_ST *)((const u8 *)p - sizeof(PAL_HEAP_CB_ST));
	s_heap_left_count += flag;
	s_heap_left_size += flag * pblock->len;

	/* debug */
	if (flag < 0) {
		PAL_PRINTF(PAL_LOG_INFO, "[%s:%d]: free = " PAL_FMT_PTR ", size = %u\n", func, line, p, pblock->len);
	} else {
		PAL_PRINTF(PAL_LOG_INFO, "[%s:%d]: alloc = " PAL_FMT_PTR ", size = %u\n", func, line, p, pblock->len);
		if (s_heap_max_size < s_heap_left_size) {
			s_heap_max_size = s_heap_left_size;
			PAL_PRINTF(PAL_LOG_INFO, "heap max = %d, count = %d\n", s_heap_max_size, s_heap_left_count);
		}
	}
}
#endif /* FEATURE_ALLOC_TRACE_ENABLE */

