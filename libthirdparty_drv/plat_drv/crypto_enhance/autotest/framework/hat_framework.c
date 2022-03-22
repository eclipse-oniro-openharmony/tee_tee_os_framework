/****************************************************************************//**
 * @file   hat_framework.c
 * @brief
 * @par    Copyright (c) 2017-2033, HUAWEI Technology Co., Ltd.
 * @date   2018/08/20
 * @author L00265041
 * @note
 *
********************************************************************************/
#include <pal_libc.h>
#include <pal_timer.h>
#include <common_utils.h>
#include "hat_framework.h"


/*===============================================================================
 *                               types/macros                                  *
===============================================================================*/
#define NTLV_FRAME_MIN_LENGTH_IN_BYTES  1
#define NTLV_FRAME_DEFAULT_LENGTH_IN_BYTES  4
#define MAJOR_NTLV_FRAME_NAME "HISEEAT"

#define RAM_SPACE_OVERHEAD_IN_BYTES  0x1000

/*support 20 parameters now, need do attention please*/
#define FUNC_IN_PARAMS_NUMBER_MAX  20
#define FUNC_STRU_POINTER_NUMBER_MAX  20

/**
 * @brief return when express is established
*/
#define HAT_CHECK_RETURN(express, ret, fmt, ...) do { \
	if (express) { \
		HAT_ERROR(fmt, ##__VA_ARGS__); \
		return ret; \
	} \
} while (0)

#define SET_IN_PARAMS_ERR_RETURN(value) do { \
	if (FUNC_IN_PARAMS_NUMBER_MAX <= g_autotest_channel.in_param_count) { \
		HAT_ERROR("in_param = %d reach the maximum\n", g_autotest_channel.in_param_count);\
		return SE_RET_ERR; \
	} \
	g_autotest_channel.in_param_array[g_autotest_channel.in_param_count++] = (u32)(value); \
} while (0)

#define BAK_STRU_PVALUES_ERR_RETURN(value) do { \
	if (FUNC_STRU_POINTER_NUMBER_MAX <= g_autotest_channel.stru_point_count) { \
		HAT_ERROR("in_param = %d reach the maximum\n", g_autotest_channel.stru_point_count);\
		return (u32)(SE_RET_ERR); \
	} \
	g_autotest_channel.stru_point_values[g_autotest_channel.stru_point_count++] = (u32)(value); \
} while (0)


#define CHECK_U32_LEN_ERR_RETURN(len) do { \
	if (sizeof(u32) != len) { \
		HAT_ERROR("u32 length check failed for %d!\n", len); \
		return SE_RET_ERR; \
	} \
} while (0)

#define CHECK_BUF_LEN_ERR_RETURN(len) do { \
	if (NTLV_FRAME_MIN_LENGTH_IN_BYTES > len) { \
		HAT_ERROR("buf length check failed for %d!\n", len); \
		return SE_RET_ERR; \
	} \
} while (0)

#define NTLV_TYPE_IS_STRUCT(type) ((NTLV_TYPE_IN_STRU_PTR == (type)) || (NTLV_TYPE_IO_STRU_PTR == type))
#define NTLV_TYPE_IS_POINTER(type) ( \
	NTLV_TYPE_IS_STRUCT(type) \
	|| (NTLV_TYPE_IO_U32 == (type)) \
	|| (NTLV_TYPE_OUT_U32 == (type)) \
	|| (NTLV_TYPE_IN_POINTER == (type)) \
	|| (NTLV_TYPE_IO_POINTER == (type)) \
	|| (NTLV_TYPE_OUT_POINTER == (type)) \
	)

#define FRAME_LEN_IS_VALID(frame, size) ((sizeof(se_ntlv_struct) < (size)) \
										&& ((sizeof(se_ntlv_struct) + ((se_ntlv_struct *)(frame))->tag_length) <= (size)))

#define GOTO_NEXT_FRAME(frame, size) do { \
	u32 __frm_len = (sizeof(se_ntlv_struct) + \
			((se_ntlv_struct *)(frame))->tag_length); \
	size -= __frm_len; \
	frame = (se_ntlv_struct *)((u8 *)(frame) + __frm_len); \
} while (0)

#define CHECK_FRAME_LEN_ERR_RETURN(pframe, frm_size) do { \
	if (!FRAME_LEN_IS_VALID(pframe, size)) { \
		void *__pfrm_types = &((se_ntlv_struct *)(pframe))->tag_type_s; \
		HAT_ERROR("[%s:%d] frame type = "PAL_FMT_PTR", len = %d, size = %d check failed!\n", __FUNCTION__, __LINE__\
				, *((u32 *)__pfrm_types), ((se_ntlv_struct *)(pframe))->tag_length, frm_size); \
		return SE_RET_ERR; \
	} \
} while (0)

#define GOTO_NEXT_FRAME_ERR_RETURN(frame, size) do { \
	GOTO_NEXT_FRAME(frame, size); \
	CHECK_FRAME_LEN_ERR_RETURN(frame, size); \
} while (0)

typedef s32 (*FUNC_PTR) (u32, ...);

typedef enum {
	NTLV_TYPE_SYSTEM_BEGIN = 1,
	NTLV_TYPE_PC2HISEE = 1,
	NTLV_TYPE_HISEE2PC = 2,

	NTLV_TYPE_FUNCTION_ADDR = 3,

	NTLV_TYPE_RETURN_U32 = 4,
	NTLV_TYPE_RETURN_BUFFER = 5,
	NTLV_TYPE_RETURN_VOID = 6,

	NTLV_TYPE_IN_U32 = 7, /*origin*/
	NTLV_TYPE_IO_U32 = 8, /*add,support now*/
	NTLV_TYPE_OUT_U32 = 9, /*add,support now*/

	NTLV_TYPE_IN_BUFFER = 10, /*origin*/
	NTLV_TYPE_IO_BUFFER = 11, /*origin*/
	NTLV_TYPE_OUT_BUFFER = 12, /*origin*/
	NTLV_TYPE_NULL_BUFFER = 13, /*add, supprot now*/

	NTLV_TYPE_IN_STRU_PTR = 14,   /*add, supprot now*/
	NTLV_TYPE_IO_STRU_PTR = 15,   /*add, supprot now*/

	NTLV_TYPE_IN_POINTER = 16,
	NTLV_TYPE_IO_POINTER = 17,
	NTLV_TYPE_OUT_POINTER = 18,

	NTLV_TYPE_TMP_BUFFER = 19,   /* template buffer for function *//* ION buffer for SCE outbuffer */

	NTLV_TYPE_USER_BEGIN = 0x1001,
	NTLV_TYPE_VALUE_MAX  = 0xFFFF
} se_ntlv_type;

typedef enum {
	NTLV_OPT_ADDR_CNV = 0, /* address convert to another */
	NTLV_OPT_MEMORY_CNV,   /* memory convert to another */
	NTLV_OPT_MEMORY_CNV2ION,/* bit[2]:memory convert to ION word-align */
	NTLV_OPT_MEMORY_CNV2CMA,/* bit[3]:memory convert to CMA word-align */
	NTLV_OPT_MEMORY_CNV2ION_NONALIGN, /* bit[4]:memory convert to ION non-align */
	NTLV_OPT_MEMORY_CNT2CMA_NONALIGN, /* bit[5]:memory convert to CMA non-align */
} se_ntlv_option;

typedef struct ntlv_struct_value_stru{
	u16 offset;
	u16 len;
} ntlv_struct_value_s;

typedef struct ntlv_struct_tl_stru{
	ntlv_struct_type_s type_s;
	u32 len;
} ntlv_struct_tl_s;

typedef struct ntlv_struct_head_stru{
	u16 tl_len;
	u16 stru_len;
	u8 ptl[0]; /*lint !e43*/
} ntlv_struct_head_s;

typedef struct {
	/*invoking functoion addr*/
	u32 function_addr;
	const char *function_name;

	/* frame */
	u8 *pframe_end;
	s32 remain_buf_len;

	/*invoking function parameters, from left to rigth*/
	u32 in_param_count;
	u32 in_param_array[FUNC_IN_PARAMS_NUMBER_MAX];

	u32 stru_point_count;
	u32 stru_point_values[FUNC_STRU_POINTER_NUMBER_MAX];
} se_autotest_channel_struct;


typedef struct {
	ntlv_struct_type_s type_s;
	u32 *addr;
	u32 length;
} se_ntlv_pool_item_struct;

typedef struct {
	u32 ddr_size;
	u32 ddr_used;
	void *ddr_pool;
	u32 ccm_size;
	u32 ccm_used;
	void *ccm_pool;
} se_ntlv_pool_struct;

typedef struct {
	u32 loop_times;
} hat_framework_struct;

/*===========================================================================
 *                      global objects                                     *
===========================================================================*/
static se_autotest_channel_struct g_autotest_channel;
static hat_framework_struct g_autotest_config;

static struct {
	u32 flag;
	u32 ion_total_size;
	u32 ion_used_size;
	u32 ion_iova_base;
	u32 ion_virt_base;
	u32 orig_addr;
	u32 orig_size;
} g_ion_pool_mgr;

static struct {
	u32 flag;
	u32 cma_total_size;
	u32 cma_used_size;
	u32 cma_phys_base;
	uintptr_t cma_virt_base;
	u32 orig_addr;
	u32 orig_size;
} g_cma_pool_mgr;

void dump_ion_pool()
{
	PAL_ERROR("flag=%d\n", g_ion_pool_mgr.flag);
	PAL_ERROR("total_size=%d\n", g_ion_pool_mgr.ion_total_size);
	PAL_ERROR("used_size=%d\n", g_ion_pool_mgr.ion_used_size);
	PAL_ERROR("iova_base=%x\n", g_ion_pool_mgr.ion_iova_base);
	PAL_ERROR("va_base=%x\n", g_ion_pool_mgr.ion_virt_base);
	PAL_ERROR("orig_addr=%x\n", g_ion_pool_mgr.orig_addr);
	PAL_ERROR("orig_size=%x\n", g_ion_pool_mgr.orig_size);
}

void dump_cma_pool()
{
	PAL_ERROR("flag=%d\n", g_cma_pool_mgr.flag);
	PAL_ERROR("total_size=%d\n", g_cma_pool_mgr.cma_total_size);
	PAL_ERROR("used_size=%d\n", g_cma_pool_mgr.cma_used_size);
	PAL_ERROR("pa_base=%x\n", g_cma_pool_mgr.cma_phys_base);
	PAL_ERROR("va_base=%x\n", g_cma_pool_mgr.cma_virt_base);
	PAL_ERROR("orig_addr=%x\n", g_cma_pool_mgr.orig_addr);
	PAL_ERROR("orig_size=%x\n", g_cma_pool_mgr.orig_size);
}

/****************************************************************************//**
 * @brief      : hat_ion_pool_init
 *               initialize ION pool, which is malloc by CA-TA, we dont care about that
 * @param[in]  : ion_iova
 *               IOVA, (mapped by SMMU)
 * @param[in]  : ion_va
 *               VA, (mapped by MMU)
 * @param[in]  : size
 *******************************************************************************/
void hat_ion_pool_init(u32 ion_iova, u32 ion_va, u32 size)
{
	g_ion_pool_mgr.flag           = 0;
	g_ion_pool_mgr.ion_total_size = size;
	g_ion_pool_mgr.ion_used_size  = 0;
	g_ion_pool_mgr.ion_iova_base  = ion_iova;
	g_ion_pool_mgr.ion_virt_base  = ion_va;
}

/****************************************************************************//**
 * @brief      : hat_cma_pool_init
 *               initialize CMA pool, which is malloc by CA-TA, we dont care about that
 * @param[in]  : cma_va
 *               VA, (mapped by MMU)
 * @param[in]  : cma_pa
 *               physical address
 * @param[in]  : size
 *******************************************************************************/
void hat_cma_pool_init(uintptr_t cma_va, u32 cma_pa, u32 size)
{
	g_cma_pool_mgr.flag           = 0;
	g_cma_pool_mgr.cma_total_size = size;
	g_cma_pool_mgr.cma_used_size  = 0;
	g_cma_pool_mgr.cma_phys_base  = cma_pa;
	g_cma_pool_mgr.cma_virt_base  = cma_va;
}

/*===========================================================================
 *                      functions                                          *
===========================================================================*/
/*
 *检查传入ntlv frame是否valid，返回true表示valid，返回false表示invalid
 *@frame：输入参数，指向一个ntlv frame的首地址
 */
PRIVATE s32 change_frame_buf_len(se_ntlv_struct *frame, u32 buf_len)
{
	errno_t libc_ret = EINVAL;
	u8 *next_frame = (u8 *)&frame->tag_value[0] + frame->tag_length;
	s32 len = (s32)(buf_len - frame->tag_length);

	/* no need move */
	if (0 >= len) {
		return SE_RET_OK;
	}

	/* left or right move */
	HAT_CHECK_RETURN((g_autotest_channel.remain_buf_len < len), SE_RET_ERR
		, "out buffer too long for offset = %d, remain = %d\n", len, g_autotest_channel.remain_buf_len);

	if (next_frame < g_autotest_channel.pframe_end) {
		libc_ret = memmove_s((next_frame + len),
				     (g_autotest_channel.pframe_end - next_frame),
				     next_frame,
				     (g_autotest_channel.pframe_end - next_frame));
		PAL_CHECK_RETURN((EOK != libc_ret), SE_RET_ERR);
	}
	frame->tag_length = buf_len;
	g_autotest_channel.remain_buf_len -= len;
	g_autotest_channel.pframe_end += len;
	return SE_RET_OK;
}

/****************************************************************************//**
 * @brief      : parse buffer address to real addr by type options
 * @param[in]  : tag_type type of parameter
 * @param[in]  : addr     preallocated buffer address
 * @param[in]  : len      buffer length
 * @return     : ::u32    real address, error when eque 0
 * @note       :
********************************************************************************/
PRIVATE u32 ntlv_parse_buf_addr(ntlv_struct_type_s tag_type_s, uintptr_t addr, u32 len)
{
	errno_t libc_ret = EINVAL;
	/* if ION used */
	if (BIT_CHK(tag_type_s.opts, NTLV_OPT_MEMORY_CNV2ION) ||
			BIT_CHK(tag_type_s.opts, NTLV_OPT_MEMORY_CNV2ION_NONALIGN)) {
		/* NOTE: only SCE pdout can be this type */
		if (len > (g_ion_pool_mgr.ion_total_size - g_ion_pool_mgr.ion_used_size)) {
			PAL_ERROR("not enough ion\n");
			return 0;
		}

		/* 1. set ion flag, indicates ion is used */
		g_ion_pool_mgr.flag = NTLV_OPT_MEMORY_CNV2ION;

		/* 2. backup original addr */
		g_ion_pool_mgr.orig_addr = addr;
		g_ion_pool_mgr.orig_size = len;

		/* 3. update ion pool */
		g_ion_pool_mgr.ion_used_size = len;

		if (BIT_CHK(tag_type_s.opts, NTLV_OPT_MEMORY_CNV2ION_NONALIGN)) {
			g_ion_pool_mgr.ion_iova_base += 1;
			g_ion_pool_mgr.ion_virt_base += 1;
		}

		PAL_ERROR("ION used\n");
		dump_ion_pool();
		PAL_DUMP("ION value:", g_ion_pool_mgr.ion_virt_base, 16, 0);

		/* if align, use IOVA else non-algin, use VA */
		return ((g_ion_pool_mgr.ion_iova_base % sizeof(u32)) == 0) ? g_ion_pool_mgr.ion_iova_base : g_ion_pool_mgr.ion_virt_base;
	}

	/* if CMA used */
	if (BIT_CHK(tag_type_s.opts, NTLV_OPT_MEMORY_CNV2CMA) ||
			BIT_CHK(tag_type_s.opts, NTLV_OPT_MEMORY_CNT2CMA_NONALIGN)) {
		if (len > (g_cma_pool_mgr.cma_total_size - g_cma_pool_mgr.cma_used_size)) {
			PAL_ERROR("not enough ion\n");
			return 0;
		}

		g_cma_pool_mgr.flag          = NTLV_OPT_MEMORY_CNV2CMA;
		g_cma_pool_mgr.orig_addr     = addr;
		g_cma_pool_mgr.orig_size     = len;
		g_cma_pool_mgr.cma_used_size = len;

		if (BIT_CHK(tag_type_s.opts, NTLV_OPT_MEMORY_CNT2CMA_NONALIGN)) {
			g_cma_pool_mgr.cma_virt_base += 1;
			g_cma_pool_mgr.cma_phys_base += 1;
		}

		/* copy original data to CMA */
		libc_ret = memcpy_s((void *)g_cma_pool_mgr.cma_virt_base,
				    g_cma_pool_mgr.cma_total_size -
				    g_cma_pool_mgr.cma_used_size,
				    (void *)addr, len);
		PAL_CHECK_RETURN((EOK != libc_ret), SE_RET_ERR);

		PAL_ERROR("CMA used\n");
		dump_cma_pool();
		PAL_DUMP("CMA value:", g_cma_pool_mgr.cma_virt_base, 16, 0);

		return (u32)g_cma_pool_mgr.cma_virt_base;
	}

	return addr;
}

PRIVATE void ntlv_post_buf_addr()
{
	errno_t libc_ret = EINVAL;

	if (NTLV_OPT_MEMORY_CNV2ION == g_ion_pool_mgr.flag) {
		/* 1. copy result to original addr from ION addr */
		libc_ret = memcpy_s((void *)(uintptr_t)g_ion_pool_mgr.orig_addr,
				    g_ion_pool_mgr.orig_size,
				    (void *)g_ion_pool_mgr.ion_virt_base,
				    g_ion_pool_mgr.orig_size);
		if (EOK != libc_ret) {
			PAL_ERROR("libc_ret = "PAL_FMT_PTR"\n", libc_ret);
			return;
		}

		/* 2. clear ion flag */
		g_ion_pool_mgr.flag = ~NTLV_OPT_MEMORY_CNV2ION;

		/* 3. update ion pool, release ion */
		g_ion_pool_mgr.ion_used_size = 0;
		PAL_ERROR("ION release\n");
		PAL_DUMP("ION result:", g_ion_pool_mgr.ion_virt_base, 16, 0);
	}

	if (NTLV_OPT_MEMORY_CNV2CMA == g_cma_pool_mgr.flag) {
		/* 1. dont copy result, CMA can only be input */

		/* 2. clear cma flag */
		g_cma_pool_mgr.flag = ~NTLV_OPT_MEMORY_CNV2CMA;

		/* 3. update cma pool, release cma */
		g_cma_pool_mgr.cma_used_size = 0;
		PAL_ERROR("CMA release\n");
	}
}

/*
 *在prepare阶段，解析函数返回值的特定frame
 *@frame：输入参数，指向一个ntlv frame的首地址
 *@frame_len：输入参数，一帧的长度
 */
PRIVATE u32 ntlv_parse_one_struct(ntlv_struct_head_s *pheader_s, u32 len)
{
	ntlv_struct_tl_s *ptl_s = NULL;
	u8 *pstru = pheader_s->ptl + pheader_s->tl_len;
	u8 *pbuffer = pstru + pheader_s->stru_len;
	u8 *pmember = pstru;
	void *ptl_types = NULL;
	ntlv_struct_value_s *pvalue_s = NULL;
	for (ptl_s = (ntlv_struct_tl_s *)pheader_s->ptl; ptl_s < (ntlv_struct_tl_s *)pstru; ptl_s++) {
		ptl_types = &ptl_s->type_s;
		HAT_CHECK_RETURN((pbuffer < pmember + ptl_s->len), 0
			, "err struct type = "PAL_FMT_PTR" len = "PAL_FMT_PTR"\n", *((u32 *)ptl_types), ptl_s->len);

		if (NTLV_TYPE_IS_POINTER(ptl_s->type_s.type)) {
			pvalue_s = (ntlv_struct_value_s *)pmember;
			HAT_CHECK_RETURN(((sizeof(u32) != ptl_s->len)
				|| (((u8 *)pheader_s + len) < pbuffer + pvalue_s->offset + pvalue_s->len)), 0
				, "err struct type = "PAL_FMT_PTR" len = "PAL_FMT_PTR"\n", *((u32 *)ptl_types), ptl_s->len);

			BAK_STRU_PVALUES_ERR_RETURN(*((u32 *)pmember));
			if (NTLV_TYPE_IS_STRUCT(ptl_s->type_s.type)) {
				*((u32 *)pmember) = ntlv_parse_one_struct((ntlv_struct_head_s *)&pbuffer[pvalue_s->offset], pvalue_s->len);
			} else {
				*((u32 *)pmember) = ntlv_parse_buf_addr(ptl_s->type_s, (uintptr_t)&pbuffer[pvalue_s->offset], pvalue_s->len);
			}
			HAT_CHECK_RETURN((0 == *((u32 *)pmember)), 0
					, "parse struct failed! type = "PAL_FMT_PTR" len = "PAL_FMT_PTR"\n", *((u32 *)ptl_types), pvalue_s->len);
		}
		pmember += ptl_s->len;
	}
	return (u32)(uintptr_t)(pheader_s->ptl + pheader_s->tl_len);
}

PRIVATE u32 ntlv_repair_one_struct(ntlv_struct_head_s *pheader_s, u32 len, u32 *pbaks, u32 baklen)
{
	ntlv_struct_tl_s *ptl_s = NULL;
	u8 *pstru = pheader_s->ptl + pheader_s->tl_len;
	u8 *pbuffer = pstru + pheader_s->stru_len;
	u8 *pmember = pstru;
	ntlv_struct_value_s *pvalue_s = NULL;
	u32 idx = 0;

	for (ptl_s = (ntlv_struct_tl_s *)pheader_s->ptl; ptl_s < (ntlv_struct_tl_s *)pstru; ptl_s++) {
		if ((baklen <= idx) || (pbuffer < pmember + ptl_s->len)) {
			break;
		}
		if (NTLV_TYPE_IS_POINTER(ptl_s->type_s.type)) {
			*((u32 *)pmember) = pbaks[idx++];
			pvalue_s = (ntlv_struct_value_s *)pmember;
			if ((baklen <= idx) || (sizeof(u32) != ptl_s->len)
				|| (((u8 *)pheader_s + len) < pbuffer + pvalue_s->offset + pvalue_s->len)) {
				break;
			}
			if (NTLV_TYPE_IS_STRUCT(ptl_s->type_s.type)) {
				idx += ntlv_repair_one_struct((ntlv_struct_head_s *)&pbuffer[pvalue_s->offset]
					, pvalue_s->len, &pbaks[idx], baklen - idx);
			}
		}
		pmember += ptl_s->len;
	}
	return idx;
}

PRIVATE u32 ntlv_post_struct(se_ntlv_struct *frame, u32 size, u32 *pbaks, u32 baklen)
{
	u32 idx = 0;

	if (0 == baklen) {
		return idx;
	}

	while (FRAME_LEN_IS_VALID(frame, size)) {
		if (NTLV_TYPE_IS_STRUCT(frame->tag_type_s.type)) {
			idx += ntlv_repair_one_struct((ntlv_struct_head_s *)frame->tag_value
										, frame->tag_length, &pbaks[idx], baklen - idx);
			if (baklen <= idx) {
				break;
			}
		}
		/* next ntlv frame */
		GOTO_NEXT_FRAME(frame, size);
	}
	return idx;
}

PRIVATE s32 ntlv_parse_parameters(se_ntlv_struct *frame, u32 size)
{
	s32 ret;
	u32 tag_value;
	while (FRAME_LEN_IS_VALID(frame, size)) {
		switch (frame->tag_type_s.type) {
		case NTLV_TYPE_NULL_BUFFER:
			frame->tag_value[0] = 0;
			CHECK_U32_LEN_ERR_RETURN(frame->tag_length);
			SET_IN_PARAMS_ERR_RETURN(frame->tag_value[0]);
			break;
		case NTLV_TYPE_IN_U32:
			CHECK_U32_LEN_ERR_RETURN(frame->tag_length);
			SET_IN_PARAMS_ERR_RETURN(frame->tag_value[0]);
			break;
		case NTLV_TYPE_IO_U32:
		case NTLV_TYPE_OUT_U32:
			CHECK_U32_LEN_ERR_RETURN(frame->tag_length);
			SET_IN_PARAMS_ERR_RETURN((u32)frame->tag_value);
			break;

		/* buffer处理相同，out buffer需要申请空间 */
		case NTLV_TYPE_OUT_BUFFER:
		case NTLV_TYPE_OUT_POINTER:
			CHECK_U32_LEN_ERR_RETURN(frame->tag_length);
			ret = change_frame_buf_len(frame, frame->tag_value[0]);
			HAT_CHECK_RETURN((SE_RET_OK != ret), ret, "\n");
			size = (u32)g_autotest_channel.pframe_end - (u32)frame;
			CHECK_BUF_LEN_ERR_RETURN(frame->tag_length);
			tag_value = ntlv_parse_buf_addr(frame->tag_type_s, (uintptr_t)frame->tag_value, frame->tag_length);
			HAT_CHECK_RETURN((0 == tag_value), SE_RET_ERR, "parse buffer addr failed\n");
			SET_IN_PARAMS_ERR_RETURN(tag_value);
			break;
		case NTLV_TYPE_IN_BUFFER:
		case NTLV_TYPE_IO_BUFFER:
		case NTLV_TYPE_IN_POINTER:
		case NTLV_TYPE_IO_POINTER:
			CHECK_BUF_LEN_ERR_RETURN(frame->tag_length);
			tag_value = ntlv_parse_buf_addr(frame->tag_type_s, (uintptr_t)frame->tag_value, frame->tag_length);
			HAT_CHECK_RETURN((0 == tag_value), SE_RET_ERR, "parse buffer addr failed\n");
			SET_IN_PARAMS_ERR_RETURN(tag_value);
			break;
		case NTLV_TYPE_TMP_BUFFER:
			CHECK_U32_LEN_ERR_RETURN(frame->tag_length);
			tag_value = ntlv_parse_buf_addr(frame->tag_type_s, 0, frame->tag_value[0]);
			HAT_CHECK_RETURN((0 == tag_value), SE_RET_ERR, "parse buffer addr failed\n");
			SET_IN_PARAMS_ERR_RETURN(tag_value);
			break;
		case NTLV_TYPE_IN_STRU_PTR:
		case NTLV_TYPE_IO_STRU_PTR:
			ret = (s32)ntlv_parse_one_struct((ntlv_struct_head_s *)frame->tag_value, frame->tag_length);
			HAT_CHECK_RETURN((0 == ret), SE_RET_ERR
				, "parse struct '%s' failed! frame len = %d\n",  frame->tag_name, frame->tag_length);
			SET_IN_PARAMS_ERR_RETURN(ret);
			break;
		default:
			HAT_ERROR("unsupport frame type = %d, opts = %d\n", frame->tag_type_s.type, frame->tag_type_s.opts);
			return SE_RET_ERR;
		}

		GOTO_NEXT_FRAME(frame, size);
	}
	return SE_RET_OK;
}

s32 ntlv_parse_func_addr(se_ntlv_struct *frame, u32 size)
{
	u32 len = 0;
	void *pfrm_types = &frame->tag_type_s;

	CHECK_FRAME_LEN_ERR_RETURN(frame, size);
	HAT_CHECK_RETURN(((NTLV_TYPE_FUNCTION_ADDR != frame->tag_type_s.type) || (0 == frame->tag_value[0])), SE_RET_ERR
		, "second ntlv error, type = "PAL_FMT_PTR" value = "PAL_FMT_PTR"!\n", *((u32 *)pfrm_types), frame->tag_value[0]);

	/* function name */
	g_autotest_channel.function_name = (char *)frame->tag_value;
	len = pal_strnlen((char *)frame->tag_value, frame->tag_length);
	if ((0 == len) || (frame->tag_length <= len)) {
		PAL_RAWDATA("error function", (char *)frame->tag_value, frame->tag_length);
		return SE_RET_ERR;
	}

	g_autotest_channel.function_addr = hat_get_func_addr((s8 *)frame->tag_value, len + 1);
	HAT_CHECK_RETURN((0 == g_autotest_channel.function_addr), SE_RET_ERR
		, "list no match func '%s'\n", (const char *)frame->tag_value);
	return SE_RET_OK;
}

s32 ntlv_parse_frame(se_ntlv_struct *frame, u32 size)
{
	s32 ret = SE_RET_ERR;

	/* the second ntlv frame must be function_addr */
	ret = ntlv_parse_func_addr(frame, size);
	if (SE_RET_OK != ret) {
		return ret;
	}

	/* point to the next ntlv frame:function_return frame */
	GOTO_NEXT_FRAME_ERR_RETURN(frame, size);
	switch (frame->tag_type_s.type) {
	case NTLV_TYPE_RETURN_VOID:
	case NTLV_TYPE_RETURN_U32:
		CHECK_U32_LEN_ERR_RETURN(frame->tag_length);
		ret = SE_RET_OK;
		break;
	case NTLV_TYPE_RETURN_BUFFER:
		CHECK_BUF_LEN_ERR_RETURN(frame->tag_length);
		ret = change_frame_buf_len(frame, frame->tag_value[0]);
		HAT_CHECK_RETURN((SE_RET_OK != ret), ret, "\n");
		size = (u32)(uintptr_t)g_autotest_channel.pframe_end - (u32)frame;
		break;
	default:
		HAT_ERROR("the thrid ntlv must be return but type = %d failed!\n", frame->tag_type_s.type);
		return SE_RET_ERR;
	}

	/* prepare parameters */
	GOTO_NEXT_FRAME(frame, size);
	if (FRAME_LEN_IS_VALID(frame, size)) {
		ret = ntlv_parse_parameters(frame, size);
		if (SE_RET_OK != ret) {
			(void)ntlv_post_struct(frame, size
								, g_autotest_channel.stru_point_values
								, g_autotest_channel.stru_point_count);
		}
	}
	return ret;
}

PRIVATE s32 ntlv_call_function(u32 *cost_time)
{
	s32 ret;
	u32 begin;
	u32 end;
	u32 run_counter = 0;
	FUNC_PTR func_ptr = (FUNC_PTR)(uintptr_t)(g_autotest_channel.function_addr);
	u32 *argv = g_autotest_channel.in_param_array;

	HAT_INFO("func=%s, with para ", g_autotest_channel.function_name);
	PAL_PRINTF(PAL_LOG_INFO, "("PAL_FMT_PTR", "PAL_FMT_PTR", "PAL_FMT_PTR", "PAL_FMT_PTR", "PAL_FMT_PTR", "PAL_FMT_PTR")\n",
		argv[0], argv[1], argv[2], argv[3], argv[4], argv[5]);

	do {
		begin = pal_timer_value();
		ret = func_ptr(argv[0], argv[1], argv[2], argv[3], argv[4]
							, argv[5], argv[6], argv[7], argv[8], argv[9]
							, argv[10], argv[11], argv[12], argv[13], argv[14]
							, argv[15], argv[16], argv[17], argv[18], argv[19]);
		end = pal_timer_value();
		run_counter++;
		if (1 < run_counter) {
			HAT_INFO("run_counter = %d\n", run_counter);
		}
	} while (run_counter < g_autotest_config.loop_times);

	g_autotest_config.loop_times = 0;
	run_counter = (u32)pal_tick2us(PAL_TIMER_INTERVAL(end, begin));
	HAT_INFO("ret="PAL_FMT_PTR", cost = %dus\n", ret, run_counter);
	if (NULL != cost_time) {
		*cost_time = run_counter;
	}
	return ret;
}

PRIVATE void ntlv_post_parameters(se_ntlv_struct *frame, u32 size)
{
	u32 ret_libc;
	se_ntlv_struct *cur_frame = frame;
	while (FRAME_LEN_IS_VALID(frame, size)) {
		switch (frame->tag_type_s.type) {
		case NTLV_TYPE_IO_U32:
		case NTLV_TYPE_OUT_U32:
		case NTLV_TYPE_IO_BUFFER:
		case NTLV_TYPE_OUT_BUFFER:
		case NTLV_TYPE_IO_STRU_PTR:
			if (cur_frame != frame) {
				ret_libc = memmove_s(cur_frame, size, frame, size);
				if (EOK != ret_libc)
					HAT_INFO("ERROR:ret_libc=%d\n", ret_libc);
				frame = cur_frame;
			}
			cur_frame = (se_ntlv_struct *)((uintptr_t)(frame + 1) + frame->tag_length);
			break;
		default:
			break;
		}

		GOTO_NEXT_FRAME(frame, size);
	}
	g_autotest_channel.pframe_end = (u8 *)cur_frame;
}


void ntlv_post_frame(se_ntlv_struct *frame, u32 size, u32 function_ret)
{
	errno_t libc_ret = EINVAL;
	/* the second ntlv frame is function_addr,goto next */
	GOTO_NEXT_FRAME(frame, size);

	/* the thrid ntlv frame is return */
	switch (frame->tag_type_s.type) {
	case NTLV_TYPE_RETURN_U32:
		frame->tag_value[0] = function_ret;
		break;
	case NTLV_TYPE_RETURN_BUFFER:
		libc_ret = memmove_s((void *)&frame->tag_value[0],
				        frame->tag_length,
				        (void *)function_ret,
				        frame->tag_length);
		if (libc_ret != EOK) {
			PAL_ERROR("errno = "PAL_FMT_PTR"\n", libc_ret);
			return;
		}
		break;
	default:
		break;
	}
	GOTO_NEXT_FRAME(frame, size);

	/* next ntlv frame is parameters, repair struct */
	(void)ntlv_post_struct(frame, size
						, g_autotest_channel.stru_point_values
						, g_autotest_channel.stru_point_count);
	/* out parameters */
	ntlv_post_parameters(frame, size);
}

void hat_set_call_loop(u32 times)
{
	g_autotest_config.loop_times = times;
	HAT_ERROR("loop_times = %d\n", g_autotest_config.loop_times);
}

/* @data pointer the major NTLV frame,
 * @size the length major NTLV frame
*/
s32 autotest_framework_case(u8 *data, u32 size, u32 *cost_time)
{
	se_ntlv_struct *major_ntlv_frame;
	s32 ret;
	u32 function_ret;

	/* check */
	major_ntlv_frame = (se_ntlv_struct *)(u32)data;
	if ((NTLV_TYPE_PC2HISEE != major_ntlv_frame->tag_type_s.type)
		|| (size < (major_ntlv_frame->tag_length + sizeof(se_ntlv_struct)))
		|| (0 != pal_strncmp(major_ntlv_frame->tag_name, MAJOR_NTLV_FRAME_NAME, sizeof(major_ntlv_frame->tag_name)))) {
		HAT_ERROR("ntlv head does not match, name = %s, type = %d, size = %d, tag_len = %d\n"
			, major_ntlv_frame->tag_name, major_ntlv_frame->tag_type_s.type, size, major_ntlv_frame->tag_length);
		return SE_RET_ERR;
	}

	/* prepare */
	(void)memset_s((void *)&g_autotest_channel, sizeof(g_autotest_channel), 0, sizeof(g_autotest_channel));
	g_autotest_channel.pframe_end = (u8 *)major_ntlv_frame->tag_value + major_ntlv_frame->tag_length;
	g_autotest_channel.remain_buf_len = &data[size] - g_autotest_channel.pframe_end;
	major_ntlv_frame->tag_type_s.type = NTLV_TYPE_HISEE2PC;
	ret = ntlv_parse_frame((se_ntlv_struct *)(uintptr_t)&major_ntlv_frame->tag_value[0], major_ntlv_frame->tag_length);
	major_ntlv_frame->tag_length = g_autotest_channel.pframe_end - (u8 *)major_ntlv_frame->tag_value;
	HAT_CHECK_RETURN((SE_RET_OK != ret), ret, "ntlv_parse_frame fail,ret="PAL_FMT_PTR"\n", ret);

	/* call function */
	function_ret = (u32)ntlv_call_function(cost_time);

	/* post */
	ntlv_post_buf_addr();
	ntlv_post_frame((se_ntlv_struct *)(uintptr_t)(u32)(uintptr_t)&major_ntlv_frame->tag_value[0], major_ntlv_frame->tag_length, function_ret);
	major_ntlv_frame->tag_length = g_autotest_channel.pframe_end - (u8 *)major_ntlv_frame->tag_value;
	return ret;
}
