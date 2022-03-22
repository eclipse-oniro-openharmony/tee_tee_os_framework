/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: called by python. implement video test.
 * Author: SecurityEngine
 * Create: 2020/04/10
 */
#include <hisee_video_perf.h>
#include <hisee_video.h>
#include <hisee_video_cmaion_mgr.h>
#include <common_sce.h>
#include <common_utils.h>
#include <pal_types.h>
#include <pal_log.h>
#include <pal_libc.h>
#include <pal_timer.h>

#define BSP_THIS_MODULE            BSP_MODULE_SCE

enum hisee_video_perf_idx {
	VIDEO_PERF_IDX_INIT = 0,
	VIDEO_PERF_IDX_DOFINAL,
	VIDEO_PERF_IDX_DEINIT,
	VIDEO_PERF_IDX_MAX,
};

PRIVATE u8 g_video_perf_key[SYMM_KEYLEN_16];
PRIVATE u8 g_video_perf_iv[SYMM_IVLEN_AES];
PRIVATE u8 *g_video_perf_pdin = NULL;
PRIVATE u32 g_video_perf_dinlen;
PRIVATE u8 *g_video_perf_pdout = NULL;
PRIVATE u32 g_video_perf_doutlen;

PRIVATE void hisee_video_print_timecost(u32 *timecost, u32 size)
{
	u32 i;

	for (i = 0; i < size; i++)
		PAL_ERROR("i=%d, timecost=%d\n", i, timecost[i]);
}

PRIVATE u32 hisee_video_get_pattern_outlen(u32 dinlen)
{
	u32 leftlen = dinlen % SYMM_BLKLEN_AES;
	u32 m;

	m = (PATTERN_1_9_CIPHERLEN + PATTERN_1_9_PLAINLEN) / SYMM_BLKLEN_AES;
	return (dinlen - leftlen) * m + leftlen;
}

PRIVATE err_bsp_t hisee_video_set_perf_param(struct hisee_video_init_param *param,
					     u32 video_type, u32 algorithm,
					     u32 dinlen)
{
	u32 cma_va;
	u32 cma_size;
	u32 buffer_id;
	u32 ion_size;
	u32 ion_va;
	u32 ion_iova;

	param->algorithm     = algorithm;
	param->direction     = SYMM_DIRECTION_DECRYPT;
	param->mode          = SYMM_MODE_CBC;
	param->padding_type  = 0;
	param->keytype       = SYMM_KEYTYPE_USER;
	param->keylen        = sizeof(g_video_perf_key);
	param->ivlen         = sizeof(g_video_perf_iv);
	param->pkey          = g_video_perf_key;
	param->piv           = g_video_perf_iv;

	hisee_video_get_ion(&buffer_id, &ion_iova, &ion_va, &ion_size);
	param->video_type    = video_type;
	param->pattern_ratio = HISEE_VIDEO_PATTERN_RATION_1_9;
	param->buffer_id     = buffer_id;
	param->size          = ion_size;
	param->outva_base    = (u8 *)(uintptr_t)ion_va;

	hisee_video_get_cma(&cma_va, NULL, &cma_size);

	g_video_perf_pdin = (u8 *)(uintptr_t)cma_va;
	g_video_perf_dinlen = dinlen;

	g_video_perf_pdout = (u8 *)(uintptr_t)ion_va;
	if (video_type == HISEE_VIDEO_TYPE_PATTERN)
		g_video_perf_doutlen = hisee_video_get_pattern_outlen(dinlen);
	else
		g_video_perf_doutlen = dinlen;

	if (g_video_perf_doutlen > ion_size) {
		PAL_ERROR("dinlen is %d, outlen is %d, too long!\n",
			  dinlen, g_video_perf_doutlen);
		return ERR_API(ERRCODE_PARAMS);
	}

	return BSP_RET_OK;
}

err_bsp_t hisee_video_perf_test(u32 video_type, u32 algorithm, u32 dinlen, u32 *timecostus)
{
	err_bsp_t ret;
	struct hisee_video_init_param init_param;
	struct hisee_video_ctx ctx;
	u32 timecost[VIDEO_PERF_IDX_MAX];
	u32 begin = 0;
	u32 end = 0;
	u32 doutlen;

	if (video_type == HISEE_VIDEO_TYPE_PATTERN)
		PAL_ERROR("video_type=pattern, dinlen=%d\n", dinlen);
	if (video_type == HISEE_VIDEO_TYPE_NOPATTERN)
		PAL_ERROR("video_type=non-pattern, dinlen=%d\n", dinlen);

	ret = hisee_video_set_perf_param(&init_param, video_type, algorithm, dinlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/* record init timecost */
	begin = (u32)pal_timer_value();
	ret = hisee_video_init(&ctx, &init_param);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	end = (u32)pal_timer_value();
	timecost[VIDEO_PERF_IDX_INIT] = end - begin;

	/* record dofinal timecost */
	begin = (u32)pal_timer_value();
	doutlen = g_video_perf_doutlen;
	ret = hisee_video_dofinal(&ctx, g_video_perf_pdin, g_video_perf_dinlen,
				  g_video_perf_pdout, &doutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end;
	end = (u32)pal_timer_value();
	timecost[VIDEO_PERF_IDX_DOFINAL] = end - begin;

end:
	(void)hisee_video_deinit(&ctx);

	*timecostus = timecost[VIDEO_PERF_IDX_DOFINAL];

	hisee_video_print_timecost(timecost, ARRAY_SIZE(timecost));

	return ret;
}

