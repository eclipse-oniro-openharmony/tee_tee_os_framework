/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cma/ion manager
 * Author: SecurityEngine
 * Create: 2020/04/10
 */
#include <hisee_video_cmaion_mgr.h>
#include <pal_log.h>

struct cma_info {
	u32 cma_va;
	u32 cma_pa;
	u32 cma_size;
};

struct ion_info {
	u32 buffer_id;
	u32 ion_iova;
	u32 ion_va;
	u32 ion_size;
};

static struct cma_info g_video_cma_pool;
static struct ion_info g_video_ion_pool;

/*
 * cma_size: bytes size
 */
void hisee_video_cma_init(u32 cma_va, u32 cma_pa, u32 cma_size)
{
	g_video_cma_pool.cma_va   = cma_va;
	g_video_cma_pool.cma_pa   = cma_pa;
	g_video_cma_pool.cma_size = cma_size;
}

void hisee_video_ion_init(u32 buffer_id, u32 ion_iova, u32 ion_va, u32 ion_size)
{
	g_video_ion_pool.buffer_id = buffer_id;
	g_video_ion_pool.ion_iova  = ion_iova;
	g_video_ion_pool.ion_va    = ion_va;
	g_video_ion_pool.ion_size  = ion_size;
}

void hisee_video_get_cma(u32 *cma_va, u32 *cma_pa, u32 *cma_size)
{
	if (cma_va)
		*cma_va = g_video_cma_pool.cma_va;
	if (cma_pa)
		*cma_pa = g_video_cma_pool.cma_pa;
	if (cma_size)
		*cma_size = g_video_cma_pool.cma_size;
}

void hisee_video_get_ion(u32 *buffer_id, u32 *ion_iova, u32 *ion_va, u32 *ion_size)
{
	if (buffer_id)
		*buffer_id = g_video_ion_pool.buffer_id;
	if (ion_va)
		*ion_va = g_video_ion_pool.ion_va;
	if (ion_iova)
		*ion_iova = g_video_ion_pool.ion_iova;
	if (ion_size)
		*ion_size = g_video_ion_pool.ion_size;
}

void hisee_video_show_cmaion(void)
{
	PAL_ERROR("cma:va=%x,pa=%x,size=%x\n",
		  g_video_cma_pool.cma_va,
		  g_video_cma_pool.cma_pa,
		  g_video_cma_pool.cma_size);

	PAL_ERROR("ion:buff_id=%d,va=%x,iova=%x,size=%x\n",
		  g_video_ion_pool.buffer_id,
		  g_video_ion_pool.ion_va,
		  g_video_ion_pool.ion_iova,
		  g_video_ion_pool.ion_size);
}
