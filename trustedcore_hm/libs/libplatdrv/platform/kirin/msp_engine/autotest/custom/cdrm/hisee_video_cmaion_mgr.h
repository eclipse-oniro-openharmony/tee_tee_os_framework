/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cma/ion manager
 * Author: SecurityEngine
 * Create: 2020/04/10
 */
#ifndef __HISEE_VIDEO_CMAION_MGR_H__
#define __HISEE_VIDEO_CMAION_MGR_H__
#include <pal_types.h>

void hisee_video_cma_init(u32 cma_va, u32 cma_pa, u32 cma_size);
void hisee_video_ion_init(u32 buffer_id, u32 ion_iova, u32 ion_va, u32 ion_size);

void hisee_video_get_cma(u32 *cma_va, u32 *cma_pa, u32 *cma_size);
void hisee_video_get_ion(u32 *buffer_id, u32 *ion_iova, u32 *ion_va, u32 *ion_size);

void hisee_video_show_cmaion(void);

#endif
