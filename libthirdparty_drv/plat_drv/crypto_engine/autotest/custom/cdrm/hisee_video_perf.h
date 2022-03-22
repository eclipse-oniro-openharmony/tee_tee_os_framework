/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: for perf test
 * Author: SecurityEngine
 * Create: 2020/04/10
 */
#ifndef __HISEE_VIDEO_PERF_H__
#define __HISEE_VIDEO_PERF_H__
#include <pal_types.h>
#include <common_sce.h>

err_bsp_t hisee_video_perf_test(u32 video_type, u32 algorithm, u32 dinlen, u32 *timecostus);

#endif

