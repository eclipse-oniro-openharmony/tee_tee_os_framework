/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: secure region function of the secure os code h
 * Author: bujing
 * Create: 2020-03-20
 */

#ifndef __SEC_REGION_H__
#define __SEC_REGION_H__

#include <global_ddr_map.h>
#include <sec_region_ops.h>
#include <ddr_sec_feature.h>

/* SUB_RGN_CFG begin */

#define HISI_CMA_START       HISI_RESERVED_DRM_CMA_BASE /* hisi-cma for DRM/TUI/Eid/faceid 2D */
#define HISI_CMA_END         (HISI_CMA_START + HISI_RESERVED_DRM_CMA_SIZE)
#define FACE_CMA_START       HISI_RESERVED_IRIS_CMA_BASE /* 3D faceid sec camera cma */
#define FACE_CMA_END         (FACE_CMA_START + HISI_RESERVED_IRIS_CMA_SIZE)
#define SMEM_CMA_START       HISI_RESERVED_SMEM_CMA_BASE /* hiai sec cma */
#define SMEM_CMA_END         (SMEM_CMA_START + HISI_RESERVED_SMEM_CMA_SIZE)

#define SEC_RGN_ADDR_MASK    0xFFFFULL
#define UNSEC_ADDR           0
#define SEC_ADDR             1
#define ERROR_ADDR           (-2)
#define OK                   0
#define ERROR                (-1)
#define BIT(n)               (1U << (n))

#define SUB_RGN_NUM(rgn_num) (rgn_num - 1)
#define SUB_RGN_FEATURE_MAX     4
#define FACE_3D_TA_FEATURE_NUM  1
#define FACE_3D_FEATURE_NUM     2
#define FACE_2D_FEATURE_NUM     3

#define HIAI_UUID_NUM        0
#define TUI_UUID_NUM         1
#define SEC_ISP_UUID_NUM     2
#define SEC_FACE_UUID_NUM    3
#define SECBOOT_UUID_NUM     4
#define EID1_UUID_NUM        5
#define EID3_UUID_NUM        6
#define ION_UUID_NUM         7
#define VLTMM_UUID_NUM       8
#define LOW_MASK_16BIT       0xffff
#define UUID_INITIALIZER  { 0 }
#define UUID_NOT_GET      0
#define UUID_GET          1
#define TA_STATE_NORMAL   0
#define TA_STATE_CRASHED  1

#define asi_num_bypass(asi_num) ((asi_num) == ASI_NUM_2 || (asi_num) == ASI_NUM_4 || (asi_num) == ASI_NUM_7 || \
				 (asi_num) == ASI_NUM_9 || (asi_num) == ASI_NUM_10 || (asi_num) == ASI_NUM_11 || \
				 (asi_num) == ASI_NUM_14)

struct sub_rgn_cfg {
	enum SEC_FEATURE sec_feature;
	u32 region_num;
	u64 start_addr;
	u64 end_addr;
	u32 granularity_size;
};

struct normal_rgn_cfg {
	enum SEC_FEATURE sec_feature;
	u32 region_num;
	struct sec_rgn_cfg sec_rgn[ASI_NUM_TYPE_MAX];
};

enum {
	RW_FORBID = 0,
	UNSEC_WR = 0x1,
	UNSEC_RD = 0x2,
	SEC_WR = 0x4,
	SEC_RD = 0x8
};

#ifdef DEF_ENG
#define PRINT_DEBUG tloge
#else
#define PRINT_DEBUG tlogi
#endif
#define PRINT_ERROR tloge
#define PRINT_INFO  tlogi

#endif
