/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: called by python. implement video test.
 * Author: SecurityEngine
 * Create: 2020/04/10
 */
#ifndef __HISEE_VIDEO_DFT_H__
#define __HISEE_VIDEO_DFT_H__
#include <pal_types.h>

struct hisee_video_cfg {
	u32 algorithm;
	u32 direction;
	u32 mode;
	u32 padding_type;
	u32 keytype;
	const u8 *pkey;
	u32 keylen;
	const u8 *piv;
	u32 ivlen;
	const u8 *pdin;
	u32 dinlen;
	u8 *pdout;
	u32 *pdoutlen;

	/* video info */
	u32 video_type;
	u32 pattern_ratio;

	/* multi-part */
	u32 *dinlen_array;
	u32 dinlen_array_size;
};

err_bsp_t hisee_video_test(struct hisee_video_cfg *pcfg);

#endif

