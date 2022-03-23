/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: cipher ops
 * Author: SecurityEngine
 * Create: 2020/04/21
 */
#ifndef __HISEE_VIDEO_OPS_H__
#define __HISEE_VIDEO_OPS_H__
#include <pal_types.h>

typedef err_bsp_t (*video_init)(void *pctx, u32 direction, u32 mode, u32 padding_type);
typedef err_bsp_t (*video_set_key)(void *pctx, u32 keytype, const u8 *pkey, u32 keylen);
typedef err_bsp_t (*video_set_iv)(void *pctx, const u8 *piv, u32 ivlen);

struct hisee_video_ops {
	video_init     init;
	video_set_key  set_key;
	video_set_iv   set_iv;
};

const struct hisee_video_ops *hisee_video_get_ops(u32 algorithm);

#endif
