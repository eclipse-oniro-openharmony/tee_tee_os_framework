/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implement for cipher ops
 * Author: SecurityEngine
 * Create: 2020/04/21
 */
#include "hisee_video_ops.h"
#include <common_utils.h>
#include <hisee_aes.h>
#include <hisee_sm4.h>

static s32 hisee_return_error_func(void *v1, void *v2, void *v3, void *v4, void *v5)
{
	UNUSED(v1);
	UNUSED(v2);
	UNUSED(v3);
	UNUSED(v4);
	UNUSED(v5);
	return -1;
}

static const struct hisee_video_ops g_hisee_video_ops_aes = {
	.init     = (video_init)hisee_aes_init,
	.set_key  = (video_set_key)hisee_aes_set_key,
	.set_iv   = (video_set_iv)hisee_aes_set_iv,
};

static const struct hisee_video_ops g_hisee_video_ops_sm4 = {
	.init     = (video_init)hisee_sm4_init,
	.set_key  = (video_set_key)hisee_sm4_set_key,
	.set_iv   = (video_set_iv)hisee_sm4_set_iv,
};

static const struct hisee_video_ops g_hisee_video_ops_default = {
	.init     = (video_init)hisee_return_error_func,
	.set_key  = (video_set_key)hisee_return_error_func,
	.set_iv   = (video_set_iv)hisee_return_error_func,
};

const struct hisee_video_ops *hisee_video_get_ops(u32 algorithm)
{
	switch (algorithm) {
	case SYMM_ALGORITHM_AES:
		return &g_hisee_video_ops_aes;
	case SYMM_ALGORITHM_SM4:
		return &g_hisee_video_ops_sm4;
	default:
		return &g_hisee_video_ops_default;
	}
}

