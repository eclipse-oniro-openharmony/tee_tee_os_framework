/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: sm4 algorithm interface of api
 * Author: s00294296
 * Create: 2019-07-26
 */
#ifndef __HISEE_SM4_H__
#define __HISEE_SM4_H__
#include <common_sce.h>

#define SM4_USER_CTX_SIZE_IN_WORDS        64

struct hisee_sm4_user_ctx {
	u32 buff[SM4_USER_CTX_SIZE_IN_WORDS];
};

err_bsp_t hisee_sm4_set_key(struct hisee_sm4_user_ctx *pctx,
			    u32 keytype, const u8 *pkey, u32 keylen);

err_bsp_t hisee_sm4_set_iv(struct hisee_sm4_user_ctx *pctx,
			   const u8 *piv, u32 ivlen);

err_bsp_t hisee_sm4_init(struct hisee_sm4_user_ctx *pctx,
			 u32 direction, u32 mode,
			 u32 padding_type);

err_bsp_t hisee_sm4_update(struct hisee_sm4_user_ctx *pctx,
			   const u8 *pdin, u32 dinlen,
			   u8 *pdout, u32 *pdoutlen);

err_bsp_t hisee_sm4_dofinal(struct hisee_sm4_user_ctx *pctx,
			    const u8 *pdin, u32 dinlen,
			    u8 *pdout, u32 *pdoutlen);

#endif

