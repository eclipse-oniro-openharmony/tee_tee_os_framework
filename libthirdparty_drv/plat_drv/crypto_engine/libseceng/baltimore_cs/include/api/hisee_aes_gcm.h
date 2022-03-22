/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: aes gcm algorithm interface of api
 * Author: s00294296
 * Create: 2019-07-26
 */
#ifndef __HISEE_AES_GCM_H__
#define __HISEE_AES_GCM_H__
#include <common_sce.h>

#define AES_GCM_USER_CTX_SIZE_IN_WORDS     64

struct hisee_aes_gcm_user_ctx {
	u32 buff[AES_GCM_USER_CTX_SIZE_IN_WORDS];
};

struct hisee_aes_gcm_ctx {
	u32 direction;
	u32 aadlen;
	u32 payload_len;
	u32 keylen;
	u8  key[SYMM_KEYLEN_32];
	u8  aes_ghash_iv[SYMM_IVLEN_AES];
	u8  aes_gctr_iv[SYMM_IVLEN_AES];
	u8  buf[SYMM_BLKLEN_AES];
	u32 blen;
};

err_bsp_t hisee_aes_gcm_init(struct hisee_aes_gcm_user_ctx *pctx,
			     u32 direction, const u8 *pkey, u32 keylen,
			     const u8 *pivin, u32 ivinlen);

err_bsp_t hisee_aes_gcm_aad_update(struct hisee_aes_gcm_user_ctx *pctx,
				   const u8 *paad, u32 aad_len);

err_bsp_t hisee_aes_gcm_dofinal(struct hisee_aes_gcm_user_ctx *pctx,
				const u8 *payload, u32 payload_len, u8 *pdout,
				u32 *doutlen, u8 *ptag, u32 *ptaglen);

err_bsp_t hisee_aes_gmac_init(struct hisee_aes_gcm_user_ctx *pctx,
			      const u8 *pkey, u32 keylen,
			      const u8 *pivin, u32 ivinlen);

err_bsp_t hisee_aes_gmac_dofinal(struct hisee_aes_gcm_user_ctx *pctx,
				 const u8 *paad, u32 aadlen,
				 u8 *ptag, u32 *ptaglen);
#endif

