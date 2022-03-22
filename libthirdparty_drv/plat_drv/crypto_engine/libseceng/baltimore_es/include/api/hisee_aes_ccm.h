/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: aes ccm algorithm interface of api
 * Author: s00294296
 * Create: 2019-07-26
 */
#ifndef __HISEE_AES_CCM_H__
#define __HISEE_AES_CCM_H__
#include <common_sce.h>

#define AES_CCM_USER_CTX_SIZE_IN_WORDS  64

struct hisee_aes_ccm_user_ctx {
	u32 buff[AES_CCM_USER_CTX_SIZE_IN_WORDS];
};

struct hisee_aes_ccm_ctx {
	u32  direction;
	u32  keylen;
	u8   key[SYMM_KEYLEN_32];
	u8   aes_cbc_mac_iv[SYMM_IVLEN_AES];
	u8   aes_ctr_iv[SYMM_IVLEN_AES];
	u8   buf[SYMM_BLKLEN_AES]; /* data unprocessed */
	u32  blen; /* unprocessed data length in buf */
	/* additional param for dofinal */
	u32  payload_len;
	u32  aadlen;
	u32  taglen;
	u32  nonce_len;
	u8   nonce[SYMM_BLKLEN_AES];
};

err_bsp_t hisee_aes_ccm_init(struct hisee_aes_ccm_user_ctx *pctx, u32 direction,
			     const u8 *pkey, u32 keylen,
			     u32 addlen, u32 payload_len,
			     const u8 *pnonce, u32 nonce_len, u32 taglen);

err_bsp_t hisee_aes_ccm_aad_update(struct hisee_aes_ccm_user_ctx *pctx,
				   const u8 *paad, u32 aadlen);

err_bsp_t hisee_aes_ccm_dofinal(struct hisee_aes_ccm_user_ctx *pctx,
				const u8 *payload, u32 payload_len, u8 *pdout,
				u32 *doutlen, u8 *ptag, u32 *ptaglen);

#endif

