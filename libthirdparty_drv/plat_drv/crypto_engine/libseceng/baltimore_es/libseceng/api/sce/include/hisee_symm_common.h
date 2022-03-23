/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * Description: common symm algotirhm interface
 * Author: s00294296
 * Create: 2019-07-26
 */
#ifndef __HISEE_SYMM_COMMON_H__
#define __HISEE_SYMM_COMMON_H__
#include <common_sce.h>

#define AES_KENLEN_CHECK(keylen)  ((keylen) != SYMM_KEYLEN_16 && \
				   (keylen) != SYMM_KEYLEN_24 && \
				   (keylen) != SYMM_KEYLEN_32)

/* max key len of XTS mode is 64B */
#define SYMM_CTX_KEY_SIZE         SYMM_KEYLEN_64
#define SYMM_CTX_IV_SIZE          SYMM_IVLEN_AES
#define SYMM_CTX_BUF_SIZE         SYMM_BLKLEN_AES

struct hisee_symm_user_ctx {
	u32  algorithm;
	u32  direction;
	u32  mode;
	u32  keytype;
	u32  klen; /* key length */
	u32  padding_type;
	u32  blen; /* unprocessed data length */
	u32  blklen;
	u8   key[SYMM_CTX_KEY_SIZE];
	u8   iv[SYMM_CTX_IV_SIZE];
	u8   buf[SYMM_CTX_BUF_SIZE]; /* unprocessed data buffer */
};

#ifdef FEATURE_USER_MEMORY_TRUSTED
	#define hisee_symm_ctx hisee_symm_user_ctx

	err_bsp_t hisee_symm_ctx_usr2sys(
		struct hisee_symm_ctx *psymm_ctx,
		struct hisee_symm_user_ctx *psymm_user_ctx);

	#define HISEE_SYMM_CTX_USR2SYS(pret, ppsymm_ctx, pctx) do { \
		*(pret) = hisee_symm_ctx_usr2sys(NULL, \
			(struct hisee_symm_user_ctx *)(pctx)); \
		if (*(pret) == BSP_RET_OK) \
			*(ppsymm_ctx) = (struct hisee_symm_ctx *)(pctx); \
	} while (0)

	#define HISEE_SYMM_CTX_SYS2USR(pret, pctx, psymm_ctx) do { \
		u32 __ret_ok = BSP_RET_OK; \
		*(pret) = __ret_ok; \
	} while (0)
#else
	struct hisee_symm_ctx {
		u32  algorithm;
		u32  direction;
		u32  mode;
		u32  keytype;
		u32  klen; /* key length */
		u32  padding_type;
		u32  blen; /* unprocessed data length */
		u32  blklen;
		u8  *key;
		u8  *iv;
		u8  *buf; /* unprocessed data buffer point */
	};

	err_bsp_t hisee_symm_ctx_usr2sys(
		struct hisee_symm_ctx *psymm_ctx,
		struct hisee_symm_user_ctx *psymm_user_ctx);

	void hisee_symm_ctx_sys2usr(
		struct hisee_symm_user_ctx *psymm_user_ctx,
		struct hisee_symm_ctx *psymm_ctx);

	#define HISEE_SYMM_CTX_USR2SYS(pret, ppsymm_ctx, pctx) \
		struct hisee_symm_ctx __symm_ctx; \
		do { \
			*(pret) = hisee_symm_ctx_usr2sys(&__symm_ctx, \
				(struct hisee_symm_user_ctx *)(pctx)); \
			if (*(pret) == BSP_RET_OK) \
				*(ppsymm_ctx) = &__symm_ctx; \
		} while (0)

	#define HISEE_SYMM_CTX_SYS2USR(pret, pctx, psymm_ctx) do {\
		hisee_symm_ctx_sys2usr((struct hisee_symm_user_ctx *)(pctx), \
				       psymm_ctx); \
		*(pret) = BSP_RET_OK; \
	} while (0)

#endif /* FEATURE_USER_MEMORY_TRUSTED */

err_bsp_t hisee_symm_chiper_update(struct hisee_symm_ctx *psymm_ctx,
				   const u8 *pdin, u32 dinlen,
				   u8 *pdout, u32 *pdoutlen);

err_bsp_t hisee_symm_mac_update(struct hisee_symm_ctx *psymm_ctx,
				const u8 *pdin, u32 dinlen);

err_bsp_t hisee_symm_mac_dofinal(struct hisee_symm_ctx *psymm_ctx,
				 const u8 *pdin, u32 dinlen,
				 u8 *pdout, u32 *pdoutlen);

err_bsp_t hisee_symm_cipher_dofinal(struct hisee_symm_ctx *psymm_ctx,
				    const u8 *pdin, u32 dinlen,
				    u8 *pdout, u32 *pdoutlen);

err_bsp_t hisee_symm_set_key(struct hisee_symm_user_ctx *psymm_user_ctx,
			     u32 keytype, const u8 *pkey, u32 keylen);

err_bsp_t hisee_symm_set_iv(struct hisee_symm_user_ctx *psymm_user_ctx,
			    const u8 *pivin, u32 ivinlen);
#endif
