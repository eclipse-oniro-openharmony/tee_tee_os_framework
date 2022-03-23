/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: implement cdrm video decrypt api
 * Author: SecurityEngine
 * Create: 2020/03/07
 */
#include <hisee_video.h>
#include "hisee_video_ops.h"
#include <common_utils.h>
#include <common_sce.h>
#include <standard_sce.h>
#include <hisee_symm_common.h>
#include <pal_smmu_plat.h>
#include <pal_log.h>
#include <pal_cpu.h>
#include <pal_libc.h>
#include <hal_cipher.h>

#define BSP_THIS_MODULE            BSP_MODULE_SCE

struct hisee_cb_param {
	u8  *pdout;
	u32 doutlen;
	u32 pattern_ratio;
};

struct hisee_video_info {
	u32 video_type;    /* PATTERN or NOPATTERN */
	u32 pattern_ratio; /* cipherlen/plainlen ratio of PATTERN */
	u32 buffer_id;     /* buffer_id of one frame outbuffer for NOPATTERN */
	u32 size;          /* byte size of buffer_id */
	u8  *outva_base;   /* va base of buffer_id */
	u32 outiova_base;  /* iova base of buffer_id */
};

PRIVATE u32 hisee_video_get_algorithm(struct hisee_video_ctx *pctx)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_symm_ctx *psymm_ctx = NULL;

	HISEE_SYMM_CTX_USR2SYS(&ret, &psymm_ctx, &pctx->cipher_ctx);
	if (PAL_CHECK(!psymm_ctx))
		return -1;

	return psymm_ctx->algorithm;
}

PRIVATE u32 hisee_video_get_mode(struct hisee_video_ctx *pctx)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_symm_ctx *psymm_ctx = NULL;

	HISEE_SYMM_CTX_USR2SYS(&ret, &psymm_ctx, &pctx->cipher_ctx);
	if (PAL_CHECK(!psymm_ctx))
		return -1;

	return psymm_ctx->mode;
}

/*
 * copy video info to ctx.
 * you need call it before hisee_video_update
 */
PRIVATE err_bsp_t hisee_video_set_info(struct hisee_video_ctx *pctx,
				       struct hisee_video_info *pinfo)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	if (PAL_CHECK(!pctx || !pinfo))
		return ERR_API(ERRCODE_NULL);

	if (PAL_CHECK(pinfo->video_type != HISEE_VIDEO_TYPE_NOPATTERN &&
		      pinfo->video_type != HISEE_VIDEO_TYPE_PATTERN))
		return ERR_API(ERRCODE_PARAMS);

	if (pinfo->video_type == HISEE_VIDEO_TYPE_NOPATTERN) {
		ret = pal_mmu_poweron();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		ret = pal_mmu_bind();
		if (PAL_CHECK(ret != BSP_RET_OK)) {
			(void)pal_mmu_poweroff();
			return ret;
		}
		ret = pal_mmu_map(pinfo->buffer_id, pinfo->size, &pinfo->outiova_base);
		if (PAL_CHECK(ret != BSP_RET_OK)) {
			(void)pal_mmu_unbind();
			(void)pal_mmu_poweroff();
			return ret;
		}
		ret = pal_mmu_tbu_init();
		if (PAL_CHECK(ret != BSP_RET_OK)) {
			(void)pal_mmu_unmap(pinfo->buffer_id, pinfo->size);
			(void)pal_mmu_unbind();
			(void)pal_mmu_poweroff();
			return ret;
		}
	}

	ret = memcpy_s(&pctx->video_ctx, sizeof(pctx->video_ctx),
		       pinfo, sizeof(struct hisee_video_info));
	if (PAL_CHECK(ret != EOK))
		return ERR_API(ERRCODE_MEMORY);
	else
		return BSP_RET_OK;
}

err_bsp_t hisee_video_init(struct hisee_video_ctx *pctx,
			   struct hisee_video_init_param *init_param)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_video_info video_info;
	const struct hisee_video_ops *ops = NULL;

	if (PAL_CHECK(!pctx || !init_param))
		return ERR_API(ERRCODE_NULL);
	if (PAL_CHECK(!init_param->pkey || !init_param->piv))
		return ERR_API(ERRCODE_NULL);
	if (PAL_CHECK(init_param->algorithm > SYMM_ALGORITHM_MAX)) {
		/* for syscall */
		PAL_DUMP("init_param:", init_param,
			 sizeof(struct hisee_video_init_param), 1);
		PAL_DUMP("key:", init_param->pkey, init_param->keylen, 0);
		PAL_DUMP("iv:", init_param->piv, init_param->ivlen, 0);
		return ERR_API(ERRCODE_PARAMS);
	}

	ops = hisee_video_get_ops(init_param->algorithm);
	ret = ops->init(&pctx->cipher_ctx, init_param->direction,
			init_param->mode, init_param->padding_type);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = ops->set_key(&pctx->cipher_ctx, init_param->keytype,
			   init_param->pkey, init_param->keylen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = ops->set_iv(&pctx->cipher_ctx, init_param->piv, init_param->ivlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	video_info.video_type    = init_param->video_type;
	video_info.pattern_ratio = init_param->pattern_ratio;
	video_info.buffer_id     = init_param->buffer_id;
	video_info.size          = init_param->size;
	video_info.outva_base    = init_param->outva_base;
	ret = hisee_video_set_info(pctx, &video_info);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

PRIVATE err_bsp_t hisee_video_set_hal_cipher(struct hisee_video_ctx *pctx,
					     struct hal_cipher *cipher)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_symm_ctx *psymm_ctx = NULL;
	u32 ivlen;

	ivlen = symm_get_ivlen(hisee_video_get_algorithm(pctx));
	if (PAL_CHECK(ivlen == 0))
		return ERR_API(ERRCODE_PARAMS);

	HISEE_SYMM_CTX_USR2SYS(&ret, &psymm_ctx, &pctx->cipher_ctx);
	if (PAL_CHECK(!psymm_ctx))
		return ERR_API(ERRCODE_PARAMS);

	cipher->algorithm   = psymm_ctx->algorithm;
	cipher->mode        = psymm_ctx->mode;
	cipher->direction   = psymm_ctx->direction;
	cipher->keytype     = psymm_ctx->keytype;
	cipher->pkey        = psymm_ctx->key;
	cipher->keylen      = psymm_ctx->klen;
	cipher->pivin       = psymm_ctx->iv;
	cipher->ivinlen     = ivlen;
	cipher->pivout      = psymm_ctx->iv;
	cipher->ivoutlen    = ivlen;

	return ret;
}

/*
 * pdin:MUST be CMA. VA.
 * pdout:VA. used to get offset of IOVA. dont hold result
 */
PRIVATE err_bsp_t hisee_video_update_nopattern(struct hisee_video_ctx *pctx,
					       const u8 *pdin, u32 dinlen,
					       u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_video_info *vctx = NULL;
	struct hal_cipher cipher;
	u32 offset;
	u32 doutlen = dinlen;

	/* outbuffer len is enough? */
	if (PAL_CHECK(*pdoutlen < doutlen))
		return ERR_API(ERRCODE_PARAMS);

	hal_cipher_init(&cipher);
	ret = hisee_video_set_hal_cipher(pctx, &cipher);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ERR_API(ERRCODE_PARAMS);

	vctx = (struct hisee_video_info *)(&pctx->video_ctx);
	if (PAL_CHECK(pdout < vctx->outva_base))
		return ERR_API(ERRCODE_PARAMS);
	offset = pdout - vctx->outva_base;
	/* add overflow? */
	if (PAL_CHECK(offset + vctx->outiova_base < offset))
		return ERR_API(ERRCODE_PARAMS);
	/* exceed buffer_id? */
	if (PAL_CHECK(offset + vctx->outiova_base > vctx->size))
		return ERR_API(ERRCODE_PARAMS);

	/* in: in_pa; out: out_iova (master_addr) */
	cipher.smmu_en                = SYMM_SMMU_READ_N_WRITE_Y;
	cipher.smmu_is_sec            = SEC_YES;
	cipher.pdin.type              = ADDR_TYPE_MASTER;
	cipher.pdin.addr.master_addr  = pal_virt_to_phy(pdin);
	cipher.dinlen                 = dinlen;
	cipher.pdout.type             = ADDR_TYPE_MASTER;
	cipher.pdout.addr.master_addr = offset + vctx->outiova_base;
	cipher.doutlen                = doutlen;

	ret = pal_flush_dcache(pdin, dinlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_cipher_function(&cipher);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = pal_clean_dcache(pdout, *pdoutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/* nopattern:doutlen is equal to dinlen */
	*pdoutlen = doutlen;

	return ret;
}

PRIVATE u32 hisee_video_get_pattern_doutlen(u32 dinlen)
{
	u32 leftlen = dinlen % SYMM_BLKLEN_AES;
	u32 m;

	m = (PATTERN_1_9_CIPHERLEN + PATTERN_1_9_PLAINLEN) / SYMM_BLKLEN_AES;
	return (dinlen - leftlen) * m + leftlen;
}

PRIVATE err_bsp_t hisee_video_output_workspace(void *param, struct hal_cb_param *hcp)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_cb_param *pparam = (struct hisee_cb_param *)param;
	u8 *src = NULL;
	u32 srclen;
	u8 *dest = NULL;
	u32 destlen;

	if (PAL_CHECK(!pparam || !hcp))
		return ERR_API(ERRCODE_NULL);

	if (PAL_CHECK(!hcp->srcva))
		return ERR_API(ERRCODE_NULL);

	if (PAL_CHECK(pparam->pattern_ratio != HISEE_VIDEO_PATTERN_RATION_1_9))
		return ERR_API(ERRCODE_PARAMS);

	/*
	 * copy rule:
	 * src(workspace) -> dest(user)
	 * -----------------------------
	 * | 1blk | 1blk | 1blk | 1blk |
	 * -----------------------------
	 *   \|/         \
	 * -----------------------------
	 * | 1blk | 9blk | 1blk | 9blk |
	 * -----------------------------
	 */
	src       = (u8 *)(uintptr_t)hcp->srcva;
	srclen    = hcp->srclen;
	dest      = pparam->pdout;
	destlen   = pparam->doutlen;
	if (PAL_CHECK(destlen < hisee_video_get_pattern_doutlen(srclen)))
		return ERR_API(ERRCODE_PARAMS);

	/* copy 16bytes every time */
	while (srclen >= PATTERN_1_9_CIPHERLEN) {
		ret = memcpy_s(dest, destlen, src, PATTERN_1_9_CIPHERLEN);
		if (PAL_CHECK(ret != EOK))
			return ERR_API(ERRCODE_MEMORY);
		src     += PATTERN_1_9_CIPHERLEN;
		srclen  -= PATTERN_1_9_CIPHERLEN;
		dest    += PATTERN_1_9_CIPHERLEN + PATTERN_1_9_PLAINLEN;
		destlen -= PATTERN_1_9_CIPHERLEN + PATTERN_1_9_PLAINLEN;
	}

	/* copy last few no-more-than 16bytes */
	if (srclen > 0) {
		ret = memcpy_s(dest, destlen, src, srclen);
		if (PAL_CHECK(ret != EOK))
			return ERR_API(ERRCODE_MEMORY);
	}

	return BSP_RET_OK;
}

/*
 * pdin:MUST be CMA. VA.
 * pdout:VA. hold result.but not the continuous result.
 */
PRIVATE err_bsp_t hisee_video_update_pattern(struct hisee_video_ctx *pctx,
					     const u8 *pdin, u32 dinlen,
					     u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_video_info *vctx = NULL;
	struct hisee_cb_param cb_param;
	struct hal_out_cb ocb;
	struct hal_cipher cipher;
	u32 doutlen;

	/* doutlen is 10 multiple of dinlen */
	doutlen = hisee_video_get_pattern_doutlen(dinlen);
	/* outbuffer len is enough? */
	if (PAL_CHECK(*pdoutlen < doutlen)) {
		PAL_ERROR("dinlen=%d,*pdoutlen=%d\n", dinlen, *pdoutlen);
		PAL_DUMP("din:", pdin, dinlen, 0);
		PAL_DUMP("dout:", pdout, *pdoutlen, 0);
		return ERR_API(ERRCODE_PARAMS);
	}

	hal_cipher_init(&cipher);
	ret = hisee_video_set_hal_cipher(pctx, &cipher);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ERR_API(ERRCODE_PARAMS);

	vctx = (struct hisee_video_info *)(&pctx->video_ctx);
	cb_param.pattern_ratio = vctx->pattern_ratio;
	cb_param.pdout         = pdout;
	cb_param.doutlen       = doutlen;
	ocb.func               = hisee_video_output_workspace;
	ocb.param              = &cb_param;

	/*
	 * in: in_pa (master_addr)
	 * out: out_va (cpu_addr)
	 */
	cipher.smmu_en                = SYMM_SMMU_READ_N_WRITE_N;
	cipher.smmu_is_sec            = SEC_NO;
	cipher.ocb                    = ocb;
	cipher.pdin.type              = ADDR_TYPE_MASTER;
	cipher.pdin.addr.master_addr  = pal_virt_to_phy(pdin);
	cipher.dinlen                 = dinlen;
	cipher.pdout.type             = ADDR_TYPE_CPU;
	cipher.pdout.addr.master_addr = (pal_master_addr_t)(uintptr_t)pdout;
	cipher.doutlen                = dinlen;

	ret = pal_flush_dcache(pdin, dinlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_cipher_function(&cipher);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/*
	 * here dont need pal_invalidate_dcache.
	 * result is copyed by CPU from workspace
	 */
	*pdoutlen = doutlen;

	return ret;
}

/*
 * decrypt video stream, dinlen MUST be multiple of block size.
 * support AES-CBC-NOPAD/AES-CTR.
 * you need call it after hisee_init/hisee_set_key/hisee_set_iv
 * pdin:MUST be CMA. VA.
 * pdout:MUST be ION.
 *       when pattern:VA of ION. hold result but not the continuous result.
 *       when nopattern:VA of ION. used to get offset of IOVA.
 */
PRIVATE err_bsp_t hisee_video_update_inner(struct hisee_video_ctx *pctx,
					   const u8 *pdin, u32 dinlen,
					   u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_video_info *vctx = NULL;

	if (PAL_CHECK(!pctx || !pdin || !pdout || !pdoutlen))
		return ERR_API(ERRCODE_NULL);

	if (PAL_CHECK(dinlen > HISEE_VIDEO_PATTERN_MAXLEN))
		return ERR_API(ERRCODE_PARAMS);

	vctx = (struct hisee_video_info *)(&pctx->video_ctx);
	switch (vctx->video_type) {
	case HISEE_VIDEO_TYPE_NOPATTERN:
		ret = hisee_video_update_nopattern(pctx, pdin, dinlen,
						   pdout, pdoutlen);
		break;
	case HISEE_VIDEO_TYPE_PATTERN:
		ret = hisee_video_update_pattern(pctx, pdin, dinlen,
						 pdout, pdoutlen);
		break;
	default:
		return ERR_API(ERRCODE_PARAMS);
	}

	return ret;
}

err_bsp_t hisee_video_update(struct hisee_video_ctx *pctx,
			     const u8 *pdin, u32 dinlen,
			     u8 *pdout, u32 *pdoutlen)
{
	u32 blklen;

	blklen = symm_get_blklen(hisee_video_get_algorithm(pctx));
	if (blklen == 0)
		return ERR_API(ERRCODE_PARAMS);

	if (PAL_CHECK(dinlen % blklen != 0 || dinlen == 0))
		return ERR_API(ERRCODE_PARAMS);

	return hisee_video_update_inner(pctx, pdin, dinlen, pdout, pdoutlen);
}

/*
 * decrypt video stream.
 * for AES-CBC-NOPAD: dinlen MUST be multiple of block size.
 * for AES-CTR: no need of multiple of block size.
 * you call it to finish decryption operation
 */
err_bsp_t hisee_video_dofinal(struct hisee_video_ctx *pctx,
			      const u8 *pdin, u32 dinlen,
			      u8 *pdout, u32 *pdoutlen)
{
	u32 mode;
	u32 blklen;

	if (PAL_CHECK(!pctx))
		return ERR_API(ERRCODE_NULL);

	/*
	 * CTR support no-multiple-of-block-size, CBC dont suppot.
	 * we dont check param here, for we dont done mode here.
	 * it is done in hal_cipher_function
	 */
	blklen = symm_get_blklen(hisee_video_get_algorithm(pctx));
	if (blklen == 0)
		return ERR_API(ERRCODE_PARAMS);
	mode = hisee_video_get_mode(pctx);
	if (PAL_CHECK(mode != SYMM_MODE_CTR && dinlen % blklen != 0))
		return ERR_API(ERRCODE_PARAMS);

	return hisee_video_update_inner(pctx, pdin, dinlen, pdout, pdoutlen);
}

/*
 * clear video info from ctx.
 * you need call it after hisee_video_dofinal
 */
PRIVATE err_bsp_t hisee_video_clr_info(struct hisee_video_ctx *pctx)
{
	struct hisee_video_info *vctx = NULL;

	if (PAL_CHECK(!pctx))
		return ERR_API(ERRCODE_NULL);

	vctx = (struct hisee_video_info *)(&pctx->video_ctx);

	if (vctx->video_type == HISEE_VIDEO_TYPE_NOPATTERN) {
		(void)pal_mmu_tbu_deinit();
		(void)pal_mmu_unmap(vctx->buffer_id, vctx->size);
		(void)pal_mmu_unbind();
		(void)pal_mmu_poweroff();
	}
	(void)memset_s(pctx, sizeof(struct hisee_video_ctx),
		       0, sizeof(struct hisee_video_ctx));

	return BSP_RET_OK;
}

err_bsp_t hisee_video_deinit(struct hisee_video_ctx *pctx)
{
	return hisee_video_clr_info(pctx);
}

u32 hisee_video_get_type(struct hisee_video_ctx *pctx)
{
	struct hisee_video_info *vctx = NULL;

	if (PAL_CHECK(!pctx))
		return ERR_API(ERRCODE_NULL);

	vctx = (struct hisee_video_info *)(&pctx->video_ctx);

	return vctx->video_type;
}

