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
#include <pal_log.h>
#include <pal_cpu.h>
#include <pal_libc.h>
#include <hal_cipher.h>
#include "hisee_video_smmu.h"

#define BSP_THIS_MODULE            BSP_MODULE_SCE

struct hisee_cb_param {
	u8  *pdout;
	u32 doutlen;
	u32 cipher_blk_size; /* ciphered block */
	u32 plain_blk_size;   /* plain block */
};

struct hisee_video_info {
	u32 video_type;    /* PATTERN or NOPATTERN */
	u32 cipher_blk_size; /* ciphered block */
	u32 plain_blk_size;   /* plain block */
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
		return U32_MAX;

	return psymm_ctx->algorithm;
}

PRIVATE u32 hisee_video_get_mode(struct hisee_video_ctx *pctx)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_symm_ctx *psymm_ctx = NULL;

	HISEE_SYMM_CTX_USR2SYS(&ret, &psymm_ctx, &pctx->cipher_ctx);
	if (PAL_CHECK(!psymm_ctx))
		return U32_MAX;

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
		ret = hisee_video_smmu_init(pinfo->buffer_id, pinfo->size, &pinfo->outiova_base);
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
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
	if (PAL_CHECK(init_param->algorithm >= SYMM_ALGORITHM_MAX)) {
		PAL_DUMP("init_param:", init_param,
			 sizeof(struct hisee_video_init_param), 1);
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

	video_info.video_type       = init_param->video_type;
	video_info.cipher_blk_size  = init_param->cipher_blk_size;
	video_info.plain_blk_size   = init_param->plain_blk_size;
	video_info.buffer_id        = init_param->buffer_id;
	video_info.size             = init_param->size;
	video_info.outva_base       = init_param->outva_base;
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
					       u8 *pdout, u32 *pdoutlen, u8 *pdout_va)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_video_info *vctx = NULL;
	struct hal_cipher cipher;
	struct hal_sce_extend cipher_extend;
	u32 offset;
	u32 doutlen = dinlen;

	/* outbuffer len is enough? */
	if (PAL_CHECK(*pdoutlen < doutlen))
		return ERR_API(ERRCODE_PARAMS);

	hal_cipher_init(&cipher);
	hal_sce_extend_init(&cipher_extend);
	ret = hisee_video_set_hal_cipher(pctx, &cipher);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ERR_API(ERRCODE_PARAMS);

	vctx = (struct hisee_video_info *)(&pctx->video_ctx);
	if (PAL_CHECK(pdout < vctx->outva_base))
		return ERR_API(ERRCODE_PARAMS);
	offset = pdout - vctx->outva_base;
	/* exceed buffer_id? */
	if (PAL_CHECK(offset > vctx->size))
		return ERR_API(ERRCODE_PARAMS);

	/* in: in_pa; out: out_iova (master_addr) */
	cipher_extend.smmu_en         = SYMM_SMMU_READ_N_WRITE_Y;
	cipher_extend.smmu_is_sec     = SEC_YES;
	cipher.pextend                = &cipher_extend;
	cipher.pdin.type              = ADDR_TYPE_MASTER;
	cipher.pdin.addr.master_addr  = pal_virt_to_phy(pdin);
	cipher.dinlen                 = dinlen;
	cipher.pdout.type             = ADDR_TYPE_MASTER;
	cipher.pdout.addr.master_addr = offset + vctx->outiova_base;
	cipher.doutlen                = doutlen;

	ret = pal_flush_dcache(pdin, dinlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	pal_clean_dcache(pdout_va, *pdoutlen);
	ret = hal_cipher_function(&cipher);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = pal_invalidate_dcache(pdout_va, *pdoutlen);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/* nopattern:doutlen is equal to dinlen */
	*pdoutlen = doutlen;

	return ret;
}

PRIVATE u32 hisee_video_get_pattern_doutlen(u32 dinlen, u32 cipher_blk_size, u32 plain_blk_size)
{
	u32 m;
	u32 sum;

	if (PAL_CHECK(cipher_blk_size == 0))
		return U32_MAX;
	if (PAL_CHECK(dinlen % cipher_blk_size != 0 || dinlen == 0))
		return U32_MAX;

	m = dinlen / cipher_blk_size;
	sum = cipher_blk_size + plain_blk_size;

	if (PAL_CHECK(sum < cipher_blk_size))
		return U32_MAX; /* if overflow, return MAX_U32 */

	if (PAL_CHECK(U32_MAX / sum <= m))
		return U32_MAX; /* if overflow, return MAX_U32 */

	return sum * m - plain_blk_size;
}

PRIVATE err_bsp_t hisee_video_output_workspace(void *param, struct hal_cb_param *hcp)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hisee_cb_param *pparam = (struct hisee_cb_param *)param;
	u8 *src = NULL;
	u32 srclen;
	u8 *dest = NULL;
	u32 destlen;
	u32 sub_blk_size;
	u32 cipher_size;
	u32 plain_size;

	if (PAL_CHECK(!pparam || !hcp))
		return ERR_API(ERRCODE_NULL);

	if (PAL_CHECK(!hcp->srcva || hcp->srclen == 0))
		return ERR_API(ERRCODE_NULL);

	if (PAL_CHECK(pparam->cipher_blk_size % SYMM_BLKLEN_AES != 0 ||
		      pparam->cipher_blk_size == 0))
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
	cipher_size = pparam->cipher_blk_size;
	plain_size  = pparam->plain_blk_size;
	sub_blk_size = cipher_size + plain_size;
	if (PAL_CHECK(sub_blk_size < cipher_size))
		return ERR_API(ERRCODE_PARAMS);

	src       = (u8 *)(uintptr_t)hcp->srcva;
	srclen    = hcp->srclen;
	dest      = pparam->pdout;
	destlen   = pparam->doutlen;
	if (PAL_CHECK(destlen < hisee_video_get_pattern_doutlen(srclen, cipher_size, plain_size)))
		return ERR_API(ERRCODE_PARAMS);

	/* copy 16bytes every time */
	while (srclen >= cipher_size) {
		ret = memcpy_s(dest, destlen, src, cipher_size);
		if (PAL_CHECK(ret != EOK))
			return ERR_API(ERRCODE_MEMORY);
		src     += cipher_size;
		srclen  -= cipher_size;
		dest    += sub_blk_size;
		destlen -= sub_blk_size;
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
	struct hal_sce_extend cipher_extend;
	u32 doutlen;

	vctx = (struct hisee_video_info *)(&pctx->video_ctx);

	if (PAL_CHECK(dinlen % SYMM_BLKLEN_AES != 0))
		return ERR_API(ERRCODE_PARAMS);
	if (PAL_CHECK(vctx->cipher_blk_size == 0 ||
		      vctx->cipher_blk_size % SYMM_BLKLEN_AES != 0)) {
		return ERR_API(ERRCODE_PARAMS);
	}

	/* doutlen is 10 multiple of dinlen */
	doutlen = hisee_video_get_pattern_doutlen(dinlen, vctx->cipher_blk_size, vctx->plain_blk_size);
	/* outbuffer len is enough? */
	if (PAL_CHECK(*pdoutlen < doutlen)) {
		PAL_ERROR("dinlen=%d,*pdoutlen=%d\n", dinlen, *pdoutlen);
		PAL_DUMP("din:", pdin, dinlen, 0);
		PAL_DUMP("dout:", pdout, *pdoutlen, 0);
		return ERR_API(ERRCODE_PARAMS);
	}

	hal_cipher_init(&cipher);
	hal_sce_extend_init(&cipher_extend);
	ret = hisee_video_set_hal_cipher(pctx, &cipher);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ERR_API(ERRCODE_PARAMS);

	cb_param.cipher_blk_size = vctx->cipher_blk_size;
	cb_param.plain_blk_size  = vctx->plain_blk_size;

	cb_param.pdout         = pdout;
	cb_param.doutlen       = doutlen;
	ocb.func               = hisee_video_output_workspace;
	ocb.param              = &cb_param;

	/*
	 * in: in_pa (master_addr)
	 * out: out_va (cpu_addr)
	 */
	cipher_extend.smmu_en         = SYMM_SMMU_READ_N_WRITE_N;
	cipher_extend.smmu_is_sec     = SEC_NO;
	cipher.pextend                = &cipher_extend;
	cipher.ocb                    = ocb;
	cipher.pdin.type              = ADDR_TYPE_MASTER;
	cipher.pdin.addr.master_addr  = pal_virt_to_phy(pdin);
	cipher.dinlen                 = dinlen;
	cipher.pdout.type             = ADDR_TYPE_CPU;
	cipher.pdout.addr.cpu_addr    = (pal_cpu_addr_t)(uintptr_t)pdout;
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
					   u8 *pdout, u32 *pdoutlen, u8 * pdout_va)
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
						   pdout, pdoutlen, pdout_va);
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
			     u8 *pdout, u32 *pdoutlen, u8* pdout_va)
{
	u32 blklen;

	blklen = symm_get_blklen(hisee_video_get_algorithm(pctx));
	if (blklen == 0)
		return ERR_API(ERRCODE_PARAMS);

	if (PAL_CHECK(dinlen % blklen != 0 || dinlen == 0))
		return ERR_API(ERRCODE_PARAMS);

	return hisee_video_update_inner(pctx, pdin, dinlen, pdout, pdoutlen, pdout_va);
}

/*
 * decrypt video stream.
 * for AES-CBC-NOPAD: dinlen MUST be multiple of block size.
 * for AES-CTR: no need of multiple of block size.
 * you call it to finish decryption operation
 */
err_bsp_t hisee_video_dofinal(struct hisee_video_ctx *pctx,
			      const u8 *pdin, u32 dinlen,
			      u8 *pdout, u32 *pdoutlen, u8* pdout_va)
{
	u32 mode;
	u32 blklen;

	if (PAL_CHECK(!pctx))
		return ERR_API(ERRCODE_NULL);
	if (PAL_CHECK(dinlen == 0))
		return ERR_API(ERRCODE_PARAMS);

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

	return hisee_video_update_inner(pctx, pdin, dinlen, pdout, pdoutlen, pdout_va);
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
		hisee_video_smmu_deinit(vctx->buffer_id, vctx->size);
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

