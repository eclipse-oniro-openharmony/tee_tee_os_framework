/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: called by python. implement video test.
 * Author: SecurityEngine
 * Create: 2020/04/10
 */
#include <hisee_video_dft.h>
#include <hisee_video.h>
#include <hisee_video_cmaion_mgr.h>
#include <common_utils.h>
#include <pal_types.h>
#include <pal_log.h>
#include <pal_libc.h>

#define BSP_THIS_MODULE            BSP_MODULE_SCE

#define DINLEN_ARRAY_SIZE_MAX      10

struct hisee_addr_ori {
	u8 *pdin;
	u32 dinlen;
	u8 *pdout;
	u32 doutlen;
};

PRIVATE struct hisee_addr_ori g_hisee_video_addr_ori;

PRIVATE void hisee_video_store_addr(struct hisee_video_cfg *pcfg)
{
	g_hisee_video_addr_ori.pdin = (u8 *)pcfg->pdin;
	g_hisee_video_addr_ori.dinlen = pcfg->dinlen;
	g_hisee_video_addr_ori.pdout = pcfg->pdout;
	g_hisee_video_addr_ori.doutlen = *pcfg->pdoutlen;
}

PRIVATE void hisee_video_restore_addr(u8 **pdout, u32 *pdoutlen)
{
	*pdout = g_hisee_video_addr_ori.pdout;
	*pdoutlen = g_hisee_video_addr_ori.doutlen;
}

/*
 * pre process:
 * 1)get cma and copy pdin to cma.
 * 2)get ion and transfer cma/ion to test object.
 */
PRIVATE err_bsp_t hisee_video_build_cmaion(struct hisee_video_cfg *pcfg)
{
	u32 ret;
	u32 cma_va;
	u32 cma_size;
	u32 ion_va;
	u32 ion_size;

	/* cma_size MUST be enough to hold indata */
	hisee_video_get_cma(&cma_va, NULL, &cma_size);

	ret = memcpy_s((u8 *)(uintptr_t)cma_va, cma_size, pcfg->pdin, pcfg->dinlen);
	if (PAL_CHECK(ret != EOK))
		return ERR_API(ERRCODE_MEMORY);

	/* ion size MUST be enough to hold indata */
	hisee_video_get_ion(NULL, NULL, &ion_va, &ion_size);

	/* save pdin and pdout */
	hisee_video_store_addr(pcfg);

	/* replace pdin by CMA */
	pcfg->pdin = (u8 *)(uintptr_t)cma_va;
	/* replace pdout by ION */
	pcfg->pdout = (u8 *)(uintptr_t)ion_va;
	*pcfg->pdoutlen = ion_size;

	return BSP_RET_OK;
}

/*
 * when nopattern:copy result from ion continuously.
 * when pattern:copy result from ion discontinuously.
 */
PRIVATE err_bsp_t hisee_video_output_result(struct hisee_video_cfg *pcfg)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u8 *src = NULL;
	u32 srclen;
	u8 *dest = NULL;
	u32 destlen;
	u32 cipherlen;
	u32 skip_len;
	u32 rlen;

	/*
	 * dest is autotest channel ddr,
	 * which will hold the continuous result.
	 */
	hisee_video_restore_addr(&dest, &destlen);

	/* src is ion, which hold the discontinuous result */
	src = pcfg->pdout;
	srclen = *pcfg->pdoutlen; /* ion result buffer len */

	/* output for nopattern */
	if (pcfg->video_type == HISEE_VIDEO_TYPE_NOPATTERN) {
		PAL_ERROR("nopattern:srclen=%d, destlen=%d\n", srclen, destlen);
		if (PAL_CHECK(srclen < destlen))
			return ERR_API(ERRCODE_PARAMS);

		ret = memcpy_s(dest, destlen, src, destlen);
		if (PAL_CHECK(ret != EOK))
			return ERR_API(ERRCODE_MEMORY);
		return BSP_RET_OK;
	} else if (pcfg->video_type == HISEE_VIDEO_TYPE_PATTERN) {
		cipherlen = pcfg->cipher_blk_size;
		skip_len = pcfg->cipher_blk_size + pcfg->plain_blk_size;
		rlen = pcfg->dinlen; /* rlen is result len */
		PAL_ERROR("pattern:srclen=%d, destlen=%d\n", srclen, destlen);
		while (rlen >= cipherlen) {
			if (PAL_CHECK(srclen < cipherlen))
				return ERR_API(ERRCODE_PARAMS);
			ret = memcpy_s(dest, destlen, src, cipherlen);
			if (PAL_CHECK(ret != EOK))
				return ERR_API(ERRCODE_MEMORY);
			src     += skip_len;
			srclen  -= skip_len;
			dest    += cipherlen;
			destlen -= cipherlen;
			rlen    -= cipherlen;
		}
		if (rlen > 0) {
			ret = memcpy_s(dest, destlen, src, rlen);
			if (PAL_CHECK(ret != EOK))
				return ERR_API(ERRCODE_MEMORY);
		}
	} else {
		return ERR_API(ERRCODE_PARAMS);
	}

	return BSP_RET_OK;
}

PRIVATE void hisee_video_set_init_param(struct hisee_video_cfg *pcfg,
					struct hisee_video_init_param *param)
{
	u32 buffer_id;
	u32 ion_size;
	u32 ion_va;
	u32 ion_iova;

	param->algorithm     = pcfg->algorithm;
	param->direction     = pcfg->direction;
	param->mode          = pcfg->mode;
	param->padding_type  = pcfg->padding_type;
	param->keytype       = pcfg->keytype;
	param->keylen        = pcfg->keylen;
	param->ivlen         = pcfg->ivlen;
	param->pkey          = pcfg->pkey;
	param->piv           = pcfg->piv;

	hisee_video_get_ion(&buffer_id, &ion_iova, &ion_va, &ion_size);
	param->video_type      = pcfg->video_type;
	param->cipher_blk_size = pcfg->cipher_blk_size;
	param->plain_blk_size  = pcfg->plain_blk_size;
	param->buffer_id       = buffer_id;
	param->size            = *pcfg->pdoutlen;
	param->outva_base      = (u8 *)(uintptr_t)ion_va;
}

PRIVATE err_bsp_t hisee_video_decrypt_frame(struct hisee_video_cfg *pcfg)
{
	err_bsp_t ret;
	struct hisee_video_ctx ctx;
	struct hisee_video_init_param init_param;
	u8 *pdin = NULL;
	u8 *pdout = NULL;
	u32 dinlen;
	u32 outbuflen;
	u32 coutlen; /* current outlen */
	u32 toutlen = 0; /* total outlen */
	u32 i;

	hisee_video_set_init_param(pcfg, &init_param);
	ret = hisee_video_init(&ctx, &init_param);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/* update */
	pdin  = (u8 *)pcfg->pdin;
	pdout = pcfg->pdout;
	outbuflen = *pcfg->pdoutlen;
	for (i = 0; i < pcfg->dinlen_array_size - 1; i++) {
		dinlen = pcfg->dinlen_array[i];
		coutlen = outbuflen;
		ret = hisee_video_update(&ctx, pdin, dinlen, pdout, &coutlen, pdout);
		if (PAL_CHECK(ret != BSP_RET_OK))
			goto end;
		pdin      += dinlen;
		pdout     += (coutlen + pcfg->plain_blk_size);
		outbuflen -= (coutlen + pcfg->plain_blk_size);
		toutlen   += (coutlen + pcfg->plain_blk_size);
	}

	PAL_ERROR("video_dofinal\n");
	/* dofinal */
	dinlen = pcfg->dinlen_array[i];
	coutlen = outbuflen;
	ret = hisee_video_dofinal(&ctx, pdin, dinlen, pdout, &coutlen, pdout);
	if (PAL_CHECK(ret != BSP_RET_OK))
		goto end;
	toutlen += coutlen;
	*pcfg->pdoutlen = toutlen;

end:
	PAL_ERROR("video_clr_info\n");
	(void)hisee_video_deinit(&ctx);

	return ret;
}

PRIVATE void hisee_video_show_cfg(struct hisee_video_cfg *pcfg)
{
	u32 i;

	PAL_ERROR("algorithm=%d\n", pcfg->algorithm);
	PAL_ERROR("direction=%d\n", pcfg->direction);
	PAL_ERROR("mode=%d\n", pcfg->mode);
	PAL_ERROR("padding_type=%d\n", pcfg->padding_type);
	PAL_ERROR("keytype=%d\n", pcfg->keytype);
	PAL_ERROR("keylen=%d\n", pcfg->keylen);
	PAL_ERROR("ivlen=%d\n", pcfg->ivlen);
	PAL_ERROR("dinlen=%d\n", pcfg->dinlen);

	PAL_ERROR("video_type=%x\n", pcfg->video_type);
	PAL_ERROR("pattern_cipher size =%x\n", pcfg->cipher_blk_size);
	PAL_ERROR("pattern_plain size =%x\n", pcfg->plain_blk_size);
	PAL_ERROR("dinlen_array_size=%d\n", pcfg->dinlen_array_size);

	if (pcfg->dinlen_array_size > DINLEN_ARRAY_SIZE_MAX)
		pcfg->dinlen_array_size = DINLEN_ARRAY_SIZE_MAX;

	for (i = 0; i < pcfg->dinlen_array_size; i++)
		PAL_ERROR("dinlen[%d]=%d\n", i, pcfg->dinlen_array[i]);
}

err_bsp_t hisee_video_test(struct hisee_video_cfg *pcfg)
{
	err_bsp_t ret;

	hisee_video_show_cfg(pcfg);
	hisee_video_show_cmaion();

	/*
	 * pre process:
	 * 1)get cma and copy pdin to cma.
	 * 2)get ion and transfer cma/ion to test object.
	 */
	ret = hisee_video_build_cmaion(pcfg);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/* exec test object */
	ret = hisee_video_decrypt_frame(pcfg);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	/* post process:
	 * copy ion to pdout
	 */
	ret = hisee_video_output_result(pcfg);
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}
