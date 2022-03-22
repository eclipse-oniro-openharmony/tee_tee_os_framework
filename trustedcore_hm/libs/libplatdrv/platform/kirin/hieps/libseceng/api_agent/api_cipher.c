/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: implement cipher agent
 * Author     : l00370476
 * Create     : 2018/12/22
 */
#include <api_cipher.h>
#include <cc_aes.h>
#include <cc_aes_defs.h>
#include <hieps_agent.h>
#include <tee_mem_mgmt_api.h>
#include <pal_log.h>
#include <pal_libc.h>
#include <securec.h>
#include <mem_ops.h> /* __check_secure_address */
#include <mem_ops_ext.h> /* __virt_to_phys */
#include <drv_cache_flush.h> /* v7_dma_clean_range */
#include <common_sce.h>
#include <api_utils.h>
#include <hieps_power.h>
#include <hieps_errno.h>

#define BSP_THIS_MODULE                  BSP_MODULE_SCE
#define ADDR_IS_ALIGNED_4_BYTES(addr) ((INTEGER(addr)) % 4 == 0)

err_bsp_t api_cipher_init(api_cipher_ctx_s *pctx, const api_cipher_init_s *pcipher_s)
{
	u32 ivlen;
	errno_t libc_ret = EINVAL;

	/* check pointer */
	PAL_CHECK_RETURN(!pctx, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pcipher_s, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(pcipher_s->keytype >= API_CIPHER_KEYTYPE_NUMS, ERR_HAL(ERRCODE_PARAMS));

	(void)memset_s(pctx, sizeof(*pctx), 0, sizeof(*pctx));

	/* set iv */
	if (pcipher_s->mode == SYMM_MODE_CBC || pcipher_s->mode == SYMM_MODE_CTR) {
		if (pcipher_s->algorithm == SYMM_ALGORITHM_AES || pcipher_s->algorithm == SYMM_ALGORITHM_SM4) {
			PAL_CHECK_RETURN(pcipher_s->ivlen != SYMM_IVLEN_AES, ERR_HAL(ERRCODE_PARAMS));
			ivlen = SYMM_IVLEN_AES;
		} else if (pcipher_s->algorithm == SYMM_ALGORITHM_DES) {
			PAL_CHECK_RETURN(pcipher_s->ivlen != SYMM_IVLEN_DES, ERR_HAL(ERRCODE_PARAMS));
			ivlen = SYMM_IVLEN_DES;
		} else {
			return ERR_HAL(ERRCODE_PARAMS);
		}

		PAL_CHECK_RETURN(!pcipher_s->piv, ERR_HAL(ERRCODE_NULL));
		libc_ret = memcpy_s(pctx->iv, sizeof(pctx->iv), pcipher_s->piv, ivlen);
		if (libc_ret != EOK)
			return ERR_API(ERRCODE_MEMORY);
	}

	/* set key */
	if (pcipher_s->keytype == API_CIPHER_KEYTYPE_USER_KEY || pcipher_s->keytype == API_CIPHER_KEYTYPE_USER_VIDEO) {
		PAL_CHECK_RETURN(!pcipher_s->pkey, ERR_HAL(ERRCODE_NULL));
		PAL_CHECK_RETURN((pcipher_s->width > SYMM_WIDTH_256) || (pcipher_s->width < SYMM_WIDTH_64),
				 ERR_HAL(ERRCODE_PARAMS));
		libc_ret = memcpy_s(pctx->key, sizeof(pctx->key), pcipher_s->pkey, BIT2BYTE(pcipher_s->width));
		if (libc_ret != EOK)
			return ERR_API(ERRCODE_MEMORY);
	}

	pctx->algorithm = pcipher_s->algorithm;
	pctx->direction = pcipher_s->direction;
	pctx->mode      = pcipher_s->mode;
	pctx->keytype   = pcipher_s->keytype;
	pctx->width     = pcipher_s->width;

	return BSP_RET_OK;
}

/*
 * @brief      : pdin MUST be VA, pdout MUST be IOVA
 * @param[in]  : pctx, pointer to context
 * @param[in]  : pdin, pointer to indata, MUST be VA(PA MUST be continuous)
 * @param[in]  : dinlen, length in byte of pdin
 * @param[in]  : pdout, pointer to outbuffer
 *               when aligned: MUST be IOVA
 *               when not-aligned: MUST be VA
 * @param[in]  : pdoutlen, in : cant less than real outlen
 *                         out: real outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_cipher_update_video(api_cipher_ctx_s *pctx, pal_master_addr_t pdin, u32 dinlen,
				  pal_master_addr_t pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_cipher_ctx_s *tee_pctx = NULL;
	u32 *tee_pdoutlen = NULL;
	api_cipher_ctx_s *eps_pctx = NULL;
	u32 *eps_pdoutlen = NULL;
	u8 *in  = NULL;
	u8 *out = NULL;
	u64 in_pa;
	u32 func_id;
	u32 size = 0;
	errno_t libc_ret = EINVAL;

	PAL_CHECK_RETURN(!pctx, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pdoutlen, ERR_HAL(ERRCODE_NULL));
	/* non-secure */
	if (ADDR_IS_ALIGNED_4_BYTES(pdin) && pctx->keytype != API_CIPHER_KEYTYPE_USER_VIDEO) {
		/* pdin MUST be VA */
		v7_dma_clean_range((u32)pdin, (u32)pdin + dinlen);
		in_pa = __virt_to_phys((u32)INTEGER(pdin));
	} else {
		/* pdin MUST be VA */
		in = (u8 *)PTR(pal_get_video_buf(&size));
		libc_ret = memcpy_s(in, size, pdin, dinlen);
		PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);
		in_pa = (u64)INTEGER(in);
	}

	if (ADDR_IS_ALIGNED_4_BYTES(pdout) && pctx->keytype != API_CIPHER_KEYTYPE_USER_VIDEO) {
		/* pdout MUST be IOVA */
		out = pdout;
		size = *pdoutlen;
		func_id  = FUNC_API_CIPHER_UPDATE_VIDEO;
	} else {
		/* pdout MUST be VA */
		out = (u8 *)PTR(pal_get_video_buf(&size));
		func_id = FUNC_API_CIPHER_UPDATE_BLOCKS;
	}

	if (pctx->keytype == API_CIPHER_KEYTYPE_USER_VIDEO)
		pctx->keytype = API_CIPHER_KEYTYPE_USER_KEY;

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = hieps_mem_new(pctx, sizeof(api_cipher_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);
	tee_pdoutlen = hieps_mem_new(&size, sizeof(u32));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), return_tag);

	/* 3. convert tee addr to eps addr */
	eps_pctx     = hieps_mem_convert2hieps(tee_pctx);
	eps_pdoutlen = hieps_mem_convert2hieps(tee_pdoutlen);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, func_id, FUNC_PARAMS_7,
			     eps_pctx, U64_LSB(in_pa), U64_MSB(in_pa), dinlen, out, 0, eps_pdoutlen);
	PAL_ERR_GOTO(ret, return_tag);

	/* 5. output result */
	(void)memcpy_s(pctx, sizeof(api_cipher_ctx_s), tee_pctx, sizeof(api_cipher_ctx_s));
	if (out != pdout) {
		libc_ret = memcpy_s(pdout, *pdoutlen, out, *tee_pdoutlen);
		PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);
	}

	*pdoutlen = *tee_pdoutlen;

return_tag:
	/* clear key info in share memroy before free */
	if (tee_pctx)
		(void)memset_s(tee_pctx->key, sizeof(tee_pctx->key), 0, sizeof(tee_pctx->key));
	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

PRIVATE err_bsp_t s_api_cipher_update_block(api_cipher_ctx_s *pctx, pal_master_addr_t pdin, u32 dinlen,
					    pal_master_addr_t pdout, u32 *pdoutlen, u32 func_id)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	api_cipher_ctx_s *tee_pctx =  NULL;
	u32 *tee_pdoutlen =  NULL;
	u8 *tee_pdin =  NULL;
	u32 dinlen_once =  0;
	u8 *tee_pdout =  NULL;
	u32 doutlen_once =  0;
	u32 outlen_done = 0;
	u32 blklen;
	u32 cur_id;

	/* malloc space for pointer in shared DDR */
	tee_pctx = (api_cipher_ctx_s *)hieps_mem_new(pctx, sizeof(api_cipher_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);
	tee_pdoutlen = (u32 *)hieps_mem_new(NULL, sizeof(u32));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), return_tag);

	dinlen_once = (dinlen > MAX_DATA_SUPPORT) ? MAX_DATA_SUPPORT : dinlen;
	tee_pdin = (u8 *)hieps_mem_new(NULL, dinlen_once);
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), return_tag);
	blklen = symm_get_blklen(pctx->algorithm);
	PAL_CHECK_GOTO(blklen == 0, ERR_HAL(ERRCODE_PARAMS), return_tag);
	doutlen_once = symm_get_doutlen(pctx->algorithm, pctx->mode, dinlen_once + blklen);
	tee_pdout = (u8 *)hieps_mem_new(NULL, doutlen_once);
	PAL_CHECK_GOTO(!tee_pdout, ERR_HAL(ERRCODE_NULL), return_tag);

	while (dinlen > 0) {
		if (dinlen > MAX_DATA_SUPPORT) {
			dinlen_once = MAX_DATA_SUPPORT;
			cur_id = FUNC_API_CIPHER_UPDATE;
		}
		else {
			dinlen_once = dinlen;
			cur_id = func_id;
		}

		*tee_pdoutlen = doutlen_once;
		libc_ret = memcpy_s(tee_pdin, dinlen_once, pdin, dinlen_once);
		PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);

		/* ipc send and wait response */
		ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, cur_id, FUNC_PARAMS_7,
				     hieps_mem_convert2hieps(tee_pctx), tee_pdin, 0, dinlen_once,
				     tee_pdout, 0, hieps_mem_convert2hieps(tee_pdoutlen));
		PAL_ERR_GOTO(ret, return_tag);
		libc_ret = memcpy_s(pdout, *pdoutlen, tee_pdout, *tee_pdoutlen);
		PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);
		pdin += dinlen_once;
		dinlen -= dinlen_once;
		pdout += *tee_pdoutlen;
		*pdoutlen -= *tee_pdoutlen;
		outlen_done += *tee_pdoutlen;
	}

	*pdoutlen = outlen_done;
	libc_ret = memcpy_s(pctx, sizeof(api_cipher_ctx_s), tee_pctx, sizeof(api_cipher_ctx_s));
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);

return_tag:
	/* clear key info in share memroy before free */
	if (tee_pctx)
		(void)memset_s(tee_pctx->key, sizeof(tee_pctx->key), 0, sizeof(tee_pctx->key));
	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

/*
 * @brief      : update cipher compute, for generic calls, all addr is VA
 *               func flow:
 *               1)copy all the params to shared DDR
 *               2)ipc send
 * @param[in]  : pctx, pointer to context
 * @param[in]  : pdin, pointer to indata
 * @param[in]  : dinlen, length in byte of pdin
 * @param[out] : pdout, pointer to outbuffer
 * @param[io]  : pdoutlen in : cant less than real outlen
 *                        out: real outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
PRIVATE err_bsp_t s_api_cipher_update(api_cipher_ctx_s *pctx,
				      pal_master_addr_t pdin,  u32 dinlen,
				      pal_master_addr_t pdout, u32 *pdoutlen,
				      u32 func_id)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	uint32_t pm_ret = HIEPS_ERROR;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx || !pdin || !pdout || !pdoutlen, ERR_HAL(ERRCODE_NULL));

	/* chinaDRM 1.0 video */
	if (pctx->keytype == API_CIPHER_KEYTYPE_CEK_VIDEO) {
		/* non-zero is non-secure, zero is secure */
		if (__check_secure_address((uintptr_t)pdin, dinlen) != 0) {
			ret = api_cipher_update_video(pctx, pdin, dinlen, pdout, pdoutlen);
			PAL_ERR_RETURN(ret);
			return ret;
		}
	}

	if (pctx->keytype == API_CIPHER_KEYTYPE_USER_VIDEO) {
		/* chinaDRM 2.0 video */
		ret = api_cipher_update_video(pctx, pdin, dinlen, pdout, pdoutlen);
		PAL_ERR_RETURN(ret);
		return ret;
	}

	pm_ret = hieps_power_on(SELF_CTRL_MULTI, PROFILE_KEEP);
	PAL_CHECK_RETURN((pm_ret != HIEPS_OK), ERR_DRV(ERRCODE_SYS));

	ret = s_api_cipher_update_block(pctx, pdin, dinlen, pdout, pdoutlen, func_id);
	PAL_ERR_GOTO(ret, return_tag);

return_tag:
	pm_ret = hieps_power_off(SELF_CTRL_MULTI, PROFILE_KEEP);
	PAL_CHECK_RETURN((pm_ret != HIEPS_OK), ERR_DRV(ERRCODE_SYS));
	return ret;
}

err_bsp_t api_cipher_update(api_cipher_ctx_s *pctx,
			    pal_master_addr_t pdin, u32 dinlen, pal_master_addr_t pdout, u32 *pdoutlen)
{
	u32 blklen;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx, ERR_HAL(ERRCODE_NULL));

	blklen = symm_get_blklen(pctx->algorithm);
	PAL_CHECK_RETURN(blklen == 0, ERR_HAL(ERRCODE_PARAMS));
	if (pctx->keytype == API_CIPHER_KEYTYPE_CEK_VIDEO || pctx->keytype == API_CIPHER_KEYTYPE_USER_VIDEO)
		PAL_CHECK_RETURN((dinlen % blklen) != 0, ERR_HAL(ERRCODE_PARAMS));

	return s_api_cipher_update(pctx, pdin, dinlen, pdout, pdoutlen, FUNC_API_CIPHER_UPDATE);
}

err_bsp_t api_cipher_dofinal(api_cipher_ctx_s *pctx,
			     pal_master_addr_t pdin,  u32 dinlen, pal_master_addr_t pdout, u32 *pdoutlen)
{
	u32 blklen;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx, ERR_HAL(ERRCODE_NULL));

	blklen = symm_get_blklen(pctx->algorithm);
	PAL_CHECK_RETURN(blklen == 0, ERR_HAL(ERRCODE_PARAMS));
	if ((pctx->keytype == API_CIPHER_KEYTYPE_CEK_VIDEO ||
	     pctx->keytype == API_CIPHER_KEYTYPE_USER_VIDEO) &&
	    (pctx->mode == SYMM_MODE_ECB || pctx->mode == SYMM_MODE_CBC))
		PAL_CHECK_RETURN((dinlen % blklen) != 0, ERR_HAL(ERRCODE_PARAMS));

	return s_api_cipher_update(pctx, pdin, dinlen, pdout, pdoutlen, FUNC_API_CIPHER_DOFINAL);
}

