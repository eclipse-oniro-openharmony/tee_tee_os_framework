/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: implement mac compute, only support single
 * Author     : l00370476
 * Create     : 2019/11/02
 */

#include <api_mac.h>
#include <hieps_agent.h>
#include <pal_libc.h>

#define BSP_THIS_MODULE BSP_MODULE_MAC

err_bsp_t api_mac_init(api_mac_ctx_s *pctx_s, u32 algorithm, u32 mode, u8 *pkey, u32 width)
{
	errno_t libc_ret;

	PAL_CHECK_RETURN(!pctx_s || !pkey, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(width > SYMM_WIDTH_256, ERR_HAL(ERRCODE_PARAMS));

	(void)memset_s(pctx_s, sizeof(*pctx_s), 0, sizeof(*pctx_s));
	pctx_s->algorithm = algorithm;
	pctx_s->mode      = mode;
	pctx_s->width     = width;
	libc_ret = memcpy_s(pctx_s->key, sizeof(pctx_s->key), pkey, BIT2BYTE(width));
	PAL_CHECK_RETURN(libc_ret != EOK, ERR_API(ERRCODE_MEMORY));

	return BSP_RET_OK;
}

/**
 * @brief      : update mac compute, only support multi-block
 *               support CBCMAC, dont support CMAC
 * @param[in]  : pctx_s  pointer to ctx
 * @param[in]  : pdin    pointer to indata(TEE VA)
 * @param[in]  : dinlen  length in bytes of pdin
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_mac_update(api_mac_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_mac_ctx_s *tee_pctx = NULL;
	u8 *tee_pdin = NULL;
	api_mac_ctx_s *eps_pctx = NULL;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx_s || !pdin, ERR_HAL(ERRCODE_NULL));
	if (dinlen == 0)
		return BSP_RET_OK;

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = (api_mac_ctx_s *)hieps_mem_new(pctx_s, sizeof(*pctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), mac_return);
	tee_pdin = hieps_mem_new((u8 *)pdin, dinlen);
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), mac_return);

	/* 3. convert tee addr to eps addr */
	eps_pctx = hieps_mem_convert2hieps(tee_pctx);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     FUNC_API_MAC_UPDATE, FUNC_PARAMS_4,
			     eps_pctx, tee_pdin, 0, dinlen);
	PAL_ERR_GOTO(ret, mac_return);

	/* 5. output result */
	(void)memcpy_s(pctx_s, sizeof(*pctx_s), tee_pctx, sizeof(*tee_pctx));

mac_return:
	/* clear key info in share memroy before free */
	if (tee_pctx)
		(void)memset_s(tee_pctx->key, sizeof(tee_pctx->key),
			       0, sizeof(tee_pctx->key));
	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdin);
	return ret;
}

/**
 * @brief      : finish mac compute, dont call update, for update dont support aes-cmac
 * @param[in]  : pctx_s, pointer to ctx
 * @param[in]  : pdin, pointer to indata(TEE VA)
 * @param[in]  : dinlen, length in bytes of pdin
 * @param[out] : pdout, pointer to outbuffer
 * @param[io]  : pdoutlen, in:cant less than real outlen, out:real outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_mac_dofinal(api_mac_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_mac_ctx_s *tee_pctx = NULL;
	u8  *tee_pdin     = NULL;
	u8  *tee_pdout    = NULL;
	u32 *tee_pdoutlen = NULL;
	api_mac_ctx_s *eps_pctx = NULL;
	u8  *eps_pdout    = NULL;
	u32 *eps_pdoutlen = NULL;
	errno_t libc_ret;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx_s || !pdout || !pdoutlen, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pdin && dinlen != 0, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(pdin && dinlen == 0, ERR_HAL(ERRCODE_PARAMS));

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = (api_mac_ctx_s *)hieps_mem_new(pctx_s, sizeof(*pctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), mac_return);
	if (dinlen != 0) {
		tee_pdin = (u8 *)hieps_mem_new(pdin, dinlen);
		PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), mac_return);
	}
	tee_pdout = (u8 *)hieps_mem_new(NULL, *pdoutlen);
	PAL_CHECK_GOTO(!tee_pdout, ERR_HAL(ERRCODE_NULL), mac_return);
	tee_pdoutlen = (u32 *)hieps_mem_new(pdoutlen, sizeof(*pdoutlen));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), mac_return);

	/* 3. convert tee addr to eps addr */
	eps_pctx     = hieps_mem_convert2hieps(tee_pctx);
	eps_pdout    = hieps_mem_convert2hieps(tee_pdout);
	eps_pdoutlen = hieps_mem_convert2hieps(tee_pdoutlen);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     FUNC_API_MAC_DOFINAL, FUNC_PARAMS_6,
			     eps_pctx, tee_pdin, 0, dinlen, eps_pdout, eps_pdoutlen);
	PAL_ERR_GOTO(ret, mac_return);

	/* 5. output result */
	PAL_CHECK_GOTO(*tee_pdoutlen > SYMM_IVLEN_AES, ERR_HAL(ERRCODE_VERIFY), mac_return);
	libc_ret = memcpy_s(pdout, *pdoutlen, tee_pdout, *tee_pdoutlen);
	PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), mac_return);
	*pdoutlen = *tee_pdoutlen;

mac_return:
	/* clear key info in share memroy before free */
	if (tee_pctx)
		(void)memset_s(tee_pctx->key, sizeof(tee_pctx->key),
			       0, sizeof(tee_pctx->key));
	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

err_bsp_t api_mac(api_mac_s *pmac_s)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_mac_ctx_s ctx_s = {0};

	PAL_CHECK_RETURN(!pmac_s, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pmac_s->pkey ||
			 !pmac_s->pdin ||
			 !pmac_s->pdout ||
			 !pmac_s->pdoutlen, ERR_HAL(ERRCODE_NULL));

	ret = api_mac_init(&ctx_s, pmac_s->algorithm, pmac_s->mode, (u8 *)pmac_s->pkey, pmac_s->width);
	PAL_CHECK_RETURN(ret != BSP_RET_OK, ret);

	ret = api_mac_dofinal(&ctx_s, pmac_s->pdin, pmac_s->dinlen, pmac_s->pdout, pmac_s->pdoutlen);
	PAL_CHECK_RETURN(ret != BSP_RET_OK, ret);

	return ret;
}

