/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Author     : l00370476
 * Create     : 2018/12/25
 */
#include <api_hmac.h>
#include <hieps_agent.h>
#include <pal_libc.h>
#include <api_utils.h>

#define BSP_THIS_MODULE                  BSP_MODULE_MAC

/*
 * @brief      : This function is used to compute HMAC-SHA1 of Licence
 * @param[in]  : pdin, A pointer to licence data.
 * @param[in]  : dinlen, The length in bytes of pdin param.
 * @param[out] : pdout, A pointer to buffer to hold licence HMAC.
 * @param[io]  : pdoutlen, IN : A pointer to an U32 that refer to length in bytes of the caller buffer
 *                         OUT: The resulting length in bytes.
 * @return     : BSP_RET_OK if sucessful, others if there was an error.
 */
err_bsp_t api_hmac_licence(pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	u8  *tee_pdin     = NULL;
	u8  *tee_pdout    = NULL;
	u32 *tee_pdoutlen = NULL;
	u8  *eps_pdout    = NULL;
	u32 *eps_pdoutlen = NULL;
	errno_t libc_ret = EINVAL;

	/* 1. check param */
	PAL_CHECK_RETURN(!pdin || !pdout || !pdoutlen, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(dinlen > MAX_DATA_SUPPORT, ERR_API(ERRCODE_PARAMS));

	/* 2. malloc space for pointer in shared DDR */
	tee_pdin = (u8 *)hieps_mem_new(pdin, dinlen);
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), return_tag);
	tee_pdout = (u8 *)hieps_mem_new(pdout, *pdoutlen);
	PAL_CHECK_GOTO(!tee_pdout, ERR_HAL(ERRCODE_NULL), return_tag);
	tee_pdoutlen = (u32 *)hieps_mem_new(pdoutlen, sizeof(*pdoutlen));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), return_tag);

	/* 3. convert tee addr to eps addr */
	eps_pdout    = hieps_mem_convert2hieps(tee_pdout);
	eps_pdoutlen = hieps_mem_convert2hieps(tee_pdoutlen);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     FUNC_API_HMAC_LICENCE, FUNC_PARAMS_5,
			     tee_pdin, 0, dinlen, eps_pdout, eps_pdoutlen);
	PAL_ERR_GOTO(ret, return_tag);

	/* 5. output result */
	PAL_CHECK_GOTO(*tee_pdoutlen > SYMM_OUTLEN_HASH_MAX, ERR_HAL(ERRCODE_VERIFY), return_tag);
	libc_ret = memcpy_s(pdout, *pdoutlen, tee_pdout, *tee_pdoutlen);
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);
	*pdoutlen = *tee_pdoutlen;

return_tag:
	/* free */
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

err_bsp_t api_hmac_init(api_hmac_ctx_s *pctx_s, u32 alg, const u8 *pkey, u32 keylen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_hmac_ctx_s *tee_pctx = NULL;
	u8 *tee_pkey = NULL;
	api_hmac_ctx_s *eps_pctx = NULL;
	u8 *eps_pkey = NULL;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx_s || !pkey, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(keylen == 0, ERR_HAL(ERRCODE_PARAMS));

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = (api_hmac_ctx_s *)hieps_mem_new(pctx_s, sizeof(api_hmac_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);
	tee_pkey = (u8 *)hieps_mem_new(pkey, keylen);
	PAL_CHECK_GOTO(!tee_pkey, ERR_HAL(ERRCODE_NULL), return_tag);

	/* 3. convert tee addr to eps addr */
	eps_pctx = hieps_mem_convert2hieps(tee_pctx);
	eps_pkey = hieps_mem_convert2hieps(tee_pkey);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     FUNC_API_HMAC_INIT, FUNC_PARAMS_4,
			     eps_pctx, alg, eps_pkey, keylen);
	PAL_ERR_GOTO(ret, return_tag);

	/* 5. output result */
	(void)memcpy_s(pctx_s, sizeof(api_hmac_ctx_s), tee_pctx, sizeof(api_hmac_ctx_s));

return_tag:
	/* clear key info in share memroy before free */
	if (tee_pkey)
		(void)memset_s(tee_pkey, keylen, 0, keylen);

	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pkey);
	return ret;
}

err_bsp_t api_hmac_update(api_hmac_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_hmac_ctx_s *tee_pctx = NULL;
	u8 *tee_pdin = NULL;
	api_hmac_ctx_s *eps_pctx = NULL;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx_s, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(dinlen > MAX_DATA_SUPPORT, ERR_API(ERRCODE_PARAMS));
	if (dinlen == 0)
		return BSP_RET_OK;

	PAL_CHECK_RETURN(!pdin, ERR_HAL(ERRCODE_PARAMS));

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = (api_hmac_ctx_s *)hieps_mem_new(pctx_s, sizeof(api_hmac_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);
	tee_pdin = (pal_master_addr_t)hieps_mem_new(pdin, dinlen);
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), return_tag);

	/* 3. convert tee addr to eps addr */
	eps_pctx = hieps_mem_convert2hieps(tee_pctx);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     FUNC_API_HMAC_UPDATE, FUNC_PARAMS_4,
			     eps_pctx, tee_pdin, 0,  dinlen);
	PAL_ERR_GOTO(ret, return_tag);

	/* 5. output result */
	(void)memcpy_s(pctx_s, sizeof(api_hmac_ctx_s), tee_pctx, sizeof(api_hmac_ctx_s));

return_tag:
	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdin);
	return ret;
}

err_bsp_t api_hmac_dofinal(api_hmac_ctx_s *pctx_s, pal_master_addr_t pdin, u32  dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_hmac_ctx_s *tee_pctx = NULL;
	u8  *tee_pdin     = NULL;
	u8  *tee_pdout    = NULL;
	u32 *tee_pdoutlen = NULL;
	api_hmac_ctx_s *eps_pctx = NULL;
	u8  *eps_pdout    = NULL;
	u32 *eps_pdoutlen = NULL;
	errno_t libc_ret = EINVAL;
	u32 outlen_actual;

	/* 1. check param */
	PAL_CHECK_RETURN((!pctx_s || !pdout || !pdoutlen), ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pdin && (dinlen != 0), ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(pdin && (dinlen == 0), ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(dinlen > MAX_DATA_SUPPORT, ERR_API(ERRCODE_PARAMS));

	outlen_actual = symm_get_doutlen(pctx_s->hash_ctx_ipad.algorithm, 0, dinlen);
	PAL_CHECK_RETURN(outlen_actual > *pdoutlen, ERR_API(ERRCODE_PARAMS));

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = (api_hmac_ctx_s *)hieps_mem_new(pctx_s, sizeof(api_hmac_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);
	if (dinlen != 0) {
		tee_pdin = (pal_master_addr_t)hieps_mem_new(pdin, dinlen);
		PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), return_tag);
	}
	tee_pdout = (u8 *)hieps_mem_new(NULL, outlen_actual);
	PAL_CHECK_GOTO(!tee_pdout, ERR_HAL(ERRCODE_NULL), return_tag);
	tee_pdoutlen = (u32 *)hieps_mem_new(&outlen_actual, sizeof(u32));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), return_tag);

	/* 3. convert tee addr to eps addr */
	eps_pctx     = hieps_mem_convert2hieps(tee_pctx);
	eps_pdout    = hieps_mem_convert2hieps(tee_pdout);
	eps_pdoutlen = hieps_mem_convert2hieps(tee_pdoutlen);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     FUNC_API_HMAC_DOFINAL, FUNC_PARAMS_6,
			     eps_pctx, tee_pdin, 0, dinlen, eps_pdout, eps_pdoutlen);
	PAL_ERR_GOTO(ret, return_tag);

	/* 5. output result */
	PAL_CHECK_GOTO(*tee_pdoutlen > SYMM_OUTLEN_HASH_MAX, ERR_HAL(ERRCODE_VERIFY), return_tag);
	libc_ret = memcpy_s(pdout, *pdoutlen, tee_pdout, *tee_pdoutlen);
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);
	*pdoutlen = *tee_pdoutlen;

return_tag:
	/* free */
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

err_bsp_t api_hmac(api_hmac_s *phmac_s)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_hmac_ctx_s ctx = {0};

	PAL_CHECK_GOTO(!phmac_s, ERR_HAL(ERRCODE_NULL), return_tag);

	ret = api_hmac_init(&ctx, phmac_s->algorithm, phmac_s->pkey, phmac_s->keylen);
	PAL_ERR_GOTO(ret, return_tag);

	ret = api_hmac_dofinal(&ctx, phmac_s->pdin, phmac_s->dinlen, phmac_s->pdout, phmac_s->pdoutlen);
	PAL_ERR_GOTO(ret, return_tag);

return_tag:
	return ret;
}
