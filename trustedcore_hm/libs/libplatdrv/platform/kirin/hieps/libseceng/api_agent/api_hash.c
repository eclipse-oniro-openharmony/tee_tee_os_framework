/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: implement hash agent for HiEPS
 * Author     : l00370476
 * Create     : 2018/12/21
 */
#include <api_hash.h>
#include <hieps_agent.h>
#include <pal_libc.h>
#include <api_utils.h>
#include <hieps_power.h>
#include <hieps_errno.h>

#define BSP_THIS_MODULE                  BSP_MODULE_HASH

#define HASH_MAX_DATALEN               (MAX_DATA_SUPPORT * 2)

err_bsp_t api_hash(u32 algorithm, pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_hash_ctx_s ctx_s = {0};

	ret = api_hash_init(&ctx_s, algorithm);
	PAL_ERR_GOTO(ret, return_tag);

	ret = api_hash_dofinal(&ctx_s, pdin, dinlen, pdout, pdoutlen);
	PAL_ERR_GOTO(ret, return_tag);
return_tag:
	return ret;
}

/**
 * @brief      : hash update
 * @param[in]  : pctx_s, pointer to ctx
 * @param[in]  : algorithm, hash algorithm, SHA1/SHA256/SM3
 * @return     : BSP_RET_OK if successful, others fail
 */
err_bsp_t api_hash_init(api_hash_ctx_s *pctx_s, u32 algorithm)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_hash_ctx_s *tee_pctx = NULL;
	api_hash_ctx_s *eps_pctx = NULL;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx_s, ERR_HAL(ERRCODE_NULL));

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = (api_hash_ctx_s *)hieps_mem_new(pctx_s, sizeof(api_hash_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);

	/* 3. convert tee addr to eps addr */
	eps_pctx = hieps_mem_convert2hieps(tee_pctx);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_HASH_INIT, FUNC_PARAMS_2,
			     eps_pctx, algorithm);
	PAL_ERR_GOTO(ret, return_tag);

	/* 5. output result */
	(void)memcpy_s(pctx_s, sizeof(api_hash_ctx_s), tee_pctx, sizeof(api_hash_ctx_s));

return_tag:
	hieps_mem_delete(tee_pctx);
	return ret;
}

/**
 * @brief      : hash update
 * @param[in]  : pctx_s, pointer to context
 * @param[in]  : pdin, pointer indata, TEE buffer
 * @param[in]  : dinlen, length in byte of pdin
 * @return     : BSP_RET_OK if successful, others fail
 */
err_bsp_t api_hash_update(api_hash_ctx_s *pctx_s, pal_master_addr_t pdin, u32 dinlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	uint32_t pm_ret = HIEPS_ERROR;
	api_hash_ctx_s *tee_pctx = NULL;
	u8 *tee_pdin = NULL;
	u32 tee_dinlen;
	u32 offset = 0;

	/* check param */
	PAL_CHECK_RETURN(!pctx_s, ERR_HAL(ERRCODE_NULL));
	if (dinlen == 0)
		return BSP_RET_OK;

	PAL_CHECK_RETURN(!pdin, ERR_HAL(ERRCODE_PARAMS));

	pm_ret = hieps_power_on(SELF_CTRL_MULTI, PROFILE_KEEP);
	PAL_CHECK_RETURN((pm_ret != HIEPS_OK), ERR_DRV(ERRCODE_SYS));

	/* malloc space for pointer in shared DDR */
	tee_pctx = (api_hash_ctx_s *)hieps_mem_new(pctx_s, sizeof(api_hash_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);

	if (dinlen > HASH_MAX_DATALEN) {
		tee_pdin = (u8 *)hieps_mem_new(NULL, HASH_MAX_DATALEN);
		tee_dinlen = HASH_MAX_DATALEN;
	} else {
		tee_pdin = (u8 *)hieps_mem_new(NULL, dinlen);
		tee_dinlen = dinlen;
	}
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), return_tag);

	while (dinlen > HASH_MAX_DATALEN) {
		libc_ret = memcpy_s(tee_pdin, tee_dinlen, pdin + offset, HASH_MAX_DATALEN);
		PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);
		/* ipc send and wait response */
		ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_HASH_UPDATE, FUNC_PARAMS_4,
				     hieps_mem_convert2hieps(tee_pctx), tee_pdin, 0, HASH_MAX_DATALEN);
		PAL_ERR_GOTO(ret, return_tag);
		offset += HASH_MAX_DATALEN;
		dinlen -= HASH_MAX_DATALEN;
	}

	if (dinlen > 0) {
		libc_ret = memcpy_s(tee_pdin, tee_dinlen, pdin + offset, dinlen);
		PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);

		/* ipc send and wait response */
		ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_HASH_UPDATE, FUNC_PARAMS_4,
				     hieps_mem_convert2hieps(tee_pctx), tee_pdin, 0, dinlen);
		PAL_ERR_GOTO(ret, return_tag);
	}

	/* output result */
	libc_ret = memcpy_s(pctx_s, sizeof(api_hash_ctx_s), tee_pctx, sizeof(api_hash_ctx_s));
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);

return_tag:
	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdin);
	pm_ret = hieps_power_off(SELF_CTRL_MULTI, PROFILE_KEEP);
	PAL_CHECK_RETURN((pm_ret != HIEPS_OK), ERR_DRV(ERRCODE_SYS));
	return ret;
}

err_bsp_t api_hash_dofinal(api_hash_ctx_s *pctx_s,
			   pal_master_addr_t pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	api_hash_ctx_s *tee_pctx = NULL;
	u8 *tee_pdin = NULL;
	u8  *tee_pdout    = NULL;
	u32 *tee_pdoutlen = NULL;

	api_hash_ctx_s *eps_pctx = NULL;
	u8  *eps_pdout    = NULL;
	u32 *eps_pdoutlen = NULL;
	u32 outlen_actual;
	errno_t libc_ret = EINVAL;

	/* 1. check param */
	PAL_CHECK_RETURN(!pctx_s || !pdout || !pdoutlen, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pdin && (dinlen != 0), ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(pdin && (dinlen == 0), ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(dinlen > HASH_MAX_DATALEN, ERR_API(ERRCODE_PARAMS));

	outlen_actual = symm_get_doutlen(pctx_s->algorithm, 0, dinlen);
	PAL_CHECK_RETURN(outlen_actual > *pdoutlen, ERR_API(ERRCODE_PARAMS));

	/* 2. malloc space for pointer in shared DDR */
	tee_pctx = (api_hash_ctx_s *)hieps_mem_new(pctx_s, sizeof(api_hash_ctx_s));
	PAL_CHECK_GOTO(!tee_pctx, ERR_HAL(ERRCODE_NULL), return_tag);
	if (dinlen != 0) {
		tee_pdin = (u8 *)hieps_mem_new(pdin, dinlen);
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
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_HASH_DOFINAL, FUNC_PARAMS_6,
			     eps_pctx, tee_pdin, 0, dinlen, eps_pdout, eps_pdoutlen);
	PAL_ERR_GOTO(ret, return_tag);

	/* 5. output result */
	PAL_CHECK_GOTO(*tee_pdoutlen > SYMM_OUTLEN_HASH_MAX, ERR_HAL(ERRCODE_VERIFY), return_tag);
	libc_ret = memcpy_s(pdout, *pdoutlen, tee_pdout, *tee_pdoutlen);
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);
	*pdoutlen = *tee_pdoutlen;

return_tag:
	/* free */
	hieps_mem_delete(tee_pctx);
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

