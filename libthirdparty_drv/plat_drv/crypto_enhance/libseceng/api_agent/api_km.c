/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: implement key management agent
 * Author     : l00370476
 * Create     : 2019/11/02
 */
#include <api_km.h>
#include <hieps_agent.h>
#include <pal_libc.h>

#define BSP_THIS_MODULE   BSP_MODULE_KM
#define LENGTH_OF_8_BYTES 8

/**
 * @brief     : static function, only called for api_decrypt_licence_hmack and api_decrypt_session_key
 * @param[in] : func_id FUNC_API_DECRYPT_LICENCE_HMACK or FUNC_API_DECRYPT_SESSION_KEY
 * @param[in] : pkey   pointer to RSA key(ciphertext)
 * @param[in] : pdin   pointer to indata, which is ciphertext of HMACK
 * @param[in] : dinlen length in bytes of pdin
 * @param[in] : pdout  pointer to outbuf to hold "plaintext" of key which is not the real plaintext
 * @param[in] : pdoutlen, in:cant less than real outlen out:real outlen
 * @return    : BSP_RET_OK if successful, others if fail
 */
PRIVATE err_bsp_t s_api_do_gen_key(u32 func_id, hal_rsa_key_s *pkey, u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	u8 *tee_pn = NULL;
	u8 *tee_pd = NULL;
	hal_rsa_key_s *tee_pkey = NULL;
	u8  *tee_pdin     = NULL;
	u8  *tee_pdout    = NULL;
	u32 *tee_pdoutlen = NULL;
	hal_rsa_key_s *eps_pkey = NULL;
	u8  *eps_pdin     = NULL;
	u8  *eps_pdout    = NULL;
	u32 *eps_pdoutlen = NULL;
	errno_t libc_ret;

	/* 1. check param */
	PAL_CHECK_RETURN(!pkey || !pdin || !pdout || !pdoutlen, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pkey->pn || !pkey->pd, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(pkey->width > RSA_WIDTH_4096, ERR_HAL(ERRCODE_PARAMS));

	/* 2. malloc space for pointer in shared DDR */
	tee_pn   = (u8 *)hieps_mem_new(pkey->pn, BIT2BYTE(pkey->width));
	PAL_CHECK_GOTO(!tee_pn, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pd   = (u8 *)hieps_mem_new(pkey->pd, BIT2BYTE(pkey->width));
	PAL_CHECK_GOTO(!tee_pd, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pkey = (hal_rsa_key_s *)hieps_mem_new(pkey, sizeof(*pkey));
	PAL_CHECK_GOTO(!tee_pkey, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pdin = (u8 *)hieps_mem_new(pdin, dinlen);
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pdout = (u8 *)hieps_mem_new(NULL, *pdoutlen);
	PAL_CHECK_GOTO(!tee_pdout, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pdoutlen = (u32 *)hieps_mem_new(pdoutlen, sizeof(*pdoutlen));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), km_return);

	/* 3. convert tee addr to eps addr */
	eps_pkey       = hieps_mem_convert2hieps(tee_pkey);
	eps_pdin       = hieps_mem_convert2hieps(tee_pdin);
	eps_pdout      = hieps_mem_convert2hieps(tee_pdout);
	eps_pdoutlen   = hieps_mem_convert2hieps(tee_pdoutlen);
	tee_pkey->pn   = hieps_mem_convert2hieps(tee_pn);
	tee_pkey->pe   = NULL;
	tee_pkey->pd   = hieps_mem_convert2hieps(tee_pd);
	tee_pkey->elen = 0;

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     func_id, FUNC_PARAMS_5, eps_pkey, eps_pdin, dinlen, eps_pdout, eps_pdoutlen);
	PAL_ERR_GOTO(ret, km_return);

	/* 5. output result */
	libc_ret = memcpy_s(pdout, *pdoutlen, tee_pdout, *tee_pdoutlen);
	PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), km_return);
	*pdoutlen = *tee_pdoutlen;

km_return:
	/* clear private key before free */
	if (tee_pd) {
		(void)memset_s(tee_pd, BIT2BYTE(pkey->width), 0, BIT2BYTE(pkey->width));
		hieps_mem_delete(tee_pd);
	}
	/* free */
	hieps_mem_delete(tee_pn);
	hieps_mem_delete(tee_pkey);
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

PRIVATE err_bsp_t s_api_encrypt_client_privk_check_param(api_enc_client_privk_s *pprivk)
{
	PAL_CHECK_RETURN(!pprivk, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pprivk->pdin || !pprivk->pdout ||
			 !pprivk->pdoutlen, ERR_HAL(ERRCODE_NULL));
	PAL_CHECK_RETURN(pprivk->dinlen == 0, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(*pprivk->pdoutlen < LENGTH_OF_8_BYTES, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(*pprivk->pdoutlen - LENGTH_OF_8_BYTES < pprivk->dinlen, ERR_HAL(ERRCODE_PARAMS));
	/* overflow */
	PAL_CHECK_RETURN(pprivk->dinlen + LENGTH_OF_8_BYTES < LENGTH_OF_8_BYTES,
			 ERR_HAL(ERRCODE_PARAMS));

	return BSP_RET_OK;
}

/**
 * @brief      : encrypt client RSA private key
 *               func flow:
 *               1)copy all the params to shared DDR
 *               2)ipc send and wait response
 * @param[in]  : pdin, pointer to RSA private plaintext key(TEE VA)
 * @param[in]  : dinlen, length in bytes of pdin
 * @param[out] : pdout, pointer to outbuffer to hold RSA ciphertext key(TEE VA)
 * @param[io]  : pdoutlen, in:cant less than real outlen, out:real outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_encrypt_client_privk(api_enc_client_privk_s *pprivk)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	u8  *tee_pdin     = NULL;
	u8  *tee_pdout    = NULL;
	u32 *tee_pdoutlen = NULL;
	api_enc_client_privk_s *tee_pprivk = NULL;
	u8  *eps_pdin     = NULL;
	u8  *eps_pdout    = NULL;
	u32 *eps_pdoutlen = NULL;
	api_enc_client_privk_s *eps_pprivk = NULL;
	errno_t libc_ret;

	/* 1. check param */
	ret = s_api_encrypt_client_privk_check_param(pprivk);
	PAL_ERR_RETURN(ret);

	/* 2. malloc space for pointer in shared DDR */
	tee_pdin = (u8 *)hieps_mem_new(pprivk->pdin, pprivk->dinlen);
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pdout = (u8 *)hieps_mem_new(NULL, pprivk->dinlen + LENGTH_OF_8_BYTES);
	PAL_CHECK_GOTO(!tee_pdout, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pdoutlen = (u32 *)hieps_mem_new(NULL, sizeof(*tee_pdoutlen));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), km_return);
	*tee_pdoutlen = pprivk->dinlen + LENGTH_OF_8_BYTES;
	tee_pprivk = (api_enc_client_privk_s *)hieps_mem_new(pprivk, sizeof(*tee_pprivk));
	PAL_CHECK_GOTO(!tee_pprivk, ERR_HAL(ERRCODE_NULL), km_return);

	/* 3. convert tee addr to eps addr */
	eps_pdin     = hieps_mem_convert2hieps(tee_pdin);
	eps_pdout    = hieps_mem_convert2hieps(tee_pdout);
	eps_pdoutlen = hieps_mem_convert2hieps(tee_pdoutlen);
	eps_pprivk   = hieps_mem_convert2hieps(tee_pprivk);
	tee_pprivk->pdin     = eps_pdin;
	tee_pprivk->pdout    = eps_pdout;
	tee_pprivk->pdoutlen = eps_pdoutlen;

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT,
			     FUNC_API_ENCRYPT_CLIENT_PRIVK, FUNC_PARAMS_1, eps_pprivk);
	PAL_ERR_GOTO(ret, km_return);

	/* 5. output result */
	libc_ret = memcpy_s(pprivk->pdout, *pprivk->pdoutlen, tee_pdout, *tee_pdoutlen);
	PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), km_return);
	*pprivk->pdoutlen = *tee_pdoutlen;

km_return:
	/* clear key info in share memroy before free */
	if (tee_pdin)
		(void)memset_s(tee_pdin, pprivk->dinlen, 0, pprivk->dinlen);
	if (tee_pprivk)
		(void)memset_s(tee_pprivk->key, sizeof(tee_pprivk->key), 0, sizeof(tee_pprivk->key));
	/* free */
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	hieps_mem_delete(tee_pprivk);
	return ret;
}

/*
 * @brief      : generate licence hmac key
 * @param[in]  : pkey, pointer to RSA key(ciphertext)
 * @param[in]  : pdin, pointer to indata, which is ciphertext of HMACK
 * @param[in]  : dinlen, length in bytes of pdin
 * @param[out] : pdout, pointer to outbuf to hold "plaintext" of HMAC
 *               which is not the real plaintext
 * @param[io]  : pdoutle, in:cant less than real outlen, out:real outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_decrypt_licence_hmack(hal_rsa_key_s *pkey, u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	return s_api_do_gen_key(FUNC_API_DECRYPT_LICENCE_HMACK, pkey, pdin, dinlen, pdout, pdoutlen);
}

err_bsp_t api_decrypt_session_key(hal_rsa_key_s *pkey, u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	return s_api_do_gen_key(FUNC_API_DECRYPT_SESSION_KEY, pkey, pdin, dinlen, pdout, pdoutlen);
}

/**
 * @brief      : generate cek(content encryption key)
 * @param[in]  : pdin pointer to cek ciphertext
 * @param[in]  : dinlen length in bytes of pdin
 * @param[out] : pdout pointer to hold cek "plaintext", it's not the real plaintext
 * @param[io]  : pdoutlen, in:cant less than real outlen out:real outlen
 * @return     : BSP_RET_OK if successful, others if fail
 */
err_bsp_t api_decrypt_cek(u8 *pdin, u32 dinlen, u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);
	u8  *tee_pdin     = NULL;
	u8  *tee_pdout    = NULL;
	u32 *tee_pdoutlen = NULL;
	u8  *eps_pdin     = NULL;
	u8  *eps_pdout    = NULL;
	u32 *eps_pdoutlen = NULL;
	errno_t libc_ret;

	/* 1. check param */
	PAL_CHECK_RETURN(!pdin || !pdout || !pdoutlen, ERR_HAL(ERRCODE_NULL));

	/* 2. malloc space for pointer in shared DDR */
	tee_pdin = (u8 *)hieps_mem_new(pdin, dinlen);
	PAL_CHECK_GOTO(!tee_pdin, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pdout = (u8 *)hieps_mem_new(NULL, *pdoutlen);
	PAL_CHECK_GOTO(!tee_pdout, ERR_HAL(ERRCODE_NULL), km_return);
	tee_pdoutlen = (u32 *)hieps_mem_new(pdoutlen, sizeof(*pdoutlen));
	PAL_CHECK_GOTO(!tee_pdoutlen, ERR_HAL(ERRCODE_NULL), km_return);

	/* 3. convert tee addr to eps addr */
	eps_pdin     = hieps_mem_convert2hieps(tee_pdin);
	eps_pdout    = hieps_mem_convert2hieps(tee_pdout);
	eps_pdoutlen = hieps_mem_convert2hieps(tee_pdoutlen);

	/* 4. ipc send and wait response */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_DECRYPT_CEK, FUNC_PARAMS_4,
			     eps_pdin, dinlen, eps_pdout, eps_pdoutlen);
	PAL_ERR_GOTO(ret, km_return);

	/* 5. output result */
	PAL_CHECK_GOTO(*tee_pdoutlen != BIT2BYTE(SYMM_WIDTH_128), ERR_HAL(ERRCODE_VERIFY), km_return);
	libc_ret = memcpy_s(pdout, *pdoutlen, tee_pdout, *tee_pdoutlen);
	PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), km_return);
	*pdoutlen = *tee_pdoutlen;

km_return:
	/* free */
	hieps_mem_delete(tee_pdin);
	hieps_mem_delete(tee_pdout);
	hieps_mem_delete(tee_pdoutlen);
	return ret;
}

