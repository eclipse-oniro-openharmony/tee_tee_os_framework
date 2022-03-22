/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2020. All rights reserved.
 * Description: implement sm2
 * Author     : z00293770
 * Create     : 2019/11/02
 */
#include <api_sm2.h>
#include <pal_log.h>
#include <common_utils.h>
#include <hieps_agent.h>
#include <pal_libc.h>
#include <api_utils.h>

#define BSP_THIS_MODULE BSP_MODULE_ECC

#define USERID_MAX_BITS 0x10000

static err_bsp_t ecc_key_check_param(enum ecc_key_e key_e, struct hal_ecc_key_s *pkey)
{
	PAL_CHECK_RETURN(!pkey, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(pkey->width != SM2_KEY_WIDTH, ERR_API(ERRCODE_PARAMS));

	/* check private key */
	if (((u32)key_e & ECC_KEY_PRIV) == ECC_KEY_PRIV)
		PAL_CHECK_RETURN(!pkey->ppriv, ERR_API(ERRCODE_NULL));

	if (((u32)key_e & ECC_KEY_PUB) == ECC_KEY_PUB)
		PAL_CHECK_RETURN(!pkey->ppubx || !pkey->ppuby, ERR_API(ERRCODE_NULL));

	return BSP_RET_OK;
}

static err_bsp_t sm2_sign_check_common_param(enum ecc_key_e key_e, struct hal_ecc_key_s *pkey,
					     u8 *pid, u8 *pmsg, u8 *psign)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	ret = ecc_key_check_param(key_e, pkey);
	PAL_ERR_RETURN(ret);

	PAL_CHECK_RETURN(!pid, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pmsg, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!psign, ERR_API(ERRCODE_NULL));

	return BSP_RET_OK;
}

/* clear and free mem */
static inline void ecc_mem_clear(u8 *mem, u32 len)
{
	mem = hieps_mem_convert2tee(mem);
	if (mem) {
		(void)memset_s(mem, len, 0, len);
		hieps_mem_delete(mem);
	}
}

static void ecc_key_mem_clear(struct hal_ecc_key_s *pkey)
{
	u32 klen;

	pkey = hieps_mem_convert2tee(pkey);
	if (!pkey)
		return;

	klen = BIT2BYTE(pkey->width);

	/* clear and free key structure */
	if (pkey->ppriv)
		ecc_mem_clear(pkey->ppriv, klen);

	if (pkey->ppubx)
		ecc_mem_clear(pkey->ppubx, klen);

	if (pkey->ppuby)
		ecc_mem_clear(pkey->ppuby, klen);

	hieps_mem_delete(pkey);
}

static err_bsp_t ecc_key_mem_new(enum ecc_key_e key_e, struct hal_ecc_key_s *src, struct hal_ecc_key_s **dst)
{
	struct hal_ecc_key_s *dst_tee = NULL;
	u32 klen = BIT2BYTE(src->width);
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	PAL_CHECK_RETURN(!src, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!dst, ERR_API(ERRCODE_NULL));
	dst_tee = hieps_mem_new(NULL, sizeof(struct hal_ecc_key_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);
	dst_tee->width = src->width;
	dst_tee->ppriv = NULL;
	dst_tee->ppubx = NULL;
	dst_tee->ppuby = NULL;

	if (((u32)key_e & ECC_KEY_PRIV) == ECC_KEY_PRIV) {
		dst_tee->ppriv = hieps_mem_new(src->ppriv, klen);
		PAL_CHECK_GOTO(!dst_tee->ppriv, ERR_API(ERRCODE_MEMORY), err_return);
		dst_tee->ppriv = hieps_mem_convert2hieps(dst_tee->ppriv);
	}

	if (((u32)key_e & ECC_KEY_PUB) == ECC_KEY_PUB) {
		dst_tee->ppubx = hieps_mem_new(src->ppubx, klen);
		PAL_CHECK_GOTO(!dst_tee->ppubx, ERR_API(ERRCODE_MEMORY), err_return);
		dst_tee->ppubx = hieps_mem_convert2hieps(dst_tee->ppubx);
		dst_tee->ppuby = hieps_mem_new(src->ppuby, klen);
		PAL_CHECK_GOTO(!dst_tee->ppuby, ERR_API(ERRCODE_MEMORY), err_return);
		dst_tee->ppuby = hieps_mem_convert2hieps(dst_tee->ppuby);
	}

	ret = BSP_RET_OK;
	goto sm2_return;

err_return:
	/* clear and free key in shared memory */
	ecc_key_mem_clear(*dst);

sm2_return:
	return ret;
}

/*
 * @brief      : sm2 sign with privkey, input userid and message
 * @param[in]  : pkey, privkey
 * @param[in]  : pid, the user id
 * @param[in]  : user id length
 * @param[in]  : pmsg, the raw data need to sign
 * @param[in]  : massage length
 * @param[out]  : psign, the out buffer for the signature
 * @param[in/out]  : signature length
 */
err_bsp_t api_sm2_sign(struct hal_ecc_key_s *pkey,
		       u8 *pid, u32 idlen, u8 *pmsg, u32 msglen, u8 *psign, u32 *psignlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	u8 *pid_tee = NULL;
	u8 *pmsg_tee = NULL;
	u32 *psign_tee = NULL;
	u32 *psignlen_tee = NULL;
	u8 *pid_eps = NULL;
	u8 *pmsg_eps = NULL;
	u8 *psign_eps = NULL;
	u32 *psignlen_eps = NULL;
	struct hal_ecc_key_s *pkey_eps = NULL;

	ret = sm2_sign_check_common_param(ECC_KEY_FULL, pkey, pid,
					  pmsg, psign);
	PAL_ERR_RETURN(ret);

	PAL_CHECK_RETURN(!psignlen, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(idlen == 0 || idlen > MAX_DATA_SUPPORT,
			 ERR_API(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(msglen == 0 || msglen > MAX_DATA_SUPPORT,
			 ERR_API(ERRCODE_PARAMS));

	ret = ecc_key_mem_new(ECC_KEY_FULL, pkey, &pkey_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	pid_tee = hieps_mem_new(pid, idlen);
	PAL_CHECK_GOTO(!pid_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	pmsg_tee = hieps_mem_new(pmsg, msglen);
	PAL_CHECK_GOTO(!pmsg_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	psign_tee = hieps_mem_new(NULL, SM2_POINT_LEN);
	PAL_CHECK_GOTO(!psign_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	psignlen_tee = hieps_mem_new(psignlen, sizeof(*psignlen));
	PAL_CHECK_GOTO(!psignlen_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	/* ipc send */
	pid_eps = hieps_mem_convert2hieps(pid_tee);
	pmsg_eps = hieps_mem_convert2hieps(pmsg_tee);
	psign_eps = hieps_mem_convert2hieps(psign_tee);
	psignlen_eps = hieps_mem_convert2hieps(psignlen_tee);
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_SM2_SIGN,
			     FUNC_PARAMS_7, pkey_eps, pid_eps, idlen,
			     pmsg_eps, msglen, psign_eps, psignlen_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	/* copy sign structure */
	libc_ret = memcpy_s(psign, *psignlen, psign_tee, *psignlen_tee);
	PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), sm2_return);
	*psignlen = *psignlen_tee;

sm2_return:
	/* clear and free key in shared memory */
	ecc_key_mem_clear(pkey_eps);
	/* free  shared memory */
	hieps_mem_delete(pid_tee);
	hieps_mem_delete(pmsg_tee);
	hieps_mem_delete(psign_tee);
	hieps_mem_delete(psignlen_tee);

	return ret;
}

/*
 * @brief      : verify the signature with sm2 pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pid, the user id
 * @param[in]  : user id length
 * @param[in]  : pmsg, the raw data of the sign
 * @param[in]  : massage length
 * @param[in]  : psign , the sigature to be verify
 * @param[in]  : signlen , the signature length
 * @note       : input the hash of the msg
 */
err_bsp_t api_sm2_verify(struct hal_ecc_key_s *pkey,
			 u8 *pid, u32 idlen, u8 *pmsg, u32 msglen, u8 *psign, u32 signlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u8 *pid_tee = NULL;
	u8 *pmsg_tee = NULL;
	u32 *psign_tee = NULL;
	u8 *pid_eps = NULL;
	u8 *pmsg_eps = NULL;
	u8 *psign_eps = NULL;
	struct hal_ecc_key_s *pkey_eps = NULL;

	ret = sm2_sign_check_common_param(ECC_KEY_PUB, pkey, pid, pmsg, psign);
	PAL_ERR_RETURN(ret);
	PAL_CHECK_RETURN(signlen != SM2_POINT_LEN, ERR_API(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(idlen == 0 || idlen > MAX_DATA_SUPPORT,
			 ERR_API(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(msglen == 0 || msglen > MAX_DATA_SUPPORT,
			 ERR_API(ERRCODE_PARAMS));

	ret = ecc_key_mem_new(ECC_KEY_PUB, pkey, &pkey_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	pid_tee = hieps_mem_new(pid, idlen);
	PAL_CHECK_GOTO(!pid_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	pmsg_tee = hieps_mem_new(pmsg, msglen);
	PAL_CHECK_GOTO(!pmsg_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	psign_tee = hieps_mem_new(psign, signlen);
	PAL_CHECK_GOTO(!psign_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	pid_eps = hieps_mem_convert2hieps(pid_tee);
	pmsg_eps = hieps_mem_convert2hieps(pmsg_tee);
	psign_eps = hieps_mem_convert2hieps(psign_tee);
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_SM2_VERIFY,
			     FUNC_PARAMS_7, pkey_eps, pid_eps, idlen,
			     pmsg_eps, msglen, psign_eps, signlen);
	PAL_ERR_GOTO(ret, sm2_return);

sm2_return:
	/* clear and free key in shared memory */
	ecc_key_mem_clear(pkey_eps);
	/* free shared memory */
	hieps_mem_delete(pid_tee);
	hieps_mem_delete(pmsg_tee);
	hieps_mem_delete(psign_tee);

	return ret;
}

static err_bsp_t s_sm2_crypto(enum ecc_key_e key_e,
			      struct hal_ecc_key_s *pkey, u8 *pin, u32 inlen, u8 *pout, u32 *poutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	u8 *pin_tee = NULL;
	u8 *pout_tee = NULL;
	u32 *poutlen_tee = NULL;
	u8 *pin_eps = NULL;
	u8 *pout_eps = NULL;
	u32 *poutlen_eps = NULL;
	struct hal_ecc_key_s *pkey_eps = NULL;
	u32 func_id;
	u32 outlen_actual;

	ret = ecc_key_check_param(key_e, pkey);
	PAL_ERR_RETURN(ret);
	PAL_CHECK_RETURN(!pin, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!pout, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!poutlen, ERR_API(ERRCODE_NULL));

	if (key_e == ECC_KEY_PUB) {
		PAL_CHECK_RETURN(inlen == 0, ERR_API(ERRCODE_PARAMS));
		outlen_actual = SM2_C_LEN(inlen);
	} else {
		PAL_CHECK_RETURN(inlen <= SM2_C_LEN(0), ERR_API(ERRCODE_PARAMS));
		outlen_actual = inlen - SM2_C_LEN(0);
	}
	PAL_CHECK_RETURN(outlen_actual > *poutlen, ERR_API(ERRCODE_PARAMS));

	ret = ecc_key_mem_new(key_e, pkey, &pkey_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	pin_tee = hieps_mem_new(pin, inlen);
	PAL_CHECK_GOTO(!pin_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	pout_tee = hieps_mem_new(NULL, outlen_actual);
	PAL_CHECK_GOTO(!pout_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	poutlen_tee = hieps_mem_new(&outlen_actual, sizeof(u32));
	PAL_CHECK_GOTO(!poutlen_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	/* ipc send */
	pin_eps = hieps_mem_convert2hieps(pin_tee);
	pout_eps = hieps_mem_convert2hieps(pout_tee);
	poutlen_eps = hieps_mem_convert2hieps(poutlen_tee);
	if (key_e == ECC_KEY_PUB)
		func_id = FUNC_API_SM2_ENCRYPT;
	else
		func_id = FUNC_API_SM2_DECRYPT;
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, func_id,
			     FUNC_PARAMS_5, pkey_eps, pin_eps, inlen,
			     pout_eps, poutlen_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	libc_ret = memcpy_s(pout, *poutlen, pout_tee, *poutlen_tee);
	PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), sm2_return);
	*poutlen = *poutlen_tee;

sm2_return:
	/* clear and free key in shared memory */
	ecc_key_mem_clear(pkey_eps);
	/* free shared memory */
	hieps_mem_delete(pin_tee);
	hieps_mem_delete(pout_tee);
	hieps_mem_delete(poutlen_tee);

	return ret;
}

/*
 * @brief      : sm2 encrypt, encrypto msg with pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pin, the input msg
 * @param[in]  : inlen , the msg length
 * @param[out] : pout, the cipher msg
 * @param[in]  : outlen , the out buffer length
 * @note       : encrypto msg with sm2 pubkey
 */
err_bsp_t api_sm2_encrypt(struct hal_ecc_key_s *pkey, u8 *pin, u32 inlen, u8 *pout, u32 *poutlen)
{
	PAL_CHECK_RETURN(inlen == 0 || inlen > MAX_DATA_SUPPORT, ERR_API(ERRCODE_PARAMS));
	return s_sm2_crypto(ECC_KEY_PUB, pkey, pin, inlen, pout, poutlen);
}

/*
 * @brief      : decrypto msg with sm2 privkey
 * @param[in]  : pkey, input privkey
 * @param[in]  : pin, the cipher msg
 * @param[in]  : inlen, the msg len
 * @param[out] : pout, the plain msg
 * @param[in]  : outlen , the out buffer size
 */
err_bsp_t api_sm2_decrypt(struct hal_ecc_key_s *pkey, u8 *pin, u32 inlen, u8 *pout, u32 *poutlen)
{
	PAL_CHECK_RETURN(inlen <= SM2_C_LEN(0) || inlen > SM2_C_LEN(MAX_DATA_SUPPORT), ERR_API(ERRCODE_PARAMS));

	return s_sm2_crypto(ECC_KEY_PRIV, pkey, pin, inlen, pout, poutlen);
}

/**
 * @brief         : sm2 sign with privkey, input digest data(e in the spec)
 * @param[in]  : pkey, privkey
 * @param[in]  : pdigest, is hash with userid, msg , curse, pubkey
 * @param[in]  : pdigest length
 * @param[out]  : psign, the out buffer for the signature
 * @param[in/out]  : signature length
 */
err_bsp_t api_sm2_digest_sign(struct hal_ecc_key_s *pkey, u8 *pdigest, u32 digestlen, u8 *psign, u32 *psignlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	u8 *pdigest_tee = NULL;
	u32 *psign_tee = NULL;
	u32 *psignlen_tee = NULL;
	u8 *pdigest_eps = NULL;
	u8 *psign_eps = NULL;
	u32 *psignlen_eps = NULL;
	struct hal_ecc_key_s *pkey_eps = NULL;

	ret = ecc_key_check_param(ECC_KEY_PRIV, pkey);
	PAL_ERR_RETURN(ret);

	PAL_CHECK_RETURN(!pdigest, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!psign, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!psignlen, ERR_API(ERRCODE_NULL));

	ret = ecc_key_mem_new(ECC_KEY_PRIV, pkey, &pkey_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	pdigest_tee = hieps_mem_new(pdigest, digestlen);
	PAL_CHECK_GOTO(!pdigest_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	psign_tee = hieps_mem_new(NULL, SM2_POINT_LEN);
	PAL_CHECK_GOTO(!psign_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	psignlen_tee = hieps_mem_new(NULL, sizeof(*psignlen));
	PAL_CHECK_GOTO(!psignlen_tee, ERR_API(ERRCODE_MEMORY), sm2_return);
	 *psignlen_tee = SM2_POINT_LEN;

	/* ipc send */
	pdigest_eps = hieps_mem_convert2hieps(pdigest_tee);
	psign_eps = hieps_mem_convert2hieps(psign_tee);
	psignlen_eps = hieps_mem_convert2hieps(psignlen_tee);
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_SM2_DIGEST_SIGN,
						 FUNC_PARAMS_5, pkey_eps, pdigest_eps, digestlen,
						 psign_eps, psignlen_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	/* copy sign structure */
	libc_ret = memcpy_s(psign, *psignlen, psign_tee, *psignlen_tee);
	PAL_CHECK_GOTO(libc_ret != EOK, ERR_API(ERRCODE_MEMORY), sm2_return);
	*psignlen = *psignlen_tee;

sm2_return:
	/* clear and free key in shared memory */
	ecc_key_mem_clear(pkey_eps);
	/* free  shared memory */
	hieps_mem_delete(pdigest_tee);
	hieps_mem_delete(psign_tee);
	hieps_mem_delete(psignlen_tee);

	return ret;
}

/**
 * @brief      : verify the signature with sm2 pubkey
 * @param[in]  : pkey, input pubkey
 * @param[in]  : pdigest, is hash with userid, msg , curse, pubkey
 * @param[in]  : pdigest length
 * @param[in]  : psign , the sigature to be verify
 * @param[in]  : signlen , the signature length
 */
err_bsp_t api_sm2_digest_verify(struct hal_ecc_key_s *pkey, u8 *pdigest, u32 digestlen, u8 *psign, u32 signlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u8 *pdigest_tee = NULL;
	u32 *psign_tee = NULL;
	u8 *pdigest_eps = NULL;
	u8 *psign_eps = NULL;
	struct hal_ecc_key_s *pkey_eps = NULL;

	ret = ecc_key_check_param(ECC_KEY_PUB, pkey);
	PAL_ERR_RETURN(ret);

	PAL_CHECK_RETURN(!pdigest, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(!psign, ERR_API(ERRCODE_NULL));
	PAL_CHECK_RETURN(signlen != SM2_POINT_LEN, ERR_API(ERRCODE_PARAMS));

	ret = ecc_key_mem_new(ECC_KEY_PUB, pkey, &pkey_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	pdigest_tee = hieps_mem_new(pdigest, digestlen);
	PAL_CHECK_GOTO(!pdigest_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	psign_tee = hieps_mem_new(psign, signlen);
	PAL_CHECK_GOTO(!psign_tee, ERR_API(ERRCODE_MEMORY), sm2_return);

	pdigest_eps = hieps_mem_convert2hieps(pdigest_tee);
	psign_eps = hieps_mem_convert2hieps(psign_tee);
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_SM2_DIGEST_VERIFY,
						 FUNC_PARAMS_5, pkey_eps, pdigest_eps, digestlen, psign_eps, signlen);
	PAL_ERR_GOTO(ret, sm2_return);

sm2_return:
	/* clear and free key in shared memory */
	ecc_key_mem_clear(pkey_eps);
	/* free shared memory */
	hieps_mem_delete(pdigest_tee);
	hieps_mem_delete(psign_tee);

	return ret;
}

static err_bsp_t ecc_key_mem_copy(struct hal_ecc_key_s *src, struct hal_ecc_key_s *dst)
{
	struct hal_ecc_key_s *src_tee = hieps_mem_convert2tee(src);
	u32 klen = BIT2BYTE(src_tee->width);
	u8 *element_tmp =  NULL;
	errno_t libc_ret = EINVAL;

	/* copy key structure */
	element_tmp =  hieps_mem_convert2tee(src_tee->ppriv);
	libc_ret = memcpy_s(dst->ppriv, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->ppubx);
	libc_ret = memcpy_s(dst->ppubx, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->ppuby);
	libc_ret = memcpy_s(dst->ppuby, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	return BSP_RET_OK;
}

/**
 * @brief      : generate sm2 keypair
 * @param[out]  : pkey, keypair
 */
err_bsp_t api_sm2_gen_keypair(struct hal_ecc_key_s *pkey)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	struct hal_ecc_key_s *pkey_eps = NULL;

	PAL_CHECK_RETURN(!pkey, ERR_API(ERRCODE_NULL));

	pkey->width = SM2_KEY_WIDTH;
	ret = ecc_key_mem_new(ECC_KEY_FULL, pkey, &pkey_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_SM2_GEN_KEYPAIR, FUNC_PARAMS_1, pkey_eps);
	PAL_ERR_GOTO(ret, sm2_return);

	/* copy apikey structure from shared memory to tee memory */
	ret = ecc_key_mem_copy(pkey_eps, pkey);
	PAL_ERR_GOTO(ret, sm2_return);

sm2_return:
	/* clear and free key in shared memory */
	ecc_key_mem_clear(pkey_eps);

	return ret;
}

