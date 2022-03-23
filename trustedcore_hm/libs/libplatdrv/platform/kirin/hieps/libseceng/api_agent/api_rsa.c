/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2020. All rights reserved.
 * Description: implement rsa
 * Author     : z00293770
 * Create     : 2018/12/06
 */
#include <api_rsa.h>
#include <hal_rsa.h>
#include <pal_log.h>
#include <common_utils.h>
#include <hieps_agent.h>
#include <api_utils.h>
#include <pal_libc.h>

/* set the module to which the file belongs, each .C file needs to be configured */
#define BSP_THIS_MODULE        BSP_MODULE_RSA

static err_bsp_t rsa_stdkey_check_param(hal_rsa_key_s *pkey_s)
{
	PAL_CHECK_RETURN(!pkey_s,  ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pe,  ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pn,  ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN((pkey_s->elen == 0) || (pkey_s->elen % sizeof(u32) != 0), ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN((pkey_s->width > RSA_WIDTH_MAX) || (pkey_s->width < RSA_WIDTH_512), ERR_HAL(ERRCODE_PARAMS));

	return BSP_RET_OK;
}

static err_bsp_t rsa_crtkey_check_param(hal_rsa_crtkey_s *pkey_s)
{
	PAL_CHECK_RETURN(!pkey_s, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pn, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pp, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pq, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pdp, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pdq, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pkey_s->pqinv, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(pkey_s->width > RSA_WIDTH_MAX || pkey_s->width < RSA_WIDTH_512, ERR_HAL(ERRCODE_PARAMS));

	return BSP_RET_OK;
}

static err_bsp_t rsa_genkey_check_param(api_param_s *pkey_s)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	switch (pkey_s->sub_mode) {
	case ALG_RSA_STD_KEY:
		ret = rsa_stdkey_check_param((hal_rsa_key_s *)(pkey_s->object));
		PAL_ERR_RETURN(ret);
		break;
	case ALG_RSA_CRT_KEY:
		ret = rsa_crtkey_check_param((hal_rsa_crtkey_s *)(pkey_s->object));
		PAL_ERR_RETURN(ret);
		break;
	default:
		ret = ERR_API(ERRCODE_PARAMS);
		break;
	}

	return ret;
}

/*
 * @brief      : rsa_free_tee_mem, free tee memory
 * @param[in]  : mem point to tee memory addr
 */
static inline void rsa_free_tee_mem(const void *mem)
{
	if (mem)
		hieps_mem_delete(mem);
}

/*
 * @brief      : rsa_free_hieps_mem, free the shared(tee and hieps) memory
 * @param[in]  : mem is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 */
static inline void rsa_free_hieps_mem(const void *mem)
{
	if (mem) {
		mem = hieps_mem_convert2tee(mem);
		hieps_mem_delete(mem);
	}
}

/*
 * @brief      : rsa_free_stdkey_struct, free the shared(tee and hieps) memory
 * @param[in]  : key_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 */
static void rsa_free_stdkey_struct(hal_rsa_key_s *key_s)
{
	if (!key_s)
		return;

	key_s = hieps_mem_convert2tee(key_s);
	rsa_free_hieps_mem(key_s->pd);
	rsa_free_hieps_mem(key_s->pn);
	rsa_free_hieps_mem(key_s->pe);
	rsa_free_tee_mem(key_s);
}

/*
 * @brief      : rsa_free_crtkey_struct, free the shared(tee and hieps) memory
 * @param[in]  : key_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 */
static void rsa_free_crtkey_struct(hal_rsa_crtkey_s *key_s)
{
	if (!key_s)
		return;

	key_s = hieps_mem_convert2tee(key_s);
	rsa_free_hieps_mem(key_s->pp);
	rsa_free_hieps_mem(key_s->pq);
	rsa_free_hieps_mem(key_s->pdp);
	rsa_free_hieps_mem(key_s->pdq);
	rsa_free_hieps_mem(key_s->pqinv);
	rsa_free_hieps_mem(key_s->pn);
	rsa_free_hieps_mem(key_s->pe);
	rsa_free_tee_mem(key_s);
}

/*
 * @brief      : rsa_free_apikey_struct, free the shared(tee and hieps) memory
 * @param[in]  : key_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 */
static void rsa_free_apikey_struct(api_rsa_key_s *key_s)
{
	if (!key_s)
		return;

	key_s = hieps_mem_convert2tee(key_s);
	/* free stdkey or crtkey structure */
	switch (key_s->key_type) {
	case ALG_RSA_STD_KEY:
		rsa_free_stdkey_struct((hal_rsa_key_s *)(key_s->key_info));
		break;
	case ALG_RSA_CRT_KEY:
		rsa_free_crtkey_struct((hal_rsa_crtkey_s *)(key_s->key_info));
		break;
	default:
		break;
	}
	rsa_free_tee_mem(key_s);
}

/*
 * @brief      : rsa_free_genkey_struct, free the shared(tee and hieps) memory
 * @param[in]  : key_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 */
static void rsa_free_genkey_struct(api_param_s *key_s)
{
	if (!key_s)
		return;

	key_s = hieps_mem_convert2tee(key_s);
	/* free stdkey or crtkey structure */
	switch (key_s->sub_mode) {
	case ALG_RSA_STD_KEY:
		rsa_free_stdkey_struct((hal_rsa_key_s *)(key_s->object));
		break;
	case ALG_RSA_CRT_KEY:
		rsa_free_crtkey_struct((hal_rsa_crtkey_s *)(key_s->object));
		break;
	default:
		break;
	}
	rsa_free_tee_mem(key_s);
}

/*
 * @brief      : rsa_free_sign_struct, free the shared(tee and hieps) memory
 * @param[in]  : psign_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 */
static void rsa_free_sign_struct(api_param_s *psign_s)
{
	api_rsa_pkcs_v1_5_sign_s *psign_v15 = NULL;
	api_rsa_pss_sign_s *psign_pss = NULL;

	if (!psign_s)
		return;

	psign_s = hieps_mem_convert2tee(psign_s);
	/* free stdkey or crtkey structure */
	switch (psign_s->sub_mode) {
	case ALG_RSASSA_PKCS1_V15_CLIENTSK:
	case ALG_RSASSA_PKCS1_V15:
		psign_v15 = hieps_mem_convert2tee((api_rsa_pkcs_v1_5_sign_s *)(psign_s->object));
		rsa_free_apikey_struct(psign_v15->pkey_s);
		rsa_free_hieps_mem(psign_v15->pdin);
		rsa_free_hieps_mem(psign_v15->psign);
		rsa_free_tee_mem(psign_v15);
		break;
	case ALG_RSASSA_PKCS1_PSS_CLIENTSK:
	case ALG_RSASSA_PKCS1_PSS:
		psign_pss = hieps_mem_convert2tee((api_rsa_pss_sign_s *)(psign_s->object));
		rsa_free_apikey_struct(psign_pss->pkey_s);
		rsa_free_hieps_mem(psign_pss->pdin);
		rsa_free_hieps_mem(psign_pss->psign);
		rsa_free_tee_mem(psign_pss);
		break;
	default:
		break;
	}
	rsa_free_tee_mem(psign_s);
}

/*
 * @brief      : rsa_set_stdkey_struct,  copy keypair struct from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out] : dst is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *               and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_stdkey_struct(hal_rsa_key_s *src, hal_rsa_key_s **dst)
{
	hal_rsa_key_s *dst_tee = NULL;
	/* cann't new from src, because the init value of element pointer in dst must be NULL */
	dst_tee = hieps_mem_new(NULL, sizeof(hal_rsa_key_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);

	dst_tee->elen = src->elen;
	dst_tee->width = src->width;

	dst_tee->pe = hieps_mem_new(src->pe, dst_tee->elen);
	PAL_CHECK_RETURN(!dst_tee->pe, ERR_API(ERRCODE_MEMORY));
	dst_tee->pe = hieps_mem_convert2hieps(dst_tee->pe);

	dst_tee->pn = hieps_mem_new(src->pn, BIT2BYTE(dst_tee->width));
	PAL_CHECK_RETURN(!dst_tee->pn, ERR_API(ERRCODE_MEMORY));
	dst_tee->pn = hieps_mem_convert2hieps(dst_tee->pn);

	dst_tee->pd = hieps_mem_new(src->pd, BIT2BYTE(dst_tee->width));
	PAL_CHECK_RETURN(!dst_tee->pd, ERR_API(ERRCODE_MEMORY));
	dst_tee->pd = hieps_mem_convert2hieps(dst_tee->pd);

	return BSP_RET_OK;
}

/*
 * @brief      : rsa_set_crtkey_struct, copy keypair struct from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out] : dst is a point to the shared(tee and hieps) memory addr , the pointer value is in hieps side
 *               and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_crtkey_struct(hal_rsa_crtkey_s *src, hal_rsa_crtkey_s **dst)
{
	hal_rsa_crtkey_s *dst_tee = NULL;
	u32 crtlen = CRT_PRIVKEY_LEN(src->width);

	/* cann't new from src, because the init value of element pointer in dst must be NULL */
	dst_tee = hieps_mem_new(NULL, sizeof(hal_rsa_crtkey_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);

	dst_tee->elen = src->elen;
	dst_tee->width = src->width;

	if (src->pe && src->elen > 0) {
		dst_tee->pe = hieps_mem_new(src->pe, dst_tee->elen);
		PAL_CHECK_RETURN(!dst_tee->pe, ERR_API(ERRCODE_MEMORY));
		dst_tee->pe = hieps_mem_convert2hieps(dst_tee->pe);
	} else {
		dst_tee->pe = NULL;
	}

	dst_tee->pn = hieps_mem_new(src->pn, BIT2BYTE(dst_tee->width));
	PAL_CHECK_RETURN(!dst_tee->pn, ERR_API(ERRCODE_MEMORY));
	dst_tee->pn = hieps_mem_convert2hieps(dst_tee->pn);

	dst_tee->pp = hieps_mem_new(src->pp, crtlen);
	PAL_CHECK_RETURN(!dst_tee->pp, ERR_API(ERRCODE_MEMORY));
	dst_tee->pp = hieps_mem_convert2hieps(dst_tee->pp);

	dst_tee->pq = hieps_mem_new(src->pq, crtlen);
	PAL_CHECK_RETURN(!dst_tee->pq, ERR_API(ERRCODE_MEMORY));
	dst_tee->pq = hieps_mem_convert2hieps(dst_tee->pq);

	dst_tee->pdp = hieps_mem_new(src->pdp, crtlen);
	PAL_CHECK_RETURN(!dst_tee->pdp, ERR_API(ERRCODE_MEMORY));
	dst_tee->pdp = hieps_mem_convert2hieps(dst_tee->pdp);

	dst_tee->pdq = hieps_mem_new(src->pdq, crtlen);
	PAL_CHECK_RETURN(!dst_tee->pdq, ERR_API(ERRCODE_MEMORY));
	dst_tee->pdq = hieps_mem_convert2hieps(dst_tee->pdq);

	dst_tee->pqinv = hieps_mem_new(src->pqinv, crtlen);
	PAL_CHECK_RETURN(!dst_tee->pqinv, ERR_API(ERRCODE_MEMORY));
	dst_tee->pqinv = hieps_mem_convert2hieps(dst_tee->pqinv);

	return BSP_RET_OK;
}

/*
 * @brief      : rsa_set_apikey_struct, copy keypair struct from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out] : dst is a point to the shared(tee and hieps) memory addr, and the pointer value is in hieps side
 *               and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_apikey_struct(api_rsa_key_s *src, api_rsa_key_s **dst)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_rsa_key_s *dst_tee = NULL;
	hal_rsa_key_s *pstd_key_tee = NULL;
	hal_rsa_crtkey_s *pcrt_key_tee = NULL;

	dst_tee = hieps_mem_new(NULL, sizeof(api_rsa_key_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);
	dst_tee->key_type = src->key_type;

	/* set stdkey or crtkey structure to key_info */
	switch (dst_tee->key_type) {
	case ALG_RSA_STD_KEY:
		ret = rsa_stdkey_check_param((hal_rsa_key_s *)(src->key_info));
		PAL_ERR_GOTO(ret, return_tag);
		ret = rsa_set_stdkey_struct((hal_rsa_key_s *)(src->key_info), &pstd_key_tee);
		dst_tee->key_info = pstd_key_tee;
		PAL_ERR_GOTO(ret, return_tag);
		break;
	case ALG_RSA_CRT_KEY:
		ret = rsa_crtkey_check_param((hal_rsa_crtkey_s *)(src->key_info));
		PAL_ERR_GOTO(ret, return_tag);
		ret = rsa_set_crtkey_struct((hal_rsa_crtkey_s *)(src->key_info), &pcrt_key_tee);
		dst_tee->key_info = pcrt_key_tee;
		PAL_ERR_GOTO(ret, return_tag);
		break;
	default:
		ret = ERR_API(ERRCODE_PARAMS);
		PAL_ERR_GOTO(ret, return_tag);
	}

return_tag:
	return ret;
}

/*
 * @brief      : rsa_set_genkey_struct, copy keypair struct from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out] : dst is a point to the shared(tee and hieps) memory addr, and the pointer value is in hieps side
 *                and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_genkey_struct(api_param_s *src, api_param_s **dst)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_param_s *dst_tee = NULL;
	hal_rsa_key_s *pstd_key_tee = NULL;
	hal_rsa_crtkey_s *pcrt_key_tee = NULL;

	dst_tee = hieps_mem_new(NULL, sizeof(api_param_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);
	dst_tee->operation_mode = src->operation_mode;
	dst_tee->sub_mode = src->sub_mode;

	/* set stdkey or crtkey structure to object */
	switch (dst_tee->sub_mode) {
	case ALG_RSA_STD_KEY:
		ret = rsa_stdkey_check_param((hal_rsa_key_s *)(src->object));
		PAL_ERR_RETURN(ret);
		ret = rsa_set_stdkey_struct((hal_rsa_key_s *)(src->object), &pstd_key_tee);
		dst_tee->object = pstd_key_tee;
		PAL_ERR_RETURN(ret);
		break;
	case ALG_RSA_CRT_KEY:
		ret = rsa_crtkey_check_param((hal_rsa_crtkey_s *)(src->object));
		PAL_ERR_RETURN(ret);
		ret = rsa_set_crtkey_struct((hal_rsa_crtkey_s *)(src->object), &pcrt_key_tee);
		dst_tee->object = pcrt_key_tee;
		PAL_ERR_RETURN(ret);
		break;
	default:
		ret = ERR_API(ERRCODE_PARAMS);
		break;
	}

	return ret;
}

/*
 * @brief      : rsa_get_stdkey_struct, copy keypair struct from shared(tee and hieps) memory to tee memory
 * @param[in]  : src is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *               and all of the element pointer in dst must be in hieps side
 * @param[out] : dst is a point to tee memory addr
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_get_stdkey_struct(hal_rsa_key_s *src, hal_rsa_key_s *dst)
{
	hal_rsa_key_s *src_tee = hieps_mem_convert2tee(src);
	u32 klen = BIT2BYTE(src_tee->width);
	u8 *element_tmp =  NULL;
	errno_t libc_ret = EINVAL;

	/* copy key structure */
	element_tmp =  hieps_mem_convert2tee(src_tee->pe);
	libc_ret = memcpy_s(dst->pe, dst->elen, element_tmp, src_tee->elen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->pn);
	libc_ret = memcpy_s(dst->pn, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->pd);
	libc_ret = memcpy_s(dst->pd, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	return BSP_RET_OK;
}

/*
 * @brief      : rsa_get_crtkey_struct, copy keypair struct from shared(tee and hieps) memory to tee memory
 * @param[in]  : src is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *               and all of the element pointer in dst must be in hieps side
 * @param[out] : dst is a point to tee memory addr
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_get_crtkey_struct(hal_rsa_crtkey_s *src, hal_rsa_crtkey_s *dst)
{
	hal_rsa_crtkey_s *src_tee = hieps_mem_convert2tee(src);
	u32 klen = BIT2BYTE(src_tee->width);
	u8 *element_tmp =  NULL;
	errno_t libc_ret = EINVAL;

	/* copy key structure */
	element_tmp =  hieps_mem_convert2tee(src_tee->pe);
	libc_ret = memcpy_s(dst->pe, dst->elen, element_tmp, src_tee->elen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->pn);
	libc_ret = memcpy_s(dst->pn, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	klen = CRT_PRIVKEY_LEN(src_tee->width);
	element_tmp =  hieps_mem_convert2tee(src_tee->pp);
	libc_ret = memcpy_s(dst->pp, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->pq);
	libc_ret = memcpy_s(dst->pq, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->pdp);
	libc_ret = memcpy_s(dst->pdp, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->pdq);
	libc_ret = memcpy_s(dst->pdq, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	element_tmp =  hieps_mem_convert2tee(src_tee->pqinv);
	libc_ret = memcpy_s(dst->pqinv, klen, element_tmp, klen);
	PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));

	return BSP_RET_OK;
}

/*
 * @brief      : rsa_get_genkey_struct, copy keypair struct from shared(tee and hieps) memory to tee memory
 * @param[in]  : src is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @param[out] : dst is a point to tee memory addr
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_get_genkey_struct(api_param_s *src, api_param_s *dst)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_param_s *src_tee = hieps_mem_convert2tee(src);

	/* set stdkey or crtkey structure to object */
	switch (src_tee->sub_mode) {
	case ALG_RSA_STD_KEY:
		ret = rsa_get_stdkey_struct((hal_rsa_key_s *)(src_tee->object), (hal_rsa_key_s *)(dst->object));
		PAL_ERR_RETURN(ret);
		break;
	case ALG_RSA_CRT_KEY:
		ret = rsa_get_crtkey_struct((hal_rsa_crtkey_s *)(src_tee->object), (hal_rsa_crtkey_s *)(dst->object));
		PAL_ERR_RETURN(ret);
		break;
	default:
		ret = ERR_API(ERRCODE_PARAMS);
		break;
	}

	return ret;
}

/*
 * @brief      : rsa_clear_stdkey_struct, clear keypair in shared memory
 * @param[in]  : key_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static void rsa_clear_stdkey_struct(hal_rsa_key_s *pkey_s)
{
	hal_rsa_key_s *pkey_tee = hieps_mem_convert2tee(pkey_s);
	u32 klen = BIT2BYTE(pkey_tee->width);
	u8 *element_tmp =  NULL;

	/* clear key structure */
	element_tmp =  hieps_mem_convert2tee(pkey_tee->pe);
	(void)memset_s(element_tmp, pkey_tee->elen, 0, pkey_tee->elen);

	element_tmp =  hieps_mem_convert2tee(pkey_tee->pn);
	(void)memset_s(element_tmp, klen, 0, klen);

	element_tmp =  hieps_mem_convert2tee(pkey_tee->pd);
	(void)memset_s(element_tmp, klen, 0, klen);
}

/*
 * @brief      : rsa_clear_crtkey_struct, clear keypair in shared memory
 * @param[in]  : pkey_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static void rsa_clear_crtkey_struct(hal_rsa_crtkey_s *pkey_s)
{
	hal_rsa_crtkey_s *src_tee = hieps_mem_convert2tee(pkey_s);
	u32 klen = BIT2BYTE(src_tee->width);
	u8 *element_tmp =  NULL;

	/* clear key structure */
	element_tmp =  hieps_mem_convert2tee(src_tee->pe);
	(void)memset_s(element_tmp, src_tee->elen, 0, src_tee->elen);

	element_tmp =  hieps_mem_convert2tee(src_tee->pn);
	(void)memset_s(element_tmp, klen, 0, klen);

	klen = CRT_PRIVKEY_LEN(src_tee->width);
	element_tmp =  hieps_mem_convert2tee(src_tee->pp);
	(void)memset_s(element_tmp, klen, 0, klen);

	element_tmp =  hieps_mem_convert2tee(src_tee->pq);
	(void)memset_s(element_tmp, klen, 0, klen);

	element_tmp =  hieps_mem_convert2tee(src_tee->pdp);
	(void)memset_s(element_tmp, klen, 0, klen);

	element_tmp =  hieps_mem_convert2tee(src_tee->pdq);
	(void)memset_s(element_tmp, klen, 0, klen);

	element_tmp =  hieps_mem_convert2tee(src_tee->pqinv);
	(void)memset_s(element_tmp, klen, 0, klen);
}

/*
 * @brief      : rsa_clear_apikey_struct, clear keypair in shared memory
 * @param[in]  : pkey_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static void rsa_clear_apikey_struct(api_rsa_key_s *pkey_s)
{
	api_rsa_key_s *src_tee = hieps_mem_convert2tee(pkey_s);

	/* clear stdkey or crtkey structure */
	switch (src_tee->key_type) {
	case ALG_RSA_STD_KEY:
		rsa_clear_stdkey_struct((hal_rsa_key_s *)(src_tee->key_info));
		break;
	case ALG_RSA_CRT_KEY:
		rsa_clear_crtkey_struct((hal_rsa_crtkey_s *)(src_tee->key_info));
		break;
	default:
		break;
	}
}

/*
 * @brief      : rsa_clear_genkey_struct, clear keypair in shared memory
 * @param[in]  : pkey_s is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static void rsa_clear_genkey_struct(api_param_s *pkey_s)
{
	api_param_s *src_tee = hieps_mem_convert2tee(pkey_s);

	/* clear stdkey or crtkey structure */
	switch (src_tee->sub_mode) {
	case ALG_RSA_STD_KEY:
		rsa_clear_stdkey_struct((hal_rsa_key_s *)(src_tee->object));
		break;
	case ALG_RSA_CRT_KEY:
		rsa_clear_crtkey_struct((hal_rsa_crtkey_s *)(src_tee->object));
		break;
	default:
		break;
	}
}

/*
 * @brief      : rsa_get_keylen, get key length from pkey_s
 * @param[in]  : pkey_s point to the struct api_rsa_key_s, include rsa keypair
 * @param[out] : key length in byte
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_get_keylen(api_rsa_key_s *pkey_s, u32 *pkey_len)
{
	if (pkey_s->key_type == ALG_RSA_STD_KEY)
		*pkey_len = BIT2BYTE(((hal_rsa_key_s *)(pkey_s->key_info))->width);
	else
		*pkey_len = BIT2BYTE(((hal_rsa_crtkey_s *)(pkey_s->key_info))->width);

	return BSP_RET_OK;
}

/*
 * @brief      : rsa_set_sign_v15_struct, copy sign struct from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out] : dst is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_sign_v15_struct(api_rsa_pkcs_v1_5_sign_s *src, api_rsa_pkcs_v1_5_sign_s **dst)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_rsa_pkcs_v1_5_sign_s *dst_tee = NULL;
	api_rsa_key_s *pkey_src =  src->pkey_s;
	api_rsa_key_s *pkey_dst =  NULL;
	u32 klen;

	PAL_CHECK_RETURN(!src->pkey_s, ERR_API(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!src->pdin, ERR_API(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!src->psign, ERR_API(ERRCODE_PARAMS));

	dst_tee = hieps_mem_new(NULL, sizeof(api_rsa_pkcs_v1_5_sign_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);

	/* set apikey structure */
	ret = rsa_set_apikey_struct(pkey_src, &pkey_dst);
	PAL_ERR_RETURN(ret);
	dst_tee->pkey_s = pkey_dst;

	dst_tee->hashmode = src->hashmode;
	dst_tee->inlen = src->inlen;

	dst_tee->pdin = hieps_mem_new(src->pdin, dst_tee->inlen);
	PAL_CHECK_RETURN(!dst_tee->pdin, ERR_API(ERRCODE_MEMORY));
	dst_tee->pdin  = hieps_mem_convert2hieps(dst_tee->pdin);

	ret = rsa_get_keylen(pkey_src, &klen);
	PAL_ERR_RETURN(ret);
	dst_tee->psign = hieps_mem_new(src->psign, klen);
	PAL_CHECK_RETURN(!dst_tee->psign, ERR_API(ERRCODE_MEMORY));
	dst_tee->psign = hieps_mem_convert2hieps(dst_tee->psign);

	return ret;
}

/*
 * @brief      : rsa_set_sign_pss_struct, copy sign struct from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out] : dst is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_sign_pss_struct(api_rsa_pss_sign_s *src, api_rsa_pss_sign_s **dst)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_rsa_pss_sign_s *dst_tee = NULL;
	api_rsa_key_s *pkey_src =  src->pkey_s;
	api_rsa_key_s *pkey_dst =  NULL;
	u32 klen;

	PAL_CHECK_RETURN(!src->pkey_s, ERR_API(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!src->pdin, ERR_API(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!src->psign, ERR_API(ERRCODE_PARAMS));

	dst_tee = hieps_mem_new(NULL, sizeof(api_rsa_pss_sign_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);

	/* set apikey structure */
	ret = rsa_set_apikey_struct(pkey_src, &pkey_dst);
	PAL_ERR_RETURN(ret);
	dst_tee->pkey_s = pkey_dst;

	dst_tee->hashmode = src->hashmode;
	dst_tee->inlen = src->inlen;
	dst_tee->MGFmode = src->MGFmode;
	dst_tee->saltlen = src->saltlen;

	dst_tee->pdin = hieps_mem_new(src->pdin, dst_tee->inlen);
	PAL_CHECK_RETURN(!dst_tee->pdin, ERR_API(ERRCODE_NULL));
	dst_tee->pdin = hieps_mem_convert2hieps(dst_tee->pdin);

	ret = rsa_get_keylen(pkey_src, &klen);
	PAL_ERR_RETURN(ret);
	dst_tee->psign = hieps_mem_new(src->psign, klen);
	PAL_CHECK_RETURN(!dst_tee->psign, ERR_API(ERRCODE_NULL));
	dst_tee->psign = hieps_mem_convert2hieps(dst_tee->psign);

	return BSP_RET_OK;
}

/*
 * @brief      : rsa_set_sign_struct, copy sign struct from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out] : dst is a point to the shared(tee and hieps) memory addr, and the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_sign_struct(api_param_s *src, api_param_s **dst)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_param_s *dst_tee = NULL;
	api_rsa_pkcs_v1_5_sign_s *psign_v15_tee = NULL;
	api_rsa_pss_sign_s *psign_pss_tee = NULL;

	dst_tee = hieps_mem_new(NULL, sizeof(api_param_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);
	dst_tee->operation_mode = src->operation_mode;
	dst_tee->sub_mode = src->sub_mode;

	/* set v1.5 or pss structure to object */
	switch (dst_tee->sub_mode) {
	case ALG_RSASSA_PKCS1_V15_CLIENTSK:
	case ALG_RSASSA_PKCS1_V15:
		ret = rsa_set_sign_v15_struct((api_rsa_pkcs_v1_5_sign_s *)(src->object), &psign_v15_tee);
		dst_tee->object = psign_v15_tee;
		PAL_ERR_GOTO(ret, return_tag);
		dst_tee->object = psign_v15_tee;
		break;
	case ALG_RSASSA_PKCS1_PSS_CLIENTSK:
	case ALG_RSASSA_PKCS1_PSS:
		ret = rsa_set_sign_pss_struct((api_rsa_pss_sign_s *)(src->object), &psign_pss_tee);
		dst_tee->object = psign_pss_tee;
		PAL_ERR_GOTO(ret, return_tag);
		break;
	default:
		ret = ERR_API(ERRCODE_PARAMS);
		break;
	}

return_tag:
	return ret;
}

/*
 * @brief      : rsa_get_sign_struct, copy sign data from shared(tee and hieps) memory to tee memory
 * @param[in]  : src is a point to the shared(tee and hieps) memory addr, and the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @param[out] : dst is a point to tee memory addr
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_get_sign_struct(api_param_s *src, api_param_s *dst)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	api_param_s *src_tee = hieps_mem_convert2tee(src);
	api_rsa_pkcs_v1_5_sign_s *psign_v15_src = NULL;
	api_rsa_pss_sign_s *psign_pss_src = NULL;
	api_rsa_pkcs_v1_5_sign_s *psign_v15_dst = NULL;
	api_rsa_pss_sign_s *psign_pss_dst = NULL;
	u32 klen;

	/* set v1.5 or pss structure to object */
	switch (src_tee->sub_mode) {
	case ALG_RSASSA_PKCS1_V15_CLIENTSK:
	case ALG_RSASSA_PKCS1_V15:
		/* copy v1.5 structure */
		psign_v15_src = hieps_mem_convert2tee((api_rsa_pkcs_v1_5_sign_s *)(src_tee->object));
		psign_v15_dst = (api_rsa_pkcs_v1_5_sign_s *)(dst->object);
		ret = rsa_get_keylen(psign_v15_dst->pkey_s, &klen);
		PAL_ERR_RETURN(ret);
		libc_ret = memcpy_s(psign_v15_dst->psign, klen, hieps_mem_convert2tee(psign_v15_src->psign), klen);
		PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));
		break;
	case ALG_RSASSA_PKCS1_PSS_CLIENTSK:
	case ALG_RSASSA_PKCS1_PSS:
		/* copy pss structure */
		psign_pss_src = hieps_mem_convert2tee((api_rsa_pss_sign_s *)(src_tee->object));
		psign_pss_dst = (api_rsa_pss_sign_s *)(dst->object);
		ret = rsa_get_keylen(psign_pss_dst->pkey_s, &klen);
		PAL_ERR_RETURN(ret);
		libc_ret = memcpy_s(psign_pss_dst->psign, klen, hieps_mem_convert2tee(psign_pss_src->psign), klen);
		PAL_CHECK_RETURN((libc_ret != EOK), ERR_API(ERRCODE_MEMORY));
		break;
	default:
		ret = ERR_API(ERRCODE_PARAMS);
		break;
	}

	return ret;
}

/*
 * @brief      : rsa_clear_sign_struct, clear keypair in shared memory
 * @param[in]  : psign_s is a point to the shared(tee and hieps) memory addr, and the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : void
 */
static void rsa_clear_sign_struct(api_param_s *psign_s)
{
	api_param_s *psign_tee = hieps_mem_convert2tee(psign_s);
	api_rsa_pkcs_v1_5_sign_s *psign_v15_src = NULL;
	api_rsa_pss_sign_s *psign_pss_src = NULL;

	/* set v1.5 or pss structure to object */
	switch (psign_tee->sub_mode) {
	case ALG_RSASSA_PKCS1_V15_CLIENTSK:
	case ALG_RSASSA_PKCS1_V15:
		/* copy v1.5 structure */
		psign_v15_src = hieps_mem_convert2tee((api_rsa_pkcs_v1_5_sign_s *)(psign_tee->object));
		rsa_clear_apikey_struct(psign_v15_src->pkey_s);
		break;
	case ALG_RSASSA_PKCS1_PSS_CLIENTSK:
	case ALG_RSASSA_PKCS1_PSS:
		/* copy pss structure */
		psign_pss_src = hieps_mem_convert2tee((api_rsa_pss_sign_s *)(psign_tee->object));
		rsa_clear_apikey_struct(psign_pss_src->pkey_s);
		break;
	default:
		break;
	}
}

/*
 * @brief      : api_rsa_gen_keypair, generate rsa keypair
 * @param[in]  : pkey_s point to the struct api_param_s
 * @return     : ::err_bsp_t error code
 */
err_bsp_t api_rsa_gen_keypair(api_param_s *pkey_s)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_param_s *pkey_dst =  NULL;

	/* check param */
	PAL_CHECK_RETURN(!pkey_s || !pkey_s->object, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(pkey_s->operation_mode != OPERATION_RSA_GEN_KEY, ERR_HAL(ERRCODE_PARAMS));
	ret = rsa_genkey_check_param(pkey_s);
	PAL_ERR_RETURN(ret);

	/* copy apikey structure from tee memory to shared memory */
	ret = rsa_set_genkey_struct(pkey_s, &pkey_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* ipc send */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_RSA_GENKEY, FUNC_API_PKE_GENKEY, FUNC_PARAMS_1, pkey_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* copy apikey structure from shared memory to tee memory */
	ret = rsa_get_genkey_struct(pkey_dst, pkey_s);
	PAL_ERR_GOTO(ret, return_tag);

	/* clear keypair in shared memory */
	rsa_clear_genkey_struct(pkey_dst);

return_tag:
	/* free shared memory */
	rsa_free_genkey_struct(pkey_dst);
	return ret;
}

/*
 * @brief      : api_rsa_sign, rsa signature process
 * @param[in]  : psign_s point to the struct api_param_s
 * @return     : ::err_bsp_t error code
 */
err_bsp_t api_rsa_sign(api_param_s *psign_s)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_param_s *psign_dst =  NULL;

	/* check param */
	PAL_CHECK_RETURN(!psign_s || !psign_s->object, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(psign_s->operation_mode != OPERATION_RSA_SIGN, ERR_HAL(ERRCODE_PARAMS));

	/* copy sign structure from tee memory to shared memory */
	ret = rsa_set_sign_struct(psign_s, &psign_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* ipc send */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_PKE_SIGN, FUNC_PARAMS_1, psign_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* copy sign structure from shared memory to tee memory */
	ret = rsa_get_sign_struct(psign_dst, psign_s);
	PAL_ERR_GOTO(ret, return_tag);

	/* clear keypair in shared memory */
	rsa_clear_sign_struct(psign_dst);

return_tag:
	/* free shared memory */
	rsa_free_sign_struct(psign_dst);
	return ret;
}

/*
 * @brief      : api_rsa_verify, rsa signature verify process
 * @param[in]  : pverify_s point to the struct api_param_s
 * @return     : ::err_bsp_t error code
 */
err_bsp_t api_rsa_verify(api_param_s *pverify_s)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	api_param_s *pverify_dst =  NULL;

	/* check param */
	PAL_CHECK_RETURN(!pverify_s || !pverify_s->object, ERR_HAL(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(pverify_s->operation_mode != OPERATION_RSA_VERIFY, ERR_HAL(ERRCODE_PARAMS));

	/* set sign structure */
	ret = rsa_set_sign_struct(pverify_s, &pverify_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* ipc send */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_PKE_VERIFY, FUNC_PARAMS_1, pverify_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* clear keypair in shared memory */
	rsa_clear_sign_struct(pverify_dst);

return_tag:
	/* free shared memory */
	rsa_free_sign_struct(pverify_dst);
	return ret;
}

/*
 * @brief      : rsa_set_data_struct, copy data from tee memory to shared(tee and hieps) memory
 * @param[in]  : src is a point to tee memory addr
 * @param[out]  : dst is a point to the shared(tee and hieps) memory addr, the pointer value is in hieps side
 *				and all of the element pointer in dst must be in hieps side
 * @return     : ::err_bsp_t error code
 */
static err_bsp_t rsa_set_data_struct(api_rsa_data_s *src, api_rsa_data_s **dst)
{
	api_rsa_data_s *dst_tee = NULL;

	dst_tee = hieps_mem_new(NULL, sizeof(api_rsa_data_s));
	PAL_CHECK_RETURN(!dst_tee, ERR_API(ERRCODE_MEMORY));
	*dst = hieps_mem_convert2hieps(dst_tee);
	dst_tee->size = src->size;

	dst_tee->pdata = hieps_mem_new(src->pdata, dst_tee->size);
	PAL_CHECK_RETURN(!dst_tee->pdata, ERR_API(ERRCODE_MEMORY));
	dst_tee->pdata = hieps_mem_convert2hieps(dst_tee->pdata);

	return BSP_RET_OK;
}

/*
 * @brief      : rsa_free_data_struct, free the shared(tee and hieps) memory
 * @param[in]  : data point to the struct hal_rsa_key_s, include rsa keypair
 * @return     : ::err_bsp_t error code
 */
static inline void rsa_free_data_struct(api_rsa_data_s *data)
{
	if (!data)
		return;

	data = hieps_mem_convert2tee(data);
	rsa_free_hieps_mem(data->pdata);
	rsa_free_tee_mem(data);
}

/*
 * @brief      : api_rsa_bnmul, c = a * b
 * @param[in]  : pmul_a  multiply data a
 * @param[in]  : pmul_b multiply data b
 * @param[out] : pout_c , the out data
 * @return     : ::err_bsp_t, error code
 */
err_bsp_t api_rsa_bnmul(api_rsa_data_s *pmul_a, api_rsa_data_s *pmul_b, api_rsa_data_s *pout_c)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	errno_t libc_ret = EINVAL;
	api_rsa_data_s *a_dst =  NULL;
	api_rsa_data_s *b_dst =  NULL;
	api_rsa_data_s *c_dst =  NULL;
	api_rsa_data_s *c_tee =  NULL;

	PAL_CHECK_RETURN(!pmul_a || !pmul_a->pdata || (pmul_a->size == 0), ERR_DRV(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pmul_b || !pmul_b->pdata || (pmul_b->size == 0), ERR_DRV(ERRCODE_PARAMS));
	PAL_CHECK_RETURN(!pout_c || !pout_c->pdata || (pout_c->size == 0), ERR_DRV(ERRCODE_PARAMS));

	/* set input structure */
	ret = rsa_set_data_struct(pmul_a, &a_dst);
	PAL_ERR_GOTO(ret, return_tag);
	ret = rsa_set_data_struct(pmul_b, &b_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* set output structure */
	ret = rsa_set_data_struct(pout_c, &c_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* ipc send */
	ret = hieps_run_func(HIEPS_AGENT_TIMEOUT_DEFAULT, FUNC_API_RSA_BMMUL, FUNC_PARAMS_3, a_dst, b_dst, c_dst);
	PAL_ERR_GOTO(ret, return_tag);

	/* copy key structure */
	c_tee =  hieps_mem_convert2tee(c_dst);
	libc_ret = memcpy_s(pout_c->pdata, pout_c->size, hieps_mem_convert2tee(c_tee->pdata), c_tee->size);
	PAL_CHECK_GOTO((libc_ret != EOK), ERR_API(ERRCODE_MEMORY), return_tag);

return_tag:
	/* free malloc */
	rsa_free_data_struct(a_dst);
	rsa_free_data_struct(b_dst);
	rsa_free_data_struct(c_dst);

	return ret;
}

