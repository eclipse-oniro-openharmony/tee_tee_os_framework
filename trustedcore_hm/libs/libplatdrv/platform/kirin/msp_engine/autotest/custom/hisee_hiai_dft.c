/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: custom hiai dft func
 * Author     : security-engine
 * Create     : 2020/04/20
 */
#include <hisee_hiai_inner.h>
#include <seceng_plat.h>

/* set the module to which the file belongs
 *  each .C file needs to be configured
 */
#define BSP_THIS_MODULE BSP_MODULE_KM

err_bsp_t hat_hisee_hiai_do_none(void)
{
	return BSP_RET_OK;
}

err_bsp_t hat_hisee_hiai_power_test(void)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	SECENG_HIAI_RUN(&ret,
			hat_hisee_hiai_do_none()
			);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}

err_bsp_t hat_hisee_hiai_key_derive(struct hisee_hiai_data *pdata,
				    u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	SECENG_HIAI_RUN(&ret,
			hisee_hiai_key_derive(pdata, pdout, pdoutlen)
			);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}

err_bsp_t hat_hisee_hiai_key_decrypt(struct hisee_hiai_data *pdata,
				     const u8 *pkey, u32 keylen,
				     const u8 *pdin, u32 dinlen,
				     u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	SECENG_HIAI_RUN(&ret,
			hisee_hiai_key_decrypt(pdata, pkey, keylen,
					       pdin, dinlen, pdout, pdoutlen)
			);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}

err_bsp_t hat_hisee_hiai_key_verify(struct hisee_hiai_data *pdata,
					    const u8 *pkey, u32 keylen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	SECENG_HIAI_RUN(&ret,
			hisee_hiai_key_verify(pdata, pkey, keylen)
			);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}

err_bsp_t hat_hisee_hiai_ecdh_compute(struct hisee_ecc_pubkey *ppubkey,
				      u8 *privkey, u32 keylen,
				      u8 *pdout, u32 doutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);

	SECENG_HIAI_RUN(&ret,
			hisee_hiai_ecdh_compute(ppubkey, privkey, keylen, pdout, doutlen)
			);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	return ret;
}

