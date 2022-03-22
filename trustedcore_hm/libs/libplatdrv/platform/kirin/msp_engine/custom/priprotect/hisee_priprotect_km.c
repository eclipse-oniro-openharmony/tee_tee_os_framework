/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: custom protect km func
 * Author     : h00401342
 * Create     : 2020/02/06
 */
#include <hisee_priprotect.h>
#include <pal_log.h>
#include <pal_libc.h>
#include <hisee_seceng.h>

#define BSP_THIS_MODULE BSP_MODULE_SCE

/**
 * @brief      : private protect key derive base kdr
 * @param[in]  : pdin derive weight
 * @param[in]  : dinlen derive weight length
 * @param[in]  : pdout derive key
 * @param[in/out]  : pdoutlen derive key length
 * @note       :
 */
err_bsp_t hisee_pri_protect_derive_kdr(const u8 *pdin, u32 dinlen,
				       u8 *pdout, u32 *pdoutlen)
{
	err_bsp_t ret = ERR_API(ERRCODE_UNKNOWN);
	u8 buf_km_derive[SYMM_KEYLEN_16]  = {0};
	u32 km_out_len = SYMM_KEYLEN_16;

	if (PAL_CHECK(!pdin || dinlen == 0))
		return ERR_API(ERRCODE_PARAMS);

	if (PAL_CHECK(!pdout || !pdoutlen || *pdoutlen == 0))
		return ERR_API(ERRCODE_PARAMS);

	ret = hisee_derive_readable_key(SYMM_KEYTYPE_KDR, pdin, dinlen, buf_km_derive, &km_out_len);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hisee_hkdf_derive(SYMM_ALGORITHM_SHA256, NULL, 0, buf_km_derive, SYMM_KEYLEN_16, NULL, 0,
				pdout, *pdoutlen);

	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return BSP_RET_OK;
}
