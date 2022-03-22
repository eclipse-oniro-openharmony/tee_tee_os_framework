/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mspe crypto selftest
 * Author: Security Engine
 * Create: 2020/10/26
 */
#include <mspe_crypto_selftest.h>
#include <pal_types.h>
#include <pal_errno.h>
#include <pal_log.h>
#include <stdbool.h>
#include <rng.h>
#include <hal_trng.h>
#include <hal_sce_selftest.h>
#include <hal_pke_selftest.h>

#define BSP_THIS_MODULE BSP_MODULE_SEC

err_bsp_t mspe_crypto_base_selftest(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	ret = hal_trng_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_symm_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_rsa_me512_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_ecc_pmulselftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

err_bsp_t mspe_crypto_sm9_selftest(void)
{
#ifdef FEATURE_SM9_ENABLE
	return hal_sm9_selftest();
#else
	return BSP_RET_OK;
#endif
}

err_bsp_t mspe_crypto_selftest(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	PAL_INFO("mspe crypto selftest begin\n");

	ret = mspe_crypto_base_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	ret = mspe_crypto_sm9_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	PAL_INFO("mspe crypto selftest ok\n");

	return ret;
}

