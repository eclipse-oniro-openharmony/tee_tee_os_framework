/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: imp android factory test
 * Author: Security Engine
 * Create: 2020/10/27
 */
#include <mspe_crypto_init.h>
#include <mspe_crypto_selftest.h>
#include <pal_errno.h>
#include <pal_log.h>

#define BSP_THIS_MODULE BSP_MODULE_SEC

/*
 * factory test for AT CMD. just do crypto init and selftest.
 * note: when hardware firstly become power on,
 * it will do cyrpto init and crypto selftest automatically.
 */
err_bsp_t mspe_factory_test(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	ret = mspe_crypto_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = mspe_crypto_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

