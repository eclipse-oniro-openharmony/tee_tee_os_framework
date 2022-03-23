/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * Description: mspe crypto init
 * Author: Security Engine
 * Create: 2020/10/26
 */
#include <mspe_crypto_init.h>
#include <pal_types.h>
#include <pal_errno.h>
#include <pal_log.h>
#include <pal_memory.h>
#include <seceng_plat.h>
#include <rng.h>
#include <hal_engctrl.h>
#include <hal_trng.h>
#include <hal_km.h>
#include <hal_symm_init.h>
#include <hal_pke_init.h>
#include <mspe_smmu.h>
#include <soc_config_interface.h>

#define BSP_THIS_MODULE       BSP_MODULE_SEC
#define CONFIG_INTR_MASK_MASK 0x1FFFF

static void mspe_intr_unmask(void)
{
	u32 val;
	u32 addr = SOC_CONFIG_HIEPS_INTR_MASK_ADDR(SOC_CONFIG_BASE_ADDR);

	/* irq unmask */
	val = pal_read_u32(addr);
	val &= ~CONFIG_INTR_MASK_MASK;
	pal_write_u32(val, addr);
}

err_bsp_t mspe_crypto_base_init(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	ret = osl_os_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	mspe_smmu_bypass();
	mspe_intr_unmask();

	/* gate clk */
	ret = hal_engctrl_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_trng_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = rng_initialize();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_km_rtl_decrypt_function();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_symm_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_rsa_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_ecc_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

err_bsp_t mspe_crypto_sm9_init(void)
{
#ifdef FEATURE_SM9_ENABLE
	return hal_sm9_init();
#else
	return BSP_RET_OK;
#endif
}

err_bsp_t mspe_crypto_init(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	PAL_INFO("mspe crypto init begin\n");

	ret = mspe_crypto_base_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
	ret = mspe_crypto_sm9_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	PAL_INFO("mspe crypto init ok\n");

	return ret;
}

