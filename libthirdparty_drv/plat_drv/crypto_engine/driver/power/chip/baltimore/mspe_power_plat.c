 /*
  * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
  * Description: msp engine power manager
  * Author     : security-engine
  * Create     : 2020/04/20
  */
#include "mspe_power.h"
#include <sre_typedef.h>
#include <pthread.h>
#include <hieps_common.h>
#include <seceng_plat.h>
#include <soc_smmuv3_tcu_interface.h>
#include <soc_smmuv3_tbu_interface.h>
#include <soc_actrl_interface.h>
#include <soc_config_interface.h>
#include <rng.h>
#include <hal_engctrl.h>
#include <hal_trng.h>
#include <hal_km.h>
#include <hal_symm_init.h>
#include <hal_sce_selftest.h>
#include <hal_pke_init.h>
#include <hal_pke_scramb.h>
#include <hal_pke_selftest.h>

/* set the module to which the file belongs
 *  each .C file needs to be configured
 */
#define BSP_THIS_MODULE BSP_MODULE_SYS

#define CONFIG_INTR_MASK_MASK   0x1FFFF

struct seceng_data {
	enum sec_bool_e osl_inited;
	enum sec_bool_e rng_inited;
	enum sec_bool_e base_selftest;
#ifdef FEATURE_SM9_ENABLE
	enum sec_bool_e sm9_inited;
	enum sec_bool_e sm9_selftest;
#endif /* FEATURE_SM9_ENABLE */
};

struct seceng_data g_seceng_data = {
	.osl_inited    = SEC_FALSE,
	.rng_inited    = SEC_FALSE,
	.base_selftest = SEC_FALSE,
#ifdef FEATURE_SM9_ENABLE
	.sm9_inited    = SEC_FALSE,
	.sm9_selftest  = SEC_FALSE,
#endif /* FEATURE_SM9_ENABLE */
};

enum sec_bool_e mspe_sm9_is_inited(void)
{
#ifdef FEATURE_SM9_ENABLE
	return g_seceng_data.sm9_inited;
#else
	return SEC_FALSE;
#endif /* FEATURE_SM9_ENABLE */
}

PRIVATE err_bsp_t mspe_engctrl_init(void)
{
	u32 val;

	SOC_SMMUv3_TBU_SMMU_TBU_SCR_UNION scr_config;

	SOC_ACTRL_HIEPS_CTRL_SEC_UNION hieps_ctrl_sec;

	/* key decompression */
	hieps_ctrl_sec.value = pal_read_u32(SOC_ACTRL_HIEPS_CTRL_SEC_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));
	hieps_ctrl_sec.reg.hieps_resume = 1;
	pal_write_u32(hieps_ctrl_sec.value, SOC_ACTRL_HIEPS_CTRL_SEC_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));
	pal_udelay(50); /* chip request delay 40us + reserve10us = 50us */
	hieps_ctrl_sec.reg.hieps_resume = 0;
	pal_write_u32(hieps_ctrl_sec.value, SOC_ACTRL_HIEPS_CTRL_SEC_ADDR(SOC_ACPU_ACTRL_BASE_ADDR));

	/* SMMU bypass */
	scr_config.value = pal_read_u32(SOC_SMMUv3_TBU_SMMU_TBU_SCR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));
	scr_config.reg.tbu_bypass = 1;
	pal_write_u32(scr_config.value, SOC_SMMUv3_TBU_SMMU_TBU_SCR_ADDR(SOC_ACPU_EPS_MMU_BASE_ADDR));

	/* irq unmask */
	val = pal_read_u32(SOC_CONFIG_HIEPS_INTR_MASK_ADDR(SOC_CONFIG_BASE_ADDR));
	val &= ~CONFIG_INTR_MASK_MASK;
	pal_write_u32(val, SOC_CONFIG_HIEPS_INTR_MASK_ADDR(SOC_CONFIG_BASE_ADDR));

	return BSP_RET_OK;
}

PRIVATE err_bsp_t seceng_base_init(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	UNUSED(ret);
	ret = hal_engctrl_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_trng_init();
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

	ret = hal_scramb_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

PRIVATE err_bsp_t seceng_base_selftest(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	UNUSED(ret);
	ret = hal_trng_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_symm_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_rsa_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_ecc_pmulselftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}

#ifdef FEATURE_SM9_ENABLE
PRIVATE err_bsp_t seceng_sm9_initialize(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	if (g_seceng_data.sm9_inited != SEC_TRUE) {
		/*
		 *  g_seceng_data.sm9_inited must be set SEC_TRUE first
		 *  since it's used by IP power on detection during hal_sm9_init
		 */
		g_seceng_data.sm9_inited = SEC_TRUE;
		ret = hal_sm9_init();
		if (PAL_CHECK(ret != BSP_RET_OK)) {
			g_seceng_data.sm9_inited = SEC_FALSE;
			return ret;
		}
	}

	if (g_seceng_data.sm9_selftest != SEC_TRUE) {
		ret = hal_sm9_selftest();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		g_seceng_data.sm9_selftest = SEC_TRUE;
	}

	return BSP_RET_OK;
}
#endif /* FEATURE_SM9_ENABLE */

PRIVATE err_bsp_t seceng_base_initialize(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	UNUSED(ret);
	PAL_INFO("init begin\n");

	if (g_seceng_data.osl_inited != SEC_TRUE) {
		ret = osl_os_init();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		g_seceng_data.osl_inited = SEC_TRUE;
	}

	ret = mspe_engctrl_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = seceng_base_init();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	ret = hal_km_rtl_decrypt_function();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	PAL_INFO("init ok\n");

	if (g_seceng_data.base_selftest != SEC_TRUE) {
		ret = seceng_base_selftest();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		g_seceng_data.base_selftest = SEC_TRUE;
	}

	if (g_seceng_data.rng_inited != SEC_TRUE) {
		ret = rng_initialize();
		if (PAL_CHECK(ret != BSP_RET_OK))
			return ret;
		g_seceng_data.rng_inited = SEC_TRUE;
	}
	return ret;
}

uint32_t hieps_power_on(uint32_t id, uint32_t profile_id)
{
	uint32_t ret = HIEPS_ERROR;
	int32_t tmp_ret;
	uint32_t old_voted = 0;
	uint32_t cur_voted = 0;

	/* Wait for mutex lock. */
	tmp_ret = pthread_mutex_lock(&g_hieps_data.seceng_lock);
	if (PAL_CHECK(tmp_ret != SRE_OK)) {
		PAL_PRINTF("mspe:wait seceng_lock failed: 0x%x!\n", tmp_ret);
		return (uint32_t)HIEPS_MUTEX_ERR; /*lint !e454 for lock failed */
	}

	old_voted = hieps_get_voted_nums();
	/* keep profile no change when power on */
	if (profile_id == PROFILE_KEEP) {
		profile_id = hieps_get_cur_profile();
		/* set to default when current power on profile is invalid */
		if (profile_id >= MAX_PROFILE)
			profile_id = PROFILE_080V;
	}
	ret = hieps_do_power_on(id, profile_id);
	if (PAL_CHECK(ret != HIEPS_OK)) {
		PAL_PRINTF("mspe:power_on failed: 0x%x!\n", ret);
		goto end_handler;
	}
	cur_voted = hieps_get_voted_nums();

	/* seceng data init and base ip init & selft */
	if (old_voted == 0) {
		tmp_ret = (int32_t)seceng_base_initialize();
		if (PAL_CHECK(tmp_ret != BSP_RET_OK)) {
			ret = (uint32_t)tmp_ret;
			goto end_handler;
		}
		g_seceng_data.sm9_inited = SEC_FALSE; /* sm9 status is uninit */
	}

	/* sm9 ip init & selft */
#ifdef FEATURE_SM9_ENABLE
	if (id == PRIP) {
		tmp_ret = (int32_t)seceng_sm9_initialize();
		if (PAL_CHECK(tmp_ret != BSP_RET_OK)) {
			ret = (uint32_t)tmp_ret;
			goto end_handler;
		}
	}
#endif /* FEATURE_SM9_ENABLE */

end_handler:
	/* poweron successfully when cur_voted >= old_voted + 1 */
	if (ret != HIEPS_OK && cur_voted >= old_voted + 1) {
		tmp_ret = (int32_t)hieps_do_power_off(id, profile_id);
		if (PAL_CHECK(tmp_ret != HIEPS_OK)) {
			PAL_PRINTF("mspe:poweroff failed: 0x%x!\n", tmp_ret);
		}
	}
	tmp_ret = pthread_mutex_unlock(&g_hieps_data.seceng_lock);
	if (PAL_CHECK(tmp_ret != SRE_OK))
		PAL_PRINTF("mspe:seceng_unlock failed: 0x%x!\n", tmp_ret);
	return ret;
}

uint32_t hieps_power_off(uint32_t id, uint32_t profile_id)
{
	return hieps_do_power_off(id, profile_id);
}

#ifdef FEATURE_DFT_ENABLE
err_bsp_t mspe_factory_test(void)
{
	err_bsp_t ret = ERR_HAL(ERRCODE_UNKNOWN);

	if (PAL_CHECK(hieps_get_voted_nums() < 1))
		return ERR_API(ERRCODE_SYS);

#ifdef FEATURE_SM9_ENABLE
	ret = seceng_sm9_initialize();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;
#endif /* FEATURE_SM9_ENABLE */

	ret = hal_seceng_selftest();
	if (PAL_CHECK(ret != BSP_RET_OK))
		return ret;

	return ret;
}
#endif /* FEATURE_DFT_ENABLE */

